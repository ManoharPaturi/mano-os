"""Approved immutable package forecasts. No install/apply API or automatic retry."""

import hashlib
import json
import time

from mano_protocol.actions import ActionRequest, canonical, identifier, unique_object
from mano_protocol.packages import digest, install_review, result, result_digest

from .broker import read_terminal_output


def catalog(client, *, task_id, resource_id):
    value = client(
        dict(
            schema_version="1.0",
            operation="package_catalog",
            body=dict(task_id=identifier(task_id), resource_id=identifier(resource_id)),
        )
    )
    if value.get("schema_version") != "1.0" or value.get("ok") is not True:
        raise ValueError("No current operator-refreshed package catalog")
    observed = value["catalog"]
    digest(observed["catalog_id"])
    digest(observed["status_sha256"])
    if (
        observed.get("signed_indexes_verified") is not True
        or observed.get("architecture") != "amd64"
    ):
        raise ValueError("Unexpected package environment")
    return observed


def proposal(*, task_id, resource_id, names, catalog_id, key, reason):
    value = dict(
        schema_version="1.0",
        task_id=task_id,
        resource_id=resource_id,
        capability="packages.plan_install",
        args=dict(names=names, catalog_id=catalog_id),
        idempotency_key=key,
        reason=reason,
    )
    ActionRequest.parse(canonical(value | dict(grant_id="0" * 32)).encode())
    return value


class PackagePlan:
    def __init__(self, client, *, proposed, action_id):
        request = ActionRequest.parse(canonical(proposed | dict(grant_id="0" * 32)).encode())
        if request.capability != "packages.plan_install":
            raise ValueError("An exact package planning proposal is required")
        self.client, self.task_id, self.expected = (
            client,
            request.task_id,
            json.loads(request.args_json),
        )
        self.action_id = identifier(action_id)
        self.proposed = proposed
        self.digest = hashlib.sha256(canonical(proposed).encode()).hexdigest()

    @staticmethod
    def request_approval(client, *, proposed):
        PackagePlan(client, proposed=proposed, action_id="0" * 32)
        reply = client(dict(schema_version="1.0", operation="request_approval", body=proposed))
        if reply.get("schema_version") != "1.0" or reply.get("ok") is not True:
            raise ValueError("Package planning approval denied")
        return reply

    @classmethod
    def start(cls, client, *, proposed, grant_id):
        worker = cls(client, proposed=proposed, action_id="0" * 32)
        request = ActionRequest.parse(canonical(proposed | dict(grant_id=grant_id)).encode())
        response = client(dict(schema_version="1.0", operation="propose", body=request.body()))
        if response.get("schema_version") != "1.0" or response.get("ok") is not True:
            raise ValueError(
                "Package plan start denied or uncertain; do not resubmit automatically"
            )
        worker.action_id = identifier(response["action"]["id"])
        worker.bound(response["action"])
        return worker

    def bound(self, action):
        if (
            not isinstance(action, dict)
            or action.get("id") != self.action_id
            or action.get("task_id") != self.task_id
            or action.get("verified") != 0
            or action.get("proposal_digest") != self.digest
        ):
            raise ValueError("Package plan action or approved scope changed")
        return action

    def status(self):
        reply = self.client(
            dict(
                schema_version="1.0",
                operation="status",
                body=dict(task_id=self.task_id, action_id=self.action_id),
            )
        )
        if reply.get("schema_version") != "1.0" or reply.get("ok") is not True:
            raise ValueError("Package plan status unavailable; reconcile without retry")
        return self.bound(reply["action"])

    def result(self):
        action = self.status()
        if action["state"] != "done" or action["exit_code"] != 0:
            raise ValueError("No durable completed package forecast")
        observed = read_terminal_output(self.client, task_id=self.task_id, action_id=self.action_id)
        if (
            observed["metadata"]["return_code"] != 0
            or observed["metadata"]["reason"] != "completed"
            or observed["stderr"]
        ):
            raise ValueError("Package forecast differs from completed action")
        plan = result(
            json.loads(observed["stdout"], object_pairs_hook=unique_object), expected=self.expected
        )
        return dict(
            plan=plan,
            sha256=result_digest(plan, expected=self.expected),
            metadata=observed["metadata"],
            install_authorized=False,
            effect_verified=False,
            current_applicability_verified=False,
        )

    def review_install(self):
        captured = self.result()
        value = self.client(dict(schema_version='1.0', operation='package_install_review',
            body=dict(task_id=self.task_id, resource_id=self.proposed['resource_id'],
                      action_id=self.action_id, plan_sha256=captured['sha256'])))
        if value.get('schema_version') != '1.0' or value.get('ok') is not True:
            raise ValueError('Package install review unavailable; refresh inputs without applying')
        reviewed = install_review(value['review'], expected=self.expected, task_id=self.task_id,
            resource_id=self.proposed['resource_id'], action_id=self.action_id,
            plan_sha256=captured['sha256'], boot_id=captured['metadata']['boot_id'])
        if time.time() >= reviewed['expires_at']:
            raise ValueError('Package review expired; no apply authorization exists')
        return reviewed


def apply_proposal(*, task_id, resource_id, forecast_action_id, plan_sha256, key, reason):
    value = dict(schema_version='1.0', task_id=task_id, resource_id=resource_id,
        capability='packages.apply_install',
        args=dict(forecast_action_id=forecast_action_id, plan_sha256=plan_sha256),
        idempotency_key=key, reason=reason)
    ActionRequest.parse(canonical(value | dict(grant_id='0' * 32)).encode())
    return value


class PackageApply(PackagePlan):
    """One exact fresh-approved apply; no retry or promotion of unknown results."""

    def __init__(self, client, *, proposed, action_id):
        request = ActionRequest.parse(canonical(proposed | dict(grant_id='0' * 32)).encode())
        if request.capability != 'packages.apply_install':
            raise ValueError('A distinct package apply proposal is required')
        self.client, self.task_id = client, request.task_id
        self.expected = json.loads(request.args_json)
        self.action_id = identifier(action_id)
        self.proposed = proposed
        self.digest = hashlib.sha256(canonical(proposed).encode()).hexdigest()

    @staticmethod
    def request_approval(client, *, proposed):
        PackageApply(client, proposed=proposed, action_id='0' * 32)
        reply = client(dict(schema_version='1.0', operation='request_approval', body=proposed))
        if reply.get('schema_version') != '1.0' or reply.get('ok') is not True:
            raise ValueError('Fresh package apply approval unavailable')
        return reply

    def result(self):
        action = self.status()
        if action['state'] != 'done' or action['exit_code'] != 0:
            raise ValueError('Package outcome unavailable or unknown; do not automatically replay')
        value = self.client(dict(schema_version='1.0', operation='package_apply_result',
            body=dict(task_id=self.task_id, action_id=self.action_id)))
        if value.get('ok') is not True or value.get('schema_version') != '1.0':
            raise ValueError('No authenticated package result')
        receipt = value['result']['receipt']
        if (value['result']['state'] != 'done' or not isinstance(receipt, dict)
                or receipt['outcome']['state'] != 'postconditions-verified'
                or receipt['outcome']['attempt_id'] != self.action_id
                or receipt['outcome']['plan_sha256'] != self.expected['plan_sha256']
                or receipt['outcome']['automatic_replay_allowed'] is not False):
            raise ValueError('Package result scope changed')
        return receipt

    def review_install(self):
        raise ValueError('Apply uses its own fresh native approval, not a forecast review')
