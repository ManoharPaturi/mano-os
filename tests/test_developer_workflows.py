import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from mano_broker.approvals import Approvals
from mano_broker.developer import step as operator_step
from mano_broker.developer_workflows import register, status
from mano_broker.protocol import ActionRequest, canonical
from mano_broker.state import Denied, State
from mano_broker.terminal_output import persist
from mano_broker.verifier import check, declare
from mano_protocol.plans import proposal
from mano_protocol.workflows import operation_key


def sha(data):
    return hashlib.sha256(data).hexdigest()


class RecordedDeveloperTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.state = State(Path(self.temp.name).resolve() / "state")
        self.state.db.execute("INSERT INTO meta VALUES('native_generation',0)")
        self.resource = "a" * 32
        self.task = self.state.create_task(
            human_uid=1002,
            caller_uid=1004,
            mode="supervised",
            resource_id=self.resource,
            classification="internal",
            boot_id="boot",
        )
        self.resource_object = SimpleNamespace(
            task_id=self.task, boot_id="boot", caller_uid=1004, human_uid=1002
        )
        self.runtime = SimpleNamespace(
            state=self.state,
            registry=SimpleNamespace(resources={self.resource: self.resource_object}),
        )
        self.managed = dict(
            context=dict(
                task_id=self.task,
                resource_id=self.resource,
                operation_key="original",
                prompt="Build and test the project",
            ),
            workspace="/fixed",
            caller_uid=1004,
            caller_name="mano-task-fixture",
            mode="supervised",
            prompt_id="d" * 32,
        )

        def write(text):
            return dict(
                plan=dict(
                    capability="files.write",
                    args=dict(path="answer.py", text=text),
                    reason="Recorded correction",
                ),
                expect={},
            )

        def run(code, stdout, stderr):
            return dict(
                plan=dict(
                    args=dict(argv=["/usr/bin/true"], cwd=".", timeout_seconds=5),
                    reason="Recorded project test",
                ),
                expect=dict(exit_code=code, stdout_sha256=sha(stdout), stderr_sha256=sha(stderr)),
            )

        self.definition = dict(
            steps=[write("broken"), run(1, b"", b"FAIL\n"), write("fixed"), run(0, b"PASS\n", b"")],
            artifact=dict(path="answer.py", sha256=sha(b"fixed"), size=5),
        )
        self.id = register(
            self.runtime,
            managed=self.managed,
            request_key="once",
            workflow=self.definition,
            boot_id="boot",
        )

    def tearDown(self):
        self.state.close()
        self.temp.cleanup()

    def status(self, **args):
        return status(self.runtime, self.id, **(dict(boot_id="boot", now=10) | args))

    def effect(self, index, *, code=None, stdout=b"", stderr=b"", unknown=False):
        step = self.definition["steps"][index]
        context = self.managed["context"] | dict(operation_key=operation_key(self.id, index))
        original = proposal(step["plan"], context)
        pending = Approvals(self.state).request(original, caller_uid=1004, now=10, boot_id="boot")
        if index == 3:
            declare(
                self.state,
                pending["approval_id"],
                **self.definition["artifact"],
                now=10,
                boot_id="boot",
            )
        view = Approvals(self.state).view(pending["approval_id"], human_uid=1002)
        grant = Approvals(self.state).approve(
            pending["approval_id"],
            authenticated_human_uid=1002,
            nonce=view["nonce"],
            operation_digest=view["operation_digest"],
            now=10,
            boot_id="boot",
        )
        request = ActionRequest.parse(canonical(original | dict(grant_id=grant)).encode())
        row, _ = self.state.authorize(request, caller_uid=1004, now=10, boot_id="boot")
        self.state.start(row["id"], now=10, boot_id="boot")
        if unknown:
            self.state.transition(row["id"], "unknown")
        elif step["plan"].get("capability") == "files.write":
            data = step["plan"]["args"]["text"].encode()
            receipt = dict(
                task_id=self.task,
                action_id=row["id"],
                boot_id="boot",
                relative_path="answer.py",
                publication="created",
                sha256=sha(data),
                size=len(data),
                published_device=1,
                published_inode=2,
                effect_verified=False,
                current_content_verified=False,
            )
            self.state.db.execute(
                "INSERT INTO file_writes VALUES(?,?)", (row["id"], canonical(receipt))
            )
            self.state.transition(row["id"], "done", exit_code=0)
        else:
            persist(
                self.state,
                row["id"],
                dict(reason="completed", return_code=code),
                dict(stdout=stdout, stderr=stderr),
                boot_id="boot",
            )
        return row["id"]

    def test_broker_definition_is_immutable_and_replayed_without_new_authority(self):
        self.assertEqual(
            register(
                self.runtime,
                managed=self.managed,
                request_key="once",
                workflow=self.definition,
                boot_id="boot",
            ),
            self.id,
        )
        changed = json.loads(canonical(self.definition))
        changed["steps"][0]["plan"]["args"]["text"] = "different"
        with self.assertRaises(Denied):
            register(
                self.runtime,
                managed=self.managed,
                request_key="once",
                workflow=changed,
                boot_id="boot",
            )
        self.assertEqual(self.state.db.execute("SELECT count(*) FROM grants").fetchone()[0], 0)

    def test_only_real_known_failure_with_expected_output_selects_correction(self):
        self.effect(0)
        self.assertEqual(self.status()["index"], 1)
        failure = self.effect(1, code=1, stderr=b"FAIL\n")
        observed = self.status()
        self.assertEqual((observed["status"], observed["index"]), ("ready", 2))
        self.assertEqual(observed["observations"][1]["output"]["return_code"], 1)
        self.assertFalse(observed["provider_disclosure"])
        self.assertEqual(
            self.state.db.execute("SELECT verified FROM actions WHERE id=?", (failure,)).fetchone()[
                0
            ],
            0,
        )
        self.state.db.execute(
            "UPDATE terminal_outputs SET stderr=? WHERE action_id=?", (b"fake", failure)
        )
        with self.assertRaises(Denied):
            self.status()

    def test_unknown_exit_does_not_advance_or_reexecute(self):
        self.effect(0)
        self.effect(1, unknown=True)
        self.assertEqual(self.status()["status"], "unknown_effect")
        self.assertEqual(self.status()["index"], 1)
        self.assertEqual(self.state.db.execute("SELECT count(*) FROM actions").fetchone()[0], 2)

    def test_changed_output_or_unexpected_exit_halts(self):
        self.effect(0)
        self.effect(1, code=0, stdout=b"unexpected success")
        self.assertEqual(self.status()["status"], "unexpected_outcome")
        self.assertEqual(self.status()["index"], 1)

    def test_stop_rearm_lost_registry_and_other_boot_cannot_resume(self):
        self.assertEqual(self.status(boot_id="other")["status"], "revoked")
        self.runtime.registry.resources.clear()
        self.assertEqual(self.status()["status"], "revoked")
        self.runtime.registry.resources[self.resource] = self.resource_object
        self.state.emergency_stop()
        self.assertEqual(self.status()["status"], "revoked")
        self.state.db.execute("UPDATE meta SET value=0 WHERE key='latched'")
        self.assertEqual(self.status()["status"], "revoked")

    def test_successful_exit_requires_independent_original_artifact_predicate(self):
        self.effect(0)
        self.effect(1, code=1, stderr=b"FAIL\n")
        self.effect(2)
        final = self.effect(3, code=0, stdout=b"PASS\n")
        self.assertEqual(self.status()["status"], "needs_verification")
        artifact_id = "e" * 32
        metadata = dict(relative_path="answer.py", sha256=sha(b"fixed"), size=5)
        self.state.db.execute(
            "INSERT INTO artifacts VALUES(?,?,?,?)",
            (artifact_id, final, canonical(metadata), b"fixed"),
        )
        check(self.state, final, artifact_id, boot_id="boot")
        observed = self.status()
        self.assertEqual(observed["status"], "verified")
        self.assertEqual(observed["artifact_id"], artifact_id)
        self.assertIn("exact-file-v1", observed["verification_scope"])
        self.assertEqual(len(observed["observations"]), 4)

    def test_pending_final_contract_uses_broker_approval_identity_without_core_launch(self):
        observed = dict(
            status="awaiting_grant",
            index=3,
            approval_id="f" * 32,
            config=dict(workflow=self.definition),
        )
        with (
            patch("mano_broker.developer.query", return_value=observed),
            patch("mano_broker.developer.control_request") as control,
            patch("mano_broker.developer.run_mock_step") as core,
        ):
            self.assertEqual(operator_step(self.id), observed)
            core.assert_not_called()
            control.assert_called_once_with(
                "declare_artifact_contract",
                dict(approval_id="f" * 32, **self.definition["artifact"]),
            )

    def test_revoked_workflow_never_launches_a_core_step(self):
        with (
            patch(
                "mano_broker.developer.query",
                return_value=dict(status="revoked", config=dict(workflow=self.definition)),
            ),
            patch("mano_broker.developer.run_mock_step") as core,
        ):
            self.assertEqual(operator_step(self.id)["status"], "revoked")
            core.assert_not_called()
