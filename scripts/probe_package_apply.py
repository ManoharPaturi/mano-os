"""Real public-SDK/native-PAM/Root apply; disposable recovered btrfs guest only."""

import hashlib
import json
import subprocess
import time
from pathlib import Path

from ci_tty import native_terminal
from probe_package_plans import approve, client, guard

ROOT = Path("/opt/mano-lab")
GROUP = Path("/sys/fs/cgroup/mano.slice/mano-package.slice")


def terminal(arguments, answer):
    code, output = native_terminal(
        "mano_runtime.recovery", arguments, answers=((b"Type ", answer),)
    )
    assert code == 0, output[-4096:]
    rows = [json.loads(line) for line in output.decode().splitlines() if line.startswith("{")]
    assert len(rows) == 1
    return rows[0]


def run(rpc, human, identity, password, task):
    guard()
    from mano_broker.package_catalog import summary
    from mano_core.packages import apply_proposal, proposal
    from mano_protocol.actions import ActionRequest, canonical
    from mano_runtime import package_attempts
    from mano_runtime.package_operator import ACK, RETIRE

    recovered = json.loads((ROOT / "evidence/package-root-recovery.json").read_text())
    attempt = "14" * 16
    old_unknown = package_attempts.BASE / attempt / "unknown.json"
    original_unknown = old_unknown.read_bytes()
    acknowledgement = terminal(
        ("acknowledge-attempt", attempt, recovered["created"]["recovery_id"]), ACK
    )
    assert old_unknown.read_bytes() == original_unknown
    assert acknowledgement["effects_reversed_verified"] is False
    retired = terminal(
        ("retire-checkpoint", recovered["coherent_checkpoint"]["recovery_id"]), RETIRE
    )
    assert retired["snapshot_deleted"] is False
    catalog = summary()
    planned = proposal(
        task_id=task["task_id"],
        resource_id=task["resource_id"],
        names=["cowsay"],
        catalog_id=catalog["catalog_id"],
        key="native-root-apply-plan",
        reason="Review cowsay install",
    )
    forecast_grant = approve(rpc, human, identity, password, planned)
    forecast = client(identity, planned, forecast_grant)
    assert forecast["state"] == "done"
    plan = forecast["result"]["plan"]
    selected = next(row for row in plan["changes"] if row["name"] == "cowsay")
    assert selected["operation"] == "install"
    # Preserve the fixture-owned signed cache object outside the visible archive
    # inventory, forcing real bounded HTTPS acquisition without deleting its bytes.
    cache = Path("/var/cache/apt/archives")
    matches = [
        path
        for path in cache.glob("*.deb")
        if path.stat().st_size == selected["download_bytes"]
        and hashlib.sha256(path.read_bytes()).hexdigest() == selected["archive_sha256"]
    ]
    assert len(matches) == 1
    holding = cache / ".mano-apply-fixture-holding"
    holding.mkdir(mode=0o700)
    held = holding / matches[0].name
    matches[0].rename(held)
    proposed = apply_proposal(
        task_id=task["task_id"],
        resource_id=task["resource_id"],
        forecast_action_id=forecast["action_id"],
        plan_sha256=forecast["result"]["sha256"],
        key="native-root-apply",
        reason="Install the exact signed cowsay dependency plan",
    )
    private_probe = subprocess.run(
        [
            "/usr/sbin/runuser",
            "-u",
            identity.name,
            "--",
            "/usr/bin/python3",
            "-c",
            "import errno,socket; s=socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET);"
            "\ntry:s.connect('/run/mano-package-apply/request.sock')"
            "\nexcept PermissionError as e:assert e.errno==errno.EACCES"
            "\nelse:raise AssertionError('Untrusted task reached private Root apply socket')",
        ],
        capture_output=True,
        text=True,
        timeout=5,
    )
    assert private_probe.returncode == 0, private_probe.stderr
    denied = rpc(
        "request",
        dict(
            schema_version="1.0", operation="propose", body=proposed | dict(grant_id=forecast_grant)
        ),
        actor=identity.name,
    )
    assert denied["ok"] is False and "populated 0" in (GROUP / "cgroup.events").read_text()
    pending = rpc(
        "request",
        dict(schema_version="1.0", operation="request_approval", body=proposed),
        actor=identity.name,
    )["approval"]
    assert pending["state"] == "pending" and pending["grant_id"] is None
    view = human(dict(mode="view", id=pending["approval_id"]))["view"]
    assert view["capability"] == "packages.apply_install"
    scope = view["package_apply_scope"]
    assert scope["plan"] == plan and scope["system_root_operation"] is True
    assert scope["profile_auto_approval_allowed"] is False
    assert human(dict(mode="confirm", view=view, password="wrong-ci-password"))["ok"] is False
    granted = human(dict(mode="confirm", view=view, password=password))
    assert granted["ok"]
    program = """import json,sys,time
from mano_core.broker import BrokerClient
from mano_core.packages import PackageApply
body=json.load(sys.stdin)
with_client=BrokerClient()
try:
 worker=PackageApply.start(with_client,proposed=body['proposed'],grant_id=body['grant'])
 deadline=time.monotonic()+65
 while time.monotonic()<deadline:
  state=worker.status()
  if state['state'] in {'done','failed','unknown'}:break
  time.sleep(.12)
 assert state['state']=='done',state
 print(json.dumps(dict(action_id=worker.action_id,receipt=worker.result())))
finally:with_client.close()
"""
    completed = subprocess.run(
        [
            "/usr/sbin/runuser",
            "-u",
            identity.name,
            "--",
            "env",
            "-i",
            "PATH=/usr/bin:/bin",
            "PYTHONPATH=/usr/lib/mano-os",
            "PYTHONDONTWRITEBYTECODE=1",
            "/usr/bin/python3",
            "-c",
            program,
        ],
        input=json.dumps(dict(proposed=proposed, grant=granted["grant_id"])),
        capture_output=True,
        text=True,
        timeout=75,
    )
    if completed.returncode:
        logs = subprocess.run(
            ["journalctl", "-u", "mano-package-apply@*.service", "--no-pager", "-n", "50"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        raise AssertionError((completed.stderr[-4096:], logs.stdout[-8192:]))
    value = json.loads(completed.stdout)
    receipt = value["receipt"]
    assert (
        receipt["outcome"]["request_sha256"]
        == ActionRequest.parse(
            canonical(proposed | dict(grant_id=granted["grant_id"])).encode()
        ).digest
    )
    assert receipt["outcome"]["plan_sha256"] == forecast["result"]["sha256"]
    assert receipt["acquisition"]["network_used"] is True
    assert selected["archive_sha256"] in receipt["acquisition"]["downloaded_sha256"]
    assert all(
        receipt["boundary"][key] is True for key in receipt["boundary"] if key != "namespaces"
    )
    installed = subprocess.check_output(
        ["/usr/bin/dpkg-query", "-W", "-f=${db:Status-Status}:${Version}", "cowsay"], text=True
    )
    assert installed == "installed:" + selected["candidate"]
    assert Path("/usr/games/cowsay").is_file() and summary()["catalog_id"] != catalog["catalog_id"]
    deadline = time.monotonic() + 5
    while "populated 0" not in (GROUP / "cgroup.events").read_text():
        assert time.monotonic() < deadline
        time.sleep(0.02)
    history = package_attempts.reconcile()
    replay = rpc(
        "request",
        dict(
            schema_version="1.0",
            operation="propose",
            body=proposed | dict(grant_id=granted["grant_id"]),
        ),
        actor=identity.name,
    )
    assert (
        replay["ok"] and replay["fresh"] is False and replay["action"]["id"] == value["action_id"]
    )
    assert package_attempts.reconcile() == history
    assert old_unknown.read_bytes() == original_unknown and held.is_file()
    return dict(
        public_sdk=True,
        native_os_pam=True,
        synthetic_os_pam=True,
        distinct_fresh_apply_approval=True,
        private_socket_untrusted_uid_denied=True,
        forecast_grant_denied=True,
        wrong_password_denied=True,
        actual_signed_cowsay_installed=True,
        full_plan=plan,
        apply=value,
        operator_acknowledgement=acknowledgement,
        metadata_retirement=retired,
        unknown_record_preserved=True,
        completed_replay_no_new_effect=True,
        native_package_domain_empty=True,
        physical_input_provenance=None,
        live_model_connected=False,
    )
