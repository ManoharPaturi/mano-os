"""Approved package apply through installed modules and native TTY in CI only."""

import hashlib
import json
import os
import subprocess
from pathlib import Path

from probe_poweroff_restore import PoweroffRestore

SDK = """import json,sys,time
from mano_core.broker import BrokerClient
from mano_core.packages import PackagePlan,PackageApply,proposal,apply_proposal
v=json.load(sys.stdin); transport=BrokerClient()
def client(packet):
 time.sleep(.12)
 return transport(packet)
try:
 mode=v['mode']
 if mode=='forecast-proposal':
  result=proposal(task_id=v['task_id'],resource_id=v['resource_id'],names=['sl'],
   catalog_id=v['catalog_id'],key='installed-sl-forecast',
   reason='Review installed runtime package apply')
 elif mode=='apply-proposal':
  result=apply_proposal(task_id=v['task_id'],resource_id=v['resource_id'],
   forecast_action_id=v['forecast']['action_id'],plan_sha256=v['forecast']['result']['sha256'],
   key='installed-sl-apply',reason='Install exact signed sl plan through packaged runtime')
 else:
  worker=(PackagePlan if mode=='forecast' else PackageApply).start(client,
   proposed=v['proposed'],grant_id=v['grant'])
  deadline=time.monotonic()+65
  while time.monotonic()<deadline:
   state=worker.status()
   if state['state'] in {'done','failed','unknown'}:break
   time.sleep(.12)
  assert state['state']=='done',state
  result=dict(action_id=worker.action_id,result=worker.result())
 print(json.dumps(result))
finally:transport.close()
"""


def run(managed, password, python, query, checkpoint):
    assert os.geteuid() == 0
    assert Path("/etc/mano-lab-disposable").read_text().strip() == "mano-phase0-ci"
    assert subprocess.check_output(["systemd-detect-virt", "--vm"], text=True).strip() in {
        "qemu",
        "kvm",
    }
    from probe_package_apply import terminal

    retired = terminal(
        ("retire-checkpoint", checkpoint["recovery_id"]),
        "ARCHIVE CHECKPOINT METADATA WITHOUT DELETING SNAPSHOT",
    )
    assert retired["snapshot_deleted"] is False
    # This refresh is an explicit CI administrator operation, not a model grant.
    refresh = subprocess.run(
        ["/usr/sbin/mano-package-catalog"], check=True, capture_output=True, text=True, timeout=120
    )
    catalog = json.loads(refresh.stdout)

    def installed(program, body=None, actor=None):
        return python(program, actor=actor, body=body)

    def public(operation, body, actor):
        return installed(
            """import json,sys
from mano_core.broker import BrokerClient
v=json.load(sys.stdin);c=BrokerClient()
try:print(json.dumps(c(v)))
finally:c.close()
""",
            dict(schema_version="1.0", operation=operation, body=body),
            actor,
        )

    def view(mode, identifier):
        return query(dict(mode=mode, id=identifier))

    approvals = PoweroffRestore(installed, public, view, "mano-human")
    context = managed["context"]

    def sdk(mode, **body):
        return installed(SDK, dict(mode=mode, **body), managed["caller_name"])

    proposed = sdk(
        "forecast-proposal",
        task_id=context["task_id"],
        resource_id=context["resource_id"],
        catalog_id=catalog["catalog_id"],
    )
    grant, _ = approvals.approval(managed, proposed, password)
    forecast = sdk("forecast", proposed=proposed, grant=grant)
    plan = forecast["result"]["plan"]
    assert 1 <= len(plan["changes"]) <= 2
    assert {"sl"} <= {row["name"] for row in plan["changes"]} <= {"sl", "libncurses6"}
    assert all(
        row["operation"] == "install" and row["installed"] is None for row in plan["changes"]
    )
    proposed = sdk(
        "apply-proposal",
        task_id=context["task_id"],
        resource_id=context["resource_id"],
        forecast=forecast,
    )
    before = Path("/var/lib/dpkg/status").read_bytes()
    grant, reviewed = approvals.approval(managed, proposed, password, cancel_first=True)
    assert Path("/var/lib/dpkg/status").read_bytes() == before
    assert reviewed["package_apply_scope"]["plan"] == plan
    applied = sdk("apply", proposed=proposed, grant=grant)
    after = Path("/var/lib/dpkg/status").read_bytes()
    receipt = applied["result"]
    assert (
        receipt["outcome"]["postconditions"]["before_status_sha256"]
        == hashlib.sha256(before).hexdigest()
    )
    assert (
        receipt["outcome"]["postconditions"]["after_status_sha256"]
        == hashlib.sha256(after).hexdigest()
    )
    assert Path("/usr/games/sl").is_file()
    package = subprocess.check_output(
        ["/usr/bin/dpkg-query", "-W", "-f=${Version}", "sl"], text=True
    )
    selected = next(row for row in plan["changes"] if row["name"] == "sl")
    assert package == selected["candidate"]
    # Retire only metadata after successful receipt; preserve its snapshot/history.
    terminal(
        ("retire-checkpoint", receipt["checkpoint"]),
        "ARCHIVE CHECKPOINT METADATA WITHOUT DELETING SNAPSHOT",
    )
    out = Path("/opt/mano-lab/evidence")
    (out / "packaged-apply-before-status").write_bytes(before)
    (out / "packaged-apply-after-status").write_bytes(after)
    witness = dict(
        actual_installed_module=True,
        native_root_tty=True,
        native_human_pam_tty=True,
        cancellation_before_password_no_grant=True,
        cancelled_approval_no_database_effect=True,
        full_plan=plan,
        forecast=forecast,
        apply=applied,
        proposed=proposed,
        package_version=package,
        actual_sl_installed=True,
        automatic_repair=False,
        physical_input_provenance=None,
        effects_reversed_verified=False,
    )
    (out / "packaged-package-apply.json").write_text(json.dumps(witness, indent=2) + "\n")
    return witness
