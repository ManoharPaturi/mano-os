"""Actual installed approval/capture/Git interoperability, disposable guest only."""

import base64
import hashlib
import io
import json
import os
import subprocess
import tarfile
import tempfile
from pathlib import Path

from mano_broker.workspaces import create_workspace
from mano_core.workspace_checkpoints import proposal

CLIENT = """import base64,json,sys,time
from mano_core.broker import BrokerClient
from mano_core.workspace_checkpoints import Checkpoint
value=json.load(sys.stdin);client=BrokerClient()
try:
 worker=Checkpoint.start(client,proposal=value['proposal'],grant_id=value['grant_id'])
 deadline=time.monotonic()+12
 while time.monotonic()<deadline:
  state=worker.status()
  if state['state'] in {'done','failed','unknown'}:break
  time.sleep(.15)
 if state['state']=='done':
  observed=worker.read();result=dict(metadata=observed['metadata'],
   data=base64.b64encode(observed['data']).decode())
 else:result=dict(state=state['state'])
 print(json.dumps(dict(action_id=worker.action_id,result=result)))
finally:client.close()
"""


def run(rpc, human, identity, password):
    assert os.geteuid() == 0
    assert Path("/etc/mano-lab-disposable").read_text().strip() == "mano-phase0-ci"
    workspace, fd = create_workspace(human_uid=1002, caller_uid=identity.uid)
    os.close(fd)
    task = rpc(
        "provision",
        dict(
            schema_version="1.0",
            operation="provision_task",
            body=dict(
                human_uid=1002,
                caller_uid=identity.uid,
                mode="supervised",
                classification="internal",
            ),
        ),
        actor="root",
        directory=workspace,
    )
    assert task["ok"]
    files = {
        "source.py": b'print("checkpoint-original")\n',
        "nested/binary": b"\0\xff\x01",
        "run.sh": b"#!/bin/sh\necho checkpoint\n",
        ".gitattributes": b"* filter=must-never-run diff=must-never-run export-ignore\n",
    }
    for name, data in files.items():
        target = workspace / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        target.chmod(0o755 if name == "run.sh" else 0o644)
    (workspace / ".git/hooks").mkdir(parents=True)
    (workspace / ".git/config").write_text(
        "[core]\nhooksPath=/tmp/must-never-use\n"
        '[filter "must-never-run"]\nclean=touch /tmp/mano-checkpoint-filter-canary\n'
    )
    (workspace / ".git/hooks/pre-commit").write_text(
        "#!/bin/sh\ntouch /tmp/mano-checkpoint-hook-canary\n"
    )
    (workspace / ".git/hooks/pre-commit").chmod(0o755)
    config_before = hashlib.sha256((workspace / ".git/config").read_bytes()).hexdigest()

    def execute(key):
        proposed = proposal(
            task_id=task["task_id"],
            resource_id=task["resource_id"],
            key=key,
            reason="Save complete bounded source workspace as Git objects",
        )
        pending = rpc(
            "request",
            dict(schema_version="1.0", operation="request_approval", body=proposed),
            actor=identity.name,
        )["approval"]
        assert pending["state"] == "pending"
        view = human(dict(mode="view", id=pending["approval_id"]))["view"]
        assert view["capability"] == "workspace.checkpoint" and view["args"] == proposed["args"]
        grant = human(dict(mode="confirm", view=view, password=password))
        assert grant["ok"]
        observed = subprocess.run(
            [
                "/usr/sbin/runuser",
                "-u",
                identity.name,
                "--",
                "env",
                "PYTHONPATH=/usr/lib/mano-os",
                "PYTHONDONTWRITEBYTECODE=1",
                "python3",
                "-c",
                CLIENT,
            ],
            input=json.dumps(dict(proposal=proposed, grant_id=grant["grant_id"])),
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
        assert observed.returncode == 0, (observed.stdout, observed.stderr)
        result = json.loads(observed.stdout)
        replay = rpc(
            "request",
            dict(
                schema_version="1.0",
                operation="propose",
                body=proposed | dict(grant_id=grant["grant_id"]),
            ),
            actor=identity.name,
        )
        assert replay["ok"] and replay["fresh"] is False
        assert replay["action"]["id"] == result["action_id"]
        return result

    saved = execute("git-checkpoint-original")
    receipt = saved["result"]["metadata"]
    data = base64.b64decode(saved["result"]["data"], validate=True)
    assert hashlib.sha256(data).hexdigest() == receipt["sha256"]
    assert receipt["files"] == len(files) and receipt["git_metadata_imported"] is False
    assert receipt["effect_verified"] is receipt["atomic_filesystem_snapshot"] is False
    (workspace / "source.py").write_bytes(b"changed after snapshot\n")
    (workspace / "added-later").write_bytes(b"not in snapshot\n")
    query = dict(
        schema_version="1.0",
        operation="checkpoint_result",
        body=dict(task_id=task["task_id"], action_id=saved["action_id"]),
    )
    assert rpc("request", query)["ok"] is False
    assert (
        rpc(
            "request",
            query | dict(body=query["body"] | dict(task_id="0" * 32)),
            actor=identity.name,
        )["ok"]
        is False
    )

    # The reference Git program runs only as the unprivileged Task UID against
    # our generated repository, never the workspace .git or Root's configuration.
    with tempfile.TemporaryDirectory(prefix="mano-checkpoint-reference-", dir="/run") as folder:
        root = Path(folder)
        repo = root / "repo"
        repo.mkdir()
        with tarfile.open(fileobj=io.BytesIO(data)) as source:
            for member in source:
                assert member.isfile() and ".." not in Path(member.name).parts
                target = repo / member.name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(source.extractfile(member).read())
        for target in [*root.rglob("*"), root]:
            os.chown(target, identity.uid, identity.gid)

        def git(*args):
            response = subprocess.run(
                [
                    "/usr/sbin/runuser",
                    "-u",
                    identity.name,
                    "--",
                    "env",
                    "-i",
                    "PATH=/usr/bin:/bin",
                    "HOME=" + folder,
                    "GIT_CONFIG_NOSYSTEM=1",
                    "GIT_CONFIG_GLOBAL=/dev/null",
                    "GIT_TERMINAL_PROMPT=0",
                    "GIT_ATTR_NOSYSTEM=1",
                    "/usr/bin/git",
                    "--git-dir=" + str(repo),
                    *args,
                ],
                cwd=root,
                capture_output=True,
                timeout=5,
                check=True,
            )
            return response.stdout

        git("fsck", "--strict", "--full")
        restored = {}
        for entry in git("ls-tree", "-rz", "HEAD").rstrip(b"\0").split(b"\0"):
            fields, name = entry.split(b"\t", 1)
            mode, kind, oid = fields.split()
            assert kind == b"blob"
            assert mode == (b"100755" if name == b"run.sh" else b"100644")
            restored[name.decode()] = git("cat-file", "blob", oid.decode())
        assert restored == files
        assert git("rev-parse", "HEAD").decode().strip() == receipt["commit"]
        git_version = git("--version").decode().strip()
    # The actual native library must reject unsafe source entries without a
    # partial checkpoint. This also exercises explicit unknown replay semantics.
    (workspace / "escape").symlink_to("/etc/passwd")
    failed = execute("git-checkpoint-symlink-denial")
    assert failed["result"]["state"] == "unknown"
    (workspace / "escape").unlink()
    assert hashlib.sha256((workspace / ".git/config").read_bytes()).hexdigest() == config_before
    assert not Path("/tmp/mano-checkpoint-filter-canary").exists()
    assert not Path("/tmp/mano-checkpoint-hook-canary").exists()
    report = dict(
        checkpoint=receipt,
        action_id=saved["action_id"],
        failed_action_id=failed["action_id"],
        native_pam=True,
        whole_source_tree=True,
        native_git_fsck=True,
        git_version=git_version,
        exact_original_bytes_recovered=True,
        original_workspace_still_changed=True,
        hook_or_filter_executed=False,
        workspace_git_config_unchanged=True,
        symlink_escape_denied=True,
        replay_reexecution=False,
        model_disclosure=False,
        scope="bounded Git source checkpoint; not atomic filesystem rollback",
    )
    assert (workspace / "source.py").read_bytes() == b"changed after snapshot\n"
    return report
