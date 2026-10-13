#!/usr/bin/env python3
"""Actual DAC/default ACL tests in the disposable VM, no executor/model."""

import errno
import fcntl
import json
import os
import pwd
import shutil
import subprocess
from pathlib import Path

from mano_broker.workspaces import BASE, create_workspace

assert os.geteuid() == 0
assert Path("/etc/mano-lab-disposable").read_text().strip() == "mano-phase0-ci"
assert subprocess.check_output(["systemd-detect-virt", "--vm"], text=True).strip() in {
    "kvm",
    "qemu",
}
assert not BASE.exists()
assert all(
    name not in {p.pw_name for p in pwd.getpwall()} for name in ("mano-broker", "mano-task-acl-ci")
)
created = []
fds = []
try:
    for name in ("mano-broker", "mano-task-acl-ci"):
        subprocess.run(
            ["useradd", "--no-create-home", "--shell", "/usr/sbin/nologin", name], check=True
        )
        created.append(name)
    broker = pwd.getpwnam("mano-broker")
    human = pwd.getpwnam("mano-human")
    worker = pwd.getpwnam("mano-worker")
    other = pwd.getpwnam("mano-task-acl-ci")
    first, fd = create_workspace(human_uid=human.pw_uid, caller_uid=worker.pw_uid)
    fds.append(fd)
    second, fd2 = create_workspace(human_uid=human.pw_uid, caller_uid=other.pw_uid)
    fds.append(fd2)
    assert first != second
    assert fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_PATH
    assert not os.get_inheritable(fd)
    assert os.fstat(fd).st_ino == first.stat().st_ino
    denials = []

    def run(actor, source, *args):
        result = subprocess.run(
            ["/usr/sbin/runuser", "-u", actor, "--", "python3", "-c", source, *map(str, args)],
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert result.returncode == 0, (actor, result.stderr)
        return result.stdout.strip()

    for actor, target in (
        ("mano-agent", first),
        ("mano-core", first),
        ("mano-task-acl-ci", first),
        ("mano-worker", second),
    ):
        observed = run(
            actor,
            """import errno,os,sys
try:os.listdir(sys.argv[1])
except PermissionError as e:
 assert e.errno==errno.EACCES;print('EACCES')
else:raise AssertionError('cross identity access')
""",
            target,
        )
        assert observed == "EACCES"
        denials.append(dict(actor=actor, target="other-workspace", errno=errno.EACCES))

    run(
        "mano-worker",
        """import os,sys
from pathlib import Path
os.umask(0o077)
p=Path(sys.argv[1]);(p/'shared.txt').write_text('worker-output')
(p/'nested').mkdir();(p/'nested'/'child.txt').write_text('nested-output')
fd=os.open(p/'private.txt',os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
os.write(fd,b'private-output');os.close(fd)
""",
        first,
    )
    for actor in ("mano-broker", "mano-human"):
        run(
            actor,
            """import errno,sys
from pathlib import Path
p=Path(sys.argv[1])
assert (p/'shared.txt').read_text()=='worker-output'
assert (p/'nested'/'child.txt').read_text()=='nested-output'
with (p/'shared.txt').open('a') as f:f.write('')
try:(p/'private.txt').read_text()
except PermissionError as e:assert e.errno==errno.EACCES
else:raise AssertionError('private creation mode bypassed')
""",
            first,
        )
    run(
        "mano-human",
        """import sys
from pathlib import Path
(Path(sys.argv[1])/'human.txt').write_text('human-output')
""",
        first,
    )
    for actor in ("mano-broker", "mano-worker"):
        run(
            actor,
            """import sys
from pathlib import Path
assert (Path(sys.argv[1])/'human.txt').read_text()=='human-output'
""",
            first,
        )
    acl = subprocess.check_output(["getfacl", "-cpn", str(first)], text=True)
    assert f"default:user:{broker.pw_uid}:rwx" in acl
    assert f"default:user:{human.pw_uid}:rwx" in acl
    for invalid in (True, 0, human.pw_uid, pwd.getpwnam("mano-core").pw_uid):
        before = set(BASE.iterdir())
        try:
            create_workspace(human_uid=human.pw_uid, caller_uid=invalid)
        except (ValueError, KeyError):
            pass
        else:
            raise AssertionError("invalid identity accepted")
        assert set(BASE.iterdir()) == before
    print(
        json.dumps(
            dict(
                scope="root administrative workspace creation; sandbox executor not integrated",
                fresh_distinct_workspaces=True,
                descriptor_noninheritable=True,
                kernel_cross_identity_denials=denials,
                inherited_broker_human_access=True,
                inherited_nested_access=True,
                private_creation_mode_respected=True,
                invalid_identity_no_directory=True,
                model_connected=False,
                production_execution_authorized=False,
            ),
            indent=2,
        )
    )
finally:
    for fd in fds:
        os.close(fd)
    # Only this guarded disposable fixture; never used by the creator.
    if BASE.exists():
        shutil.rmtree(BASE)
    for name in reversed(created):
        subprocess.run(["userdel", name], check=False, capture_output=True)
