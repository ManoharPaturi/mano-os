#!/usr/bin/env python3
"""Real openat2 descriptor/mount denial tests, fixed disposable guest only."""

import errno
import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path

from mano_broker.resources import LIBRARY, Workspace
from mano_broker.state import Denied

BASE = Path("/var/lib/mano-broker/resource-pin-probe")
assert os.geteuid() == 0
assert Path("/etc/mano-lab-disposable").read_text().strip() == "mano-phase0-ci"
assert subprocess.check_output(["systemd-detect-virt", "--vm"], text=True).strip() in {
    "kvm",
    "qemu",
}
assert not BASE.exists() and not LIBRARY.exists()
BASE.mkdir(mode=0o700)
mounted = False
workspace = None
try:
    LIBRARY.parent.mkdir(mode=0o755, exist_ok=True)
    subprocess.run(
        [
            "cc",
            "-std=c11",
            "-O2",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-fPIC",
            "-shared",
            "/opt/mano-lab/native/mano_resources.c",
            "-Wl,-z,relro,-z,now",
            "-o",
            str(LIBRARY),
        ],
        check=True,
    )
    LIBRARY.chmod(0o644)
    root = BASE / "workspace"
    root.mkdir()
    outside = BASE / "outside"
    outside.write_text("protected")
    sentinel = hashlib.sha256(outside.read_bytes()).hexdigest()
    (root / "file").write_text("original")
    fd = os.open(root, os.O_PATH | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        workspace = Workspace(fd)
    finally:
        os.close(fd)
    denials = []
    with workspace.pin("file") as target:
        assert not os.get_inheritable(target.fd)
        initial_inode = target.inode
        (root / "file").unlink()
        (root / "file").symlink_to(outside)
        assert os.fstat(target.fd).st_ino == initial_inode
        assert os.fstat(target.fd).st_ino != outside.stat().st_ino
    try:
        workspace.pin("file")
    except OSError as error:
        assert error.errno == errno.ELOOP
        denials.append({"case": "symlink-replacement", "kernel_errno": "ELOOP"})
    else:
        raise AssertionError("Symlink followed")
    (root / "dirlink").symlink_to(BASE)
    try:
        workspace.pin("dirlink/outside")
    except OSError as error:
        assert error.errno == errno.ELOOP
        denials.append({"case": "intermediate-symlink", "kernel_errno": "ELOOP"})
    else:
        raise AssertionError("Intermediate symlink followed")
    os.link(outside, root / "hard")
    try:
        workspace.pin("hard")
    except Denied:
        denials.append({"case": "hardlinked-file", "policy_denied": True})
    else:
        raise AssertionError("Hardlinked target accepted")
    os.mkfifo(root / "fifo")
    try:
        workspace.pin("fifo")
    except Denied:
        denials.append({"case": "fifo-type", "policy_denied": True})
    else:
        raise AssertionError("FIFO accepted")
    (root / "mounted").mkdir()
    subprocess.run(
        ["mount", "-t", "tmpfs", "-o", "size=1m", "mano-pin-test", str(root / "mounted")],
        check=True,
    )
    mounted = True
    (root / "mounted/file").write_text("different-mount")
    try:
        workspace.pin("mounted/file")
    except OSError as error:
        assert error.errno == errno.EXDEV
        denials.append({"case": "mount-crossing", "kernel_errno": "EXDEV"})
    else:
        raise AssertionError("Mount crossed")
    subprocess.run(["umount", str(root / "mounted")], check=True)
    mounted = False
    moved = BASE / "moved"
    root.rename(moved)
    root.mkdir()
    (root / "replacement").write_text("new-root")
    (moved / "retained").write_text("old-root")
    with workspace.pin("retained") as retained:
        assert retained.inode == (moved / "retained").stat().st_ino
    try:
        workspace.pin("replacement")
    except FileNotFoundError:
        pass
    else:
        raise AssertionError("Replacement root used")
    assert hashlib.sha256(outside.read_bytes()).hexdigest() == sentinel
    print(
        json.dumps(
            dict(
                scope="descriptor custody library; registry/executor not integrated",
                regular_target_pinned=True,
                retained_target_inode_after_replacement=True,
                retained_root_inode_after_rename=True,
                no_descriptor_inheritance=True,
                denials=denials,
                protected_sentinel_hash_preserved=True,
                binary_sha256=hashlib.sha256(LIBRARY.read_bytes()).hexdigest(),
                contents_immutable=False,
                model_connected=False,
                production_execution_authorized=False,
            ),
            indent=2,
        )
    )
finally:
    if workspace:
        workspace.close()
    if mounted:
        subprocess.run(["umount", str(BASE / "workspace/mounted")], check=True)
    LIBRARY.unlink(missing_ok=True)
    shutil.rmtree(BASE)
