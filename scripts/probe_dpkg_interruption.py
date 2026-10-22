"""Real dpkg interruption with unsigned fixture, disposable Root CI only; never shipped."""

import hashlib
import json
import os
import re
import shutil
import signal
import stat
import subprocess
import time
from pathlib import Path

PACKAGE = "mano-recovery-interrupt-ci"
RUNTIME = Path("/run/mano-package-interruption-ci")
PAYLOAD = Path("/usr/share/mano-recovery-interrupt-ci/payload.bin")
PAYLOAD_BYTES = b"actual dpkg unpacked fixture payload\x00\xff\n"


def guard():
    assert os.geteuid() == 0
    assert Path("/etc/mano-lab-disposable").read_text().strip() == "mano-phase0-ci"
    assert subprocess.check_output(["systemd-detect-virt", "--vm"], text=True).strip() in {
        "qemu",
        "kvm",
    }


def journal_inventory(directory):
    paths = sorted(directory.iterdir())
    assert 1 <= len(paths) <= 32
    records, half_configured = {}, None
    for path in paths:
        info = path.lstat()
        assert re.fullmatch("[A-Za-z0-9_.-]{1,64}", path.name)
        assert stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1
        assert info.st_size <= 65536
        content = path.read_bytes()
        assert len(content) == info.st_size
        records[path.name] = dict(size=len(content), sha256=hashlib.sha256(content).hexdigest())
        if (
            b"Package: " + PACKAGE.encode() + b"\n" in content
            and b"Status: install ok half-configured\n" in content
        ):
            half_configured = path.name
    assert half_configured is not None, "dpkg did not persist its half-configured journal"
    return records, half_configured


def wait_stopped(pid):
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline:
        text = Path("/proc", str(pid), "status").read_text()
        if next(row.split()[1] for row in text.splitlines() if row.startswith("State:")) == "T":
            return
        time.sleep(0.01)
    raise AssertionError("Actual dpkg/postinst process did not stop")


def interrupt_install(while_frozen, *, frontend_scope=None):
    guard()
    frontend_env = {}
    if frontend_scope is not None:
        frontend_scope.check(backend=False)
        assert frontend_scope.backend_held is False
        frontend_env = {"DPKG_FRONTEND_LOCKED": "1"}
    assert not PAYLOAD.exists() and not RUNTIME.exists()
    RUNTIME.mkdir(mode=0o700)
    stage = Path("/opt/mano-lab/work/interrupted-package")
    assert not stage.exists()
    shutil.copytree("/opt/mano-lab/tests/fixtures/package-recovery-interrupt", stage)
    data = stage / PAYLOAD.relative_to("/")
    data.parent.mkdir(parents=True)
    data.write_bytes(PAYLOAD_BYTES)
    package = Path("/opt/mano-lab/work/unsigned-interruption-ci.deb")
    assert not package.exists()
    subprocess.run(
        ["/usr/bin/dpkg-deb", "--root-owner-group", "--build", str(stage), str(package)],
        check=True,
        capture_output=True,
        timeout=30,
    )
    assert package.stat().st_size < 16384
    observer = Path("/opt/mano-lab/work/package-lock-owner-ci")
    if frontend_scope is not None:
        assert not observer.exists()
        subprocess.run(
            [
                "/usr/bin/cc",
                "-std=c11",
                "-O2",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-fstack-protector-strong",
                "-D_FORTIFY_SOURCE=2",
                "/opt/mano-lab/tests/fixtures/package-lock-owner.c",
                "-o",
                str(observer),
            ],
            check=True,
            capture_output=True,
            timeout=30,
        )
    status_r, status_w = os.pipe2(os.O_CLOEXEC)
    process = subprocess.Popen(
        ["/usr/bin/dpkg", "--status-fd", str(status_w), "--install", str(package)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env={"PATH": "/usr/sbin:/usr/bin:/bin", "LANG": "C.UTF-8", **(frontend_env or {})},
        pass_fds=(status_w,),
        start_new_session=True,
    )
    os.close(status_w)
    os.set_blocking(status_r, False)
    transcript = bytearray()
    handles = []
    try:
        deadline = time.monotonic() + 15
        marker = RUNTIME / "postinst-started"
        while time.monotonic() < deadline:
            try:
                transcript.extend(os.read(status_r, 8192))
            except BlockingIOError:
                pass
            assert len(transcript) <= 32768
            if marker.exists():
                break
            assert process.poll() is None, "dpkg exited before the maintainer-script checkpoint"
            time.sleep(0.02)
        assert marker.exists(), "Actual dpkg postinst never started"
        postinst_pid = int(marker.read_text().strip())
        expected = ["/usr/bin/dpkg", "--status-fd", str(status_w), "--install", str(package)]
        actual = Path("/proc", str(process.pid), "cmdline").read_bytes().rstrip(b"\0").split(b"\0")
        assert actual == [value.encode() for value in expected]
        executable = Path("/proc", str(process.pid), "exe").resolve(strict=True)
        assert executable == Path("/usr/bin/dpkg").resolve(strict=True)
        status = Path("/proc", str(postinst_pid), "status").read_text()
        assert (
            int(next(row.split()[1] for row in status.splitlines() if row.startswith("PPid:")))
            == process.pid
        )
        assert Path("/proc", str(postinst_pid)).stat().st_uid == 0
        assert (PACKAGE + ".postinst").encode() in Path(
            "/proc", str(postinst_pid), "cmdline"
        ).read_bytes()
        assert os.getpgid(process.pid) == process.pid == os.getpgid(postinst_pid)
        assert PAYLOAD.read_bytes() == PAYLOAD_BYTES
        for pid in (process.pid, postinst_pid):
            handle = os.pidfd_open(pid)
            handles.append(handle)
            signal.pidfd_send_signal(handle, signal.SIGSTOP)
            wait_stopped(pid)
        assert not (RUNTIME / "postinst-completed").exists()
        owners, observed = None, None
        if frontend_scope is not None:
            result = subprocess.run(
                [str(observer)], check=False, capture_output=True, text=True, timeout=5
            )
            assert result.returncode == 0, (result.stdout, result.stderr)
            observed = json.loads(result.stdout)
            assert observed["query"] == "F_GETLK"
            assert observed["observer_pid"] not in {os.getpid(), process.pid, postinst_pid}
            owners = observed["owners"]
            assert owners["frontend"]["pid"] == os.getpid(), observed
            assert owners["backend"]["pid"] == process.pid, observed
        assert "BlockingIOError" in while_frozen()
        # Intentionally interrupt only this known, pinned, fresh CI process group.
        os.killpg(process.pid, signal.SIGKILL)
        stdout, stderr = process.communicate(timeout=10)
        assert process.returncode == -signal.SIGKILL
        assert len(stdout) + len(stderr) <= 32768
        while True:
            try:
                piece = os.read(status_r, 8192)
                if not piece:
                    break
                transcript.extend(piece)
            except BlockingIOError:
                break
        assert len(transcript) <= 32768
        assert PACKAGE.encode() in transcript and b"half-configured" in transcript
        records, entry = journal_inventory(Path("/var/lib/dpkg/updates"))
        assert PAYLOAD.read_bytes() == PAYLOAD_BYTES
        return dict(
            actual_dpkg_interruption=True,
            unsigned_ci_package=True,
            package_name=PACKAGE,
            package_sha256=hashlib.sha256(package.read_bytes()).hexdigest(),
            dpkg_pid=process.pid,
            postinst_pid=postinst_pid,
            dpkg_executable=str(executable),
            process_group=process.pid,
            return_code=process.returncode,
            kernel_stopped_before_kill=True,
            postinst_started=True,
            postinst_completed=False,
            unpacked_payload_sha256=hashlib.sha256(PAYLOAD_BYTES).hexdigest(),
            journal_entries=records,
            half_configured_entry=entry,
            half_configured_status_event=True,
            product_stop_invoked=False,
            recovery_while_dpkg_live_denied=True,
            frontend_protocol_lock_owners=owners,
            frontend_protocol_lock_observation=observed,
            maintainer_script_scope="controlled unsigned CI fixture, not production package",
        )
    finally:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.communicate(timeout=10)
        os.close(status_r)
        for fd in handles:
            os.close(fd)
