#!/usr/bin/env python3
"""Fixed disposable-guest setup/status/cleanup for the real serial rescue test."""

import errno
import json
import os
import pwd
import secrets
import stat
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path("/run/mano-rescue-fixture")
UNIT = "mano-rescue-core.service"


def run(argv, **kwargs):
    return subprocess.run(argv, text=True, capture_output=True, check=True, timeout=20, **kwargs)


def status():
    deadline = time.monotonic() + 5
    while True:
        pid = int(run(["systemctl", "show", UNIT, "-p", "MainPID", "--value"]).stdout.strip())
        if pid > 0:
            fields = dict(
                line.split(":", 1)
                for line in Path(f"/proc/{pid}/status").read_text().splitlines()
                if ":" in line
            )
            if fields["State"].strip().startswith("T"):
                break
        if time.monotonic() > deadline:
            raise RuntimeError(f"Core freeze not observed: pid={pid}")
        time.sleep(0.05)
    actual_uid = int(fields["Uid"].split()[0])
    assert actual_uid == pwd.getpwnam("mano-core").pw_uid, f"Unexpected frozen UID {actual_uid}"
    return {
        "core_pid": pid,
        "core_state": fields["State"].strip(),
        "core_uid": int(fields["Uid"].split()[0]),
        "human_uid": pwd.getpwnam("mano-human").pw_uid,
    }


def main():
    if len(sys.argv) != 2 or sys.argv[1] not in {"prepare", "status", "cleanup", "approval-status"}:
        raise RuntimeError("Fixed fixture operation required")
    if os.getuid() != 0 or Path("/etc/mano-lab-disposable").read_text().strip() != "mano-phase0-ci":
        raise RuntimeError("Disposable guest root required")
    if run(["systemd-detect-virt", "--vm"]).stdout.strip() not in {"kvm", "qemu"}:
        raise RuntimeError("QEMU guest required")
    operation = sys.argv[1]
    if operation == "approval-status":
        journal = Path("/var/lib/mano-broker/approval-journal.jsonl")
        events = [json.loads(line) for line in journal.read_text().splitlines()]
        marker = json.loads(Path("/var/lib/mano-broker/approval-fixture").read_text())
        assert sum(event["decision"] == "approved" for event in events) == 1
        assert marker["decision"] == "approved"
        assert journal.stat().st_uid == 0 and stat.S_IMODE(journal.stat().st_mode) == 0o600
        attacks = json.loads(Path("/opt/mano-lab/evidence/approval-attacks.json").read_text())
        print(
            json.dumps(
                {
                    "journal": events,
                    "marker": marker,
                    "attacks": attacks,
                    "journal_owner_uid": 0,
                    "journal_mode": "0600",
                }
            )
        )
        return
    if operation == "cleanup":
        for command in (
            ["systemctl", "kill", "--signal=KILL", "--kill-whom=all", UNIT],
            ["systemctl", "stop", UNIT],
        ):
            subprocess.run(command, text=True, capture_output=True, timeout=20, check=False)
        for command in (["systemctl", "stop", "mano-approval-spike.service"],):
            subprocess.run(command, text=True, capture_output=True, timeout=20, check=False)
        approval_pid = subprocess.run(
            ["systemctl", "show", "mano-approval-spike.service", "-p", "MainPID", "--value"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        assert approval_pid.stdout.strip() in {"", "0"}, "Approval service remained alive"
        for name in (
            "/var/lib/mano-broker/approval-journal.jsonl",
            "/var/lib/mano-broker/approval-fixture",
            "/run/mano-approval-fixture/human.sock",
        ):
            Path(name).unlink(missing_ok=True)
        run(["/usr/sbin/usermod", "-L", "mano-human"])
        shadow = next(
            line.split(":")[1]
            for line in Path("/etc/shadow").read_text().splitlines()
            if line.startswith("mano-human:")
        )
        assert shadow.startswith("!"), "Fixture human account did not lock"
        remaining = subprocess.run(
            ["systemctl", "show", UNIT, "-p", "MainPID", "--value"],
            text=True,
            capture_output=True,
            timeout=10,
            check=False,
        )
        assert remaining.stdout.strip() in {"", "0"}, "Fixture core still alive after cleanup"
        for name in ("state.json", "challenge"):
            (ROOT / name).unlink(missing_ok=True)
        print(json.dumps({"account_locked": True, "core_removed": True}))
        return
    if operation == "status":
        print(json.dumps(status()))
        return
    if ROOT.is_symlink():
        raise RuntimeError("Invalid fixture directory")
    ROOT.mkdir(mode=0o711, exist_ok=True)
    if ROOT.stat().st_uid != 0 or (ROOT / "state.json").exists():
        raise RuntimeError("Refusing existing fixture state")
    human = pwd.getpwnam("mano-human")
    password, challenge = secrets.token_hex(24), secrets.token_hex(24)
    run(["chpasswd"], input=f"mano-human:{password}\n")
    token = ROOT / "challenge"
    token.write_text(challenge)
    os.chown(token, human.pw_uid, human.pw_gid)
    os.chmod(token, 0o400)
    for actor in ("mano-agent", "mano-core", "mano-worker"):
        result = subprocess.run(
            [
                "/usr/sbin/runuser",
                "-u",
                actor,
                "--",
                "python3",
                "-c",
                "from pathlib import Path; import sys; "
                "\ntry: Path('/run/mano-rescue-fixture/challenge').read_text()"
                "\nexcept PermissionError: sys.exit(0)"
                "\nsys.exit(1)",
            ],
            text=True,
            capture_output=True,
            timeout=10,
            check=False,
        )
        assert result.returncode == 0, f"{actor} accessed the human recovery challenge"
    run(["systemctl", "start", "serial-getty@ttyS0.service"])
    run(
        [
            "systemd-run",
            "--unit=mano-rescue-core",
            "--uid=mano-core",
            "--property=Type=exec",
            "--property=TimeoutStopSec=5",
            "/bin/sleep",
            "600",
        ]
    )
    run(["systemctl", "kill", "--signal=STOP", "--kill-whom=main", UNIT])
    run(
        [
            "systemd-run",
            "--unit=mano-approval-spike",
            "--property=Type=exec",
            "--property=TimeoutStopSec=5",
            "--setenv=PYTHONPATH=/opt/mano-lab/src",
            "/usr/bin/python3",
            "/opt/mano-lab/scripts/approval_service.py",
        ]
    )
    deadline = time.monotonic() + 10
    while not Path("/run/mano-approval-fixture/human.sock").is_socket():
        if time.monotonic() > deadline:
            raise RuntimeError("Approval service not ready")
        time.sleep(0.05)
    subprocess.run(["/usr/sbin/modprobe", "uinput"], capture_output=True, timeout=10, check=False)
    device = Path("/dev/uinput")
    if not device.exists():
        os.mknod(device, stat.S_IFCHR | 0o600, os.makedev(10, 223))
    assert stat.S_ISCHR(device.stat().st_mode)
    try:
        descriptor = os.open(device, os.O_WRONLY)
        os.close(descriptor)
        driver_available = True
    except OSError as error:
        assert error.errno in {errno.ENODEV, errno.ENXIO}, error
        driver_available = False
    attacks = []
    for actor in ("mano-agent", "mano-core", "mano-worker"):
        for kind, path in (
            ("approval-socket", "/run/mano-approval-fixture/human.sock"),
            ("journal-write", "/var/lib/mano-broker/approval-journal.jsonl"),
            ("uinput-open", "/dev/uinput"),
        ):
            code = (
                "import socket,os,sys,errno; "
                "\ntry:"
                "\n if sys.argv[1]=='approval-socket': "
                "s=socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET); s.connect(sys.argv[2])"
                "\n else: os.open(sys.argv[2],os.O_WRONLY|os.O_CREAT) "
                "if sys.argv[1]=='journal-write' else os.open(sys.argv[2],os.O_WRONLY)"
                "\nexcept PermissionError as e: assert e.errno==errno.EACCES; sys.exit(0)"
                "\nsys.exit(1)"
            )
            denial = subprocess.run(
                ["/usr/sbin/runuser", "-u", actor, "--", "python3", "-c", code, kind, path],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            assert denial.returncode == 0, f"{actor} {kind} was not denied"
            attacks.append({"actor": actor, "route": kind, "kernel_errno": "EACCES"})
    Path("/opt/mano-lab/evidence/approval-attacks.json").write_text(
        json.dumps(
            {
                "denials": attacks,
                "uinput_driver_available": driver_available,
                "uinput_character_device": True,
                "physical_input_provenance": None,
            },
            indent=2,
        )
        + "\n"
    )
    value = dict(status(), password=password, challenge=challenge)
    descriptor = os.open(
        ROOT / "state.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
    )
    with os.fdopen(descriptor, "w") as stream:
        stream.write(json.dumps(value))
    # Captured by the trusted CI runner, never printed to CI logs or artifacts.
    print(json.dumps(value))


if __name__ == "__main__":
    main()
