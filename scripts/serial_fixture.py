#!/usr/bin/env python3
"""Fixed disposable-guest setup/status/cleanup for the real serial rescue test."""

import json
import os
import pwd
import secrets
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
    assert int(fields["Uid"].split()[0]) == pwd.getpwnam("mano-core").pw_uid
    return {
        "core_pid": pid,
        "core_state": fields["State"].strip(),
        "core_uid": int(fields["Uid"].split()[0]),
        "human_uid": pwd.getpwnam("mano-human").pw_uid,
    }


def main():
    if len(sys.argv) != 2 or sys.argv[1] not in {"prepare", "status", "cleanup"}:
        raise RuntimeError("Fixed fixture operation required")
    if os.getuid() != 0 or Path("/etc/mano-lab-disposable").read_text().strip() != "mano-phase0-ci":
        raise RuntimeError("Disposable guest root required")
    if run(["systemd-detect-virt", "--vm"]).stdout.strip() not in {"kvm", "qemu"}:
        raise RuntimeError("QEMU guest required")
    operation = sys.argv[1]
    if operation == "cleanup":
        for command in (
            ["systemctl", "kill", "--signal=KILL", "--kill-whom=all", UNIT],
            ["systemctl", "stop", UNIT],
            ["usermod", "-L", "mano-human"],
        ):
            subprocess.run(command, text=True, capture_output=True, timeout=20, check=False)
        for name in ("state.json", "challenge"):
            (ROOT / name).unlink(missing_ok=True)
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
            "--property=TimeoutStopSec=5",
            "/bin/sleep",
            "600",
        ]
    )
    run(["systemctl", "kill", "--signal=STOP", "--kill-whom=main", UNIT])
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
