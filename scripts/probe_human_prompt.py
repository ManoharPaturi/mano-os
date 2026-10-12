#!/usr/bin/env python3
"""Disposable-VM native human surface probe. No model or approval authority."""

import json
import os
import pwd
import shutil
import subprocess
import time
from pathlib import Path

from mano_lab.resources import process_memory

ROOT = Path("/opt/mano-lab")
OUT = ROOT / "evidence"
RUNTIME = Path("/run/mano-human")


def human(argv):
    return [
        "/usr/sbin/runuser",
        "-u",
        "mano-human",
        "--",
        "env",
        "-i",
        "PATH=/usr/bin:/bin",
        "HOME=/home/mano-human",
        "LANG=C.UTF-8",
        "PYTHONPATH=/opt/mano-lab/src",
        "XDG_RUNTIME_DIR=/run/mano-human",
        *argv,
    ]


def walk(node):
    yield node
    for child in node.get("nodes", []) + node.get("floating_nodes", []):
        yield from walk(child)


def main():
    if os.getuid() != 0 or Path("/etc/mano-lab-disposable").read_text().strip() != "mano-phase0-ci":
        raise RuntimeError("Disposable guest root required")
    if subprocess.check_output(["systemd-detect-virt", "--vm"], text=True).strip() not in {
        "kvm",
        "qemu",
    }:
        raise RuntimeError("QEMU guest required")
    if list(RUNTIME.glob("sway-ipc.*.sock")):
        raise RuntimeError("Refusing an existing human session")
    started = time.monotonic()
    log = (OUT / "human-sway.txt").open("w")
    proc = subprocess.Popen(
        [
            "/usr/bin/unshare",
            "--net",
            *human(
                [
                    "WLR_BACKENDS=headless",
                    "WLR_RENDERER=pixman",
                    "WLR_HEADLESS_OUTPUTS=1",
                    "GSK_RENDERER=cairo",
                    "GDK_BACKEND=wayland",
                    "GTK_A11Y=atspi",
                    "dbus-run-session",
                    "--",
                    "sway",
                    "-c",
                    str(ROOT / "packaging/sway/human.conf"),
                ]
            ),
        ],
        stdout=log,
        stderr=log,
    )
    ipc = None
    try:
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            matches = list(RUNTIME.glob("sway-ipc.*.sock"))
            if matches:
                ipc = str(matches[0])
                break
            if proc.poll() is not None:
                raise RuntimeError("Human compositor exited")
            time.sleep(0.1)
        if not ipc:
            raise RuntimeError("Human compositor IPC absent")

        def sway(*argv):
            result = subprocess.run(
                human([f"SWAYSOCK={ipc}", "swaymsg", "-r", *argv]),
                text=True,
                capture_output=True,
                timeout=20,
                check=True,
            )
            return json.loads(result.stdout)

        while time.monotonic() < deadline:
            tree = sway("-t", "get_tree")
            windows = [n for n in walk(tree) if n.get("app_id")]
            if windows:
                assert len(windows) == 1 and windows[0]["app_id"] == "org.mano.Prompt"
                break
            time.sleep(0.1)
        else:
            raise RuntimeError("Default native prompt window absent")
        prompt = windows[0]
        assert prompt["visible"] and prompt["fullscreen_mode"] == 1
        assert Path(f"/proc/{prompt['pid']}").stat().st_uid == pwd.getpwnam("mano-human").pw_uid
        sway(
            "exec /usr/bin/python3 /opt/mano-lab/tests/desktop/prompt_contract.py "
            "> /run/mano-human/prompt-driver.txt 2>&1"
        )
        deadline = time.monotonic() + 40
        while not (RUNTIME / "prompt-test.json").is_file():
            if time.monotonic() > deadline:
                raise RuntimeError("Native prompt semantic input test timed out")
            time.sleep(0.1)
        test = json.loads((RUNTIME / "prompt-test.json").read_text())
        assert test["request"]["text"] == "Show system status"
        image = subprocess.run(
            human(["WAYLAND_DISPLAY=wayland-1", "grim", str(RUNTIME / "prompt.png")]),
            text=True,
            capture_output=True,
            timeout=20,
            check=True,
        )
        assert image.returncode == 0
        shutil.copyfile(RUNTIME / "prompt.png", OUT / "human-prompt.png")
        sway_pid = int(
            subprocess.check_output(["pgrep", "-u", "mano-human", "-x", "sway"], text=True).strip()
        )
        report = {
            "input": test,
            "window": prompt,
            "session_backend": "CI headless Wayland",
            "launch_to_verified_request_seconds": time.monotonic() - started,
            "human_compositor_memory_bytes": process_memory(sway_pid),
            "prompt_memory_bytes": process_memory(prompt["pid"]),
            "physical_display_verified": False,
            "approval_service_verified": False,
        }
        (OUT / "human-prompt.json").write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps(report, indent=2))
    finally:
        if (RUNTIME / "prompt-driver.txt").is_file():
            shutil.copyfile(RUNTIME / "prompt-driver.txt", OUT / "prompt-driver.txt")
        if ipc and proc.poll() is None:
            subprocess.run(
                human([f"SWAYSOCK={ipc}", "swaymsg", "exit"]),
                capture_output=True,
                timeout=10,
                check=False,
            )
        if proc.poll() is None:
            proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
        log.close()


if __name__ == "__main__":
    main()
