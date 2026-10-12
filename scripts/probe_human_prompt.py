#!/usr/bin/env python3
"""Disposable-VM native human surface probe. No model or approval authority."""

import json
import os
import pwd
import select
import shutil
import subprocess
import time
from contextlib import contextmanager
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


class HumanWitness:
    def __init__(self, report, sway, ipc, prompt, sway_pid):
        self.report, self.sway, self.ipc = report, sway, ipc
        self.prompt, self.sway_pid = prompt, sway_pid
        self.checkpoints = []

    def checkpoint(self, label):
        windows = [node for node in walk(self.sway("-t", "get_tree")) if node.get("app_id")]
        assert len(windows) == 1 and windows[0]["id"] == self.prompt["id"]
        assert windows[0]["pid"] == self.prompt["pid"] and windows[0]["focused"]
        assert windows[0]["app_id"] == "org.mano.Prompt"
        self.checkpoints.append({"label": label, "window": windows[0]})

    def capture(self, name):
        # Capture outside the GTK main loop, after the client can paint/commit.
        result = subprocess.run(
            human(["WAYLAND_DISPLAY=wayland-1", "grim", str(RUNTIME / name)]),
            capture_output=True,
            text=True,
            timeout=20,
            check=True,
        )
        assert result.returncode == 0
        shutil.copyfile(RUNTIME / name, OUT / name)

    def start_monitor(self):
        self.checkpoint("before-agent")
        (RUNTIME / "focus-arm").touch()
        deadline = time.monotonic() + 30
        while not (RUNTIME / "focus-ready.json").is_file():
            if time.monotonic() > deadline:
                raise RuntimeError("Human focus monitor not ready")
            time.sleep(0.1)
        time.sleep(0.2)
        self.capture("focus-before.png")

    def finish_monitor(self):
        self.checkpoint("after-agent")
        (RUNTIME / "focus-stop").touch()
        deadline = time.monotonic() + 15
        while not (RUNTIME / "focus-report.json").is_file():
            if time.monotonic() > deadline:
                raise RuntimeError("Human focus monitor did not finish")
            time.sleep(0.1)
        self.capture("focus-after.png")
        report = json.loads((RUNTIME / "focus-report.json").read_text())
        report["compositor_checkpoints"] = self.checkpoints
        (OUT / "cross-session-focus.json").write_text(json.dumps(report, indent=2) + "\n")
        for name in ("focus-driver.txt", "focus-before.png", "focus-after.png"):
            if (RUNTIME / name).is_file():
                shutil.copyfile(RUNTIME / name, OUT / name)
        assert report["passed"], report
        return report


@contextmanager
def human_session():
    if os.getuid() != 0 or Path("/etc/mano-lab-disposable").read_text().strip() != "mano-phase0-ci":
        raise RuntimeError("Disposable guest root required")
    if subprocess.check_output(["systemd-detect-virt", "--vm"], text=True).strip() not in {
        "kvm",
        "qemu",
    }:
        raise RuntimeError("QEMU guest required")
    if list(RUNTIME.glob("sway-ipc.*.sock")):
        raise RuntimeError("Refusing an existing human session")
    config = RUNTIME / "human-test.conf"
    config.write_text(
        (ROOT / "packaging/sway/human.conf")
        .read_text()
        .replace(
            "/usr/bin/python3 -m mano_prompt",
            "/usr/bin/python3 /opt/mano-lab/tests/desktop/prompt_witness.py "
            "> /run/mano-human/focus-driver.txt 2>&1",
        )
    )
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
                    str(config),
                ]
            ),
        ],
        stdout=log,
        stderr=log,
    )
    ipc = None
    keyboard = None
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

        keyboard = subprocess.Popen(
            human(
                ["WAYLAND_DISPLAY=wayland-1", "/usr/local/bin/mano-wayland-probe", "keyboard-hold"]
            ),
            text=True,
            stdout=subprocess.PIPE,
            stderr=log,
        )
        ready = select.poll()
        ready.register(keyboard.stdout, select.POLLIN | select.POLLHUP)
        if not ready.poll(10000) or keyboard.stdout.readline().strip() != "READY":
            raise RuntimeError("Human fixture keyboard did not become ready")
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
        yield HumanWitness(report, sway, ipc, prompt, sway_pid)
    finally:
        if keyboard is not None:
            keyboard.terminate()
            try:
                keyboard.wait(timeout=5)
            except subprocess.TimeoutExpired:
                keyboard.kill()
                keyboard.wait()
        for name in ("focus-driver.txt", "focus-report.json"):
            if (RUNTIME / name).is_file():
                shutil.copyfile(RUNTIME / name, OUT / name)
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
    with human_session() as witness:
        print(json.dumps(witness.report, indent=2))
