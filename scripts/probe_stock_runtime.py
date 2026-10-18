"""Clean-image install and real reboot witness. No product source is copied to this VM."""

import argparse
import hashlib
import json
import os
import pwd
import secrets
import sqlite3
import stat
import subprocess
import sys
import time
from pathlib import Path

from ci_tty import native_terminal

ROOT = Path("/opt/mano-lab")
OUT = ROOT / "evidence"
RUNTIME = Path("/run/mano-stock-human")
PRIVATE = Path("/root/mano-stock-private.json")
ACTOR = "lab"


def command(*argv, timeout=40, **kwargs):
    return subprocess.run(
        argv, check=True, capture_output=True, text=True, timeout=timeout, **kwargs
    )


def guard():
    assert os.geteuid() == 0
    assert Path("/etc/mano-lab-disposable").read_text().strip() == "mano-phase0-ci"
    assert command("systemd-detect-virt", "--vm").stdout.strip() in {"kvm", "qemu"}
    assert not (ROOT / "src").exists() and not Path("/usr/local/lib/mano-core").exists()


def python(program, body=None, actor=None):
    argv = [
        "env",
        "-i",
        "PATH=/usr/sbin:/usr/bin:/bin",
        "LANG=C.UTF-8",
        "PYTHONDONTWRITEBYTECODE=1",
        "PYTHONPATH=/usr/lib/mano-os:/usr/lib/mano-runtime/vendor",
        "/usr/bin/python3",
        "-P",
        "-c",
        program,
    ]
    if actor:
        argv = ["/usr/sbin/runuser", "-u", actor, "--", *argv]
    return json.loads(command(*argv, input=json.dumps(body)).stdout)


def public(operation, body, actor):
    return python(
        """import json,sys
from mano_core.broker import BrokerClient
value=json.load(sys.stdin);client=BrokerClient()
try:print(json.dumps(client(value)))
finally:client.close()
""",
        dict(schema_version="1.0", operation=operation, body=body),
        actor,
    )


def query(mode, identifier):
    return python(
        """import json,sys
from mano_prompt.approve import rpc,view_packet
from mano_prompt.mode import read_profile_status
mode,identifier=json.load(sys.stdin)
try:result=(read_profile_status(identifier) if mode=='status' else rpc(view_packet(identifier)))
except (PermissionError,ValueError):result={'denied':True}
print(json.dumps(result))
""",
        [mode, identifier],
        ACTOR,
    )


def wait(check, timeout=30):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = check()
        if value:
            return value
        time.sleep(0.1)
    raise AssertionError("Fresh Debian workflow stage timed out")


def baseline():
    assert not Path("/usr/lib/mano-os").exists() and not Path("/etc/mano").exists()
    assert not Path("/usr/lib/mano-runtime").exists()
    assert not any(account.pw_name.startswith("mano-") for account in pwd.getpwall())
    os_release = Path("/etc/os-release").read_text()
    assert "ID=debian" in os_release and 'VERSION_ID="13"' in os_release
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "stock-before-packages.tsv").write_text(command("dpkg-query", "-W").stdout)
    value = dict(
        boot_id=Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
        no_mano_accounts_config_code_or_dependencies=True,
        no_product_source_tree=True,
        human_name=ACTOR,
        human_uid=pwd.getpwnam(ACTOR).pw_uid,
    )
    assert value["human_uid"] >= 1000
    (OUT / "stock-baseline.json").write_text(json.dumps(value, indent=2) + "\n")


def gui(password, label):
    account = pwd.getpwnam(ACTOR)
    try:
        pwd.getpwnam("mano-human")
    except KeyError:
        pass
    else:
        raise AssertionError("This fresh test must not depend on a mano-human login account")
    RUNTIME.mkdir(mode=0o700)
    os.chown(RUNTIME, account.pw_uid, account.pw_gid)

    def human(*arguments):
        return [
            "/usr/sbin/runuser",
            "-u",
            ACTOR,
            "--",
            "env",
            "-i",
            "PATH=/usr/bin:/bin",
            "HOME=" + account.pw_dir,
            "LANG=C.UTF-8",
            "XDG_RUNTIME_DIR=" + str(RUNTIME),
            *arguments,
        ]

    log = (OUT / ("stock-sway-" + label + ".txt")).open("w")
    proc = subprocess.Popen(
        [
            "/usr/bin/unshare",
            "--net",
            *human(
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
                "/usr/share/mano-runtime/human-sway.conf",
            ),
        ],
        stdout=log,
        stderr=log,
    )
    ipc = None
    duration = 900 if label == "before" else 120
    try:
        ipc = wait(lambda: next(RUNTIME.glob("sway-ipc.*.sock"), None))
        command(
            *human(
                "SWAYSOCK=" + str(ipc),
                "swaymsg",
                "exec /usr/bin/python3 /opt/mano-lab/tests/desktop/stock_prompt_contract.py "
                + "--duration "
                + str(duration)
                + " > /run/mano-stock-human/driver.txt 2>&1",
            )
        )
        wait(lambda: (RUNTIME / "received.json").exists())
        receipt = json.loads((RUNTIME / "received.json").read_text())
        factory = command(
            "/usr/sbin/mano-task", input=json.dumps(dict(prompt_id=receipt["prompt_id"]))
        )
        managed = json.loads(factory.stdout)["task"]
        assert managed["prompt_id"] == receipt["prompt_id"]
        assert managed["context"]["prompt"] == "Clean Debian runtime reboot witness"
        (RUNTIME / "provisioned").touch()
        wait(lambda: (RUNTIME / "pending.json").exists())
        pending = json.loads((RUNTIME / "pending.json").read_text())
        assert pending["task_id"] == managed["context"]["task_id"]
        view = query("view", pending["approval_id"])["view"]
        assert view["human_uid"] == account.pw_uid and view["task_id"] == pending["task_id"]
        assert view["args"] == dict(
            mode="auto", duration_seconds=duration, max_actions=3, max_timeout_seconds=10
        )
        for answer, credential in (("n", None), ("y", "wrong-stock-ci"), ("y", password)):
            answers = ((b"Approve this exact operation?", answer),)
            if credential is not None:
                answers += ((b"OS authentication password:", credential),)
            code, output = native_terminal(
                "mano_prompt.approve", (pending["approval_id"],), actor=ACTOR, answers=answers
            )
            if credential == password:
                assert code == 0 and b"Approval recorded:" in output
            else:
                assert code == (0 if answer == "n" else 1)
                assert query("status", receipt["prompt_id"])["profile"]["automatic"] is False
            if credential:
                assert credential.encode() not in output
        (RUNTIME / "approved").touch()
        wait(lambda: (RUNTIME / "result.json").exists())
        result = json.loads((RUNTIME / "result.json").read_text())
        assert result["unmodified_packaged_prompt"] and not result["app_observer_injected"]
        effective = query("status", receipt["prompt_id"])["profile"]
        assert effective["automatic"] and effective["remaining_actions"] == 3
        assert effective["mode"] == "auto" and 0 < effective["seconds_remaining"] <= duration
        result["native_effective_status"] = effective
        result["artifact_sha256"] = {}
        for name in ("stock-permissions-pending.png", "stock-permissions-effective.png"):
            data = (RUNTIME / name).read_bytes()
            target = label + "-" + name
            (OUT / target).write_bytes(data)
            result["artifact_sha256"][target] = hashlib.sha256(data).hexdigest()
        (OUT / ("stock-gui-" + label + ".json")).write_text(json.dumps(result, indent=2) + "\n")
        return managed, result
    finally:
        if ipc is not None and proc.poll() is None:
            subprocess.run(
                human("SWAYSOCK=" + str(ipc), "swaymsg", "exit"),
                check=False,
                capture_output=True,
                timeout=10,
            )
        if proc.poll() is None:
            proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
        log.close()
        if (RUNTIME / "driver.txt").exists():
            text = (RUNTIME / "driver.txt").read_text()
            (OUT / ("stock-driver-" + label + ".txt")).write_text(text)
            if text:
                print(text, file=sys.stderr)


def mock_effect(managed, filename):
    packet = dict(
        prompt_id=managed["prompt_id"],
        plan=dict(
            args=dict(
                argv=[
                    "/usr/bin/python3",
                    "-c",
                    "from pathlib import Path;"
                    + "Path('/workspace/"
                    + filename
                    + "').write_text('stock-ok')",
                ],
                cwd=".",
                timeout_seconds=2,
            ),
            reason="Explicit fresh Debian mock witness",
        ),
    )
    deadline = time.monotonic() + 30
    while True:
        result = json.loads(
            command("/usr/sbin/mano-core-step", "--mock", input=json.dumps(packet)).stdout
        )["task"]
        if result["status"] == "verifying":
            break
        assert result["status"] in {"queued", "running"} and time.monotonic() < deadline, result
        time.sleep(0.1)
    assert (Path(managed["workspace"]) / filename).read_text() == "stock-ok"
    return result


def phase(after_reboot):
    original = json.loads((OUT / "stock-baseline.json").read_text())
    boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    assert original["human_uid"] == pwd.getpwnam(ACTOR).pw_uid
    assert Path("/etc/mano/human.uid").read_text() == str(original["human_uid"]) + "\n"
    command("systemctl", "is-enabled", "--quiet", "mano-runtime.target")
    for unit in ("mano-runtime.target", "mano-stopd.service"):
        wait(
            lambda unit=unit: subprocess.run(
                ["systemctl", "is-active", "--quiet", unit], check=False, timeout=5
            ).returncode
            == 0
        )
    for name in ("provider", "pricing", "controller", "egress"):
        assert json.loads(Path("/etc/mano/" + name + ".json").read_text())["enabled"] is False
    assert not Path("/etc/mano/credentials/openai").exists()
    if after_reboot:
        assert boot != original["boot_id"]
        info = PRIVATE.stat()
        assert info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o600
        previous = json.loads(PRIVATE.read_text())
        assert query("status", previous["managed"]["prompt_id"]) == dict(denied=True)
        replay = public(
            "propose",
            previous["proposal"] | {"grant_id": previous["grant_id"]},
            previous["managed"]["caller_name"],
        )
        assert replay["ok"] is False
        with sqlite3.connect(
            "file:/var/lib/mano-broker/runtime/state.sqlite3?mode=ro", uri=True
        ) as database:
            row = database.execute(
                "SELECT expires,revoked,used FROM grants WHERE id=?", (previous["grant_id"],)
            ).fetchone()
        assert row[0] > time.monotonic() and row[1:] == (1, 0)
        assert (Path(previous["managed"]["workspace"]) / "before-reboot").read_text() == "stock-ok"
    else:
        assert boot == original["boot_id"] and not PRIVATE.exists()
    password = secrets.token_hex(24)
    command("chpasswd", input=ACTOR + ":" + password + "\n")
    try:
        managed, result = gui(password, "after" if after_reboot else "before")
        mock_effect(managed, "after-reboot" if after_reboot else "before-reboot")
        if not after_reboot:
            proposal = dict(
                schema_version="1.0",
                task_id=managed["context"]["task_id"],
                resource_id=managed["context"]["resource_id"],
                capability="files.read",
                args=dict(path="before-reboot"),
                idempotency_key="unused-before-real-reboot",
                reason="Synthetic unused exact grant before real boot change",
            )
            approved = public("request_approval", proposal, managed["caller_name"])["approval"]
            assert approved["state"] == "approved"
            with sqlite3.connect(
                "file:/var/lib/mano-broker/runtime/state.sqlite3?mode=ro", uri=True
            ) as database:
                row = database.execute(
                    "SELECT expires,revoked,used FROM grants WHERE id=?", (approved["grant_id"],)
                ).fetchone()
            assert row[0] > time.monotonic() and row[1:] == (0, 0)
            fd = os.open(PRIVATE, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
            with os.fdopen(fd, "w") as stream:
                json.dump(
                    dict(managed=managed, proposal=proposal, grant_id=approved["grant_id"]), stream
                )
                stream.flush()
                os.fsync(stream.fileno())
        else:
            stopped = command("/usr/sbin/runuser", "-u", ACTOR, "--", "/usr/libexec/mano-stop")
            assert "Emergency Stop acknowledged" in stopped.stdout
            assert Path("/var/lib/mano-stopd/state").read_text().endswith(":latched\n")
            report = dict(
                schema_version="1.0",
                boot_id_before=original["boot_id"],
                boot_id_after=boot,
                pristine_baseline=original,
                runtime_started_on_boot_without_setup=True,
                generic_login_without_mano_human_account=True,
                unmodified_packaged_gui_before_and_after_boot=True,
                app_observer_injected=False,
                native_pam_before_and_after_boot=True,
                package_owned_mock_effect_before_and_after_boot=True,
                effect_verified=False,
                unexpired_unused_old_grant_revoked_after_real_boot=True,
                old_grant_replay_denied=True,
                previous_workspace_data_preserved=True,
                configured_human_native_stop=True,
                defaults_disabled_no_key=True,
                external_source_tree_or_lab_environment_copied=False,
                paid_model_execution=False,
                physical_input_provenance=None,
                gui_start_mode="manual headless user session; no physical/display-manager test",
            )
            (OUT / "stock-runtime-reboot.json").write_text(json.dumps(report, indent=2) + "\n")
            print(json.dumps(report))
    finally:
        command("usermod", "--lock", ACTOR)


def main():
    guard()
    parser = argparse.ArgumentParser()
    parser.add_argument("phase", choices=("baseline", "before", "after"))
    args = parser.parse_args()
    if args.phase == "baseline":
        baseline()
    else:
        phase(args.phase == "after")


if __name__ == "__main__":
    try:
        main()
    except subprocess.CalledProcessError as error:
        print((error.stdout or "")[-8000:], file=sys.stderr)
        print((error.stderr or "")[-8000:], file=sys.stderr)
        raise
