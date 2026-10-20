"""Actual build/install/reinstall/remove witness, disposable Debian guest only."""

import hashlib
import json
import os
import pwd
import shutil
import stat
import subprocess
import sys
import time
from pathlib import Path

from ci_tty import native_terminal
from probe_live_human import run as live_human

ROOT = Path("/opt/mano-lab")
OUT = ROOT / "evidence"
CODE = Path("/usr/lib/mano-os")
VENDOR = Path("/usr/lib/mano-runtime/vendor")
POLICY = Path("/etc/mano/human.uid")


def command(*argv, timeout=60, **kwargs):
    return subprocess.run(
        argv, check=True, capture_output=True, text=True, timeout=timeout, **kwargs
    )


def installed_python(program, *, actor=None, body=None):
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
    result = command(*argv, input=json.dumps(body) if body is not None else None)
    return json.loads(result.stdout)


def query(body):
    return installed_python(
        """import json,sys
from mano_prompt.approve import rpc,view_packet
from mano_prompt.mode import read_profile_status
body=json.load(sys.stdin)
result=(read_profile_status(body['id']) if body['mode']=='permission_status'
        else rpc(view_packet(body['id'])))
print(json.dumps(result))
""",
        actor="mano-human",
        body=body,
    )


def verify_payload():
    manifest = json.loads(Path("/usr/share/doc/mano-runtime/payload-sha256.json").read_text())
    for name, digest in manifest.items():
        path = Path("/") / name
        assert path.is_file() and hashlib.sha256(path.read_bytes()).hexdigest() == digest, name
        info = path.stat()
        assert info.st_uid == info.st_gid == 0 and not info.st_mode & 0o6022, name
    for name in ("provider", "pricing", "controller", "egress"):
        path = Path("/etc/mano") / (name + ".json")
        assert json.loads(path.read_text())["enabled"] is False
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert not Path("/etc/mano/credentials/openai").exists()
    return len(manifest)


def main():
    assert os.geteuid() == 0
    assert Path("/etc/mano-lab-disposable").read_text().strip() == "mano-phase0-ci"
    assert command("systemd-detect-virt", "--vm").stdout.strip() in {"kvm", "qemu"}
    assert not CODE.exists() and not POLICY.exists()
    source = json.loads((ROOT / "source-info.json").read_text())
    metadata = []
    for directory in ("package-build-a", "package-build-b"):
        result = command(
            "/usr/bin/python3",
            str(ROOT / "scripts/build_runtime_deb.py"),
            "--wheelhouse",
            "/opt/mano-runtime-wheelhouse",
            "--output",
            "/opt/" + directory,
            "--revision",
            source["revision"],
            "--source-date-epoch",
            str(source["epoch"]),
            timeout=180,
        )
        metadata.append(json.loads(result.stdout))
    assert metadata[0]["sha256"] == metadata[1]["sha256"], metadata
    package = Path(metadata[0]["package"])
    assert package.stat().st_size < 64_000_000
    # Prove the installed runtime cannot fall back to the old lab environment/dependencies.
    if Path("/usr/local/lib/mano-core").exists():
        Path("/usr/local/lib/mano-core").rename("/usr/local/lib/mano-core-lab-disabled")
    if VENDOR.exists():
        VENDOR.rename("/opt/mano-runtime-vendor-before-package")
    old_gui = Path("/run/mano-live-human")
    if old_gui.exists():
        assert not old_gui.is_symlink()
        assert old_gui.stat().st_uid == pwd.getpwnam("mano-human").pw_uid
        old_gui.rename("/run/mano-live-human-before-package")
    tasks = []
    password = None
    installed = False
    try:
        command("dpkg", "--install", str(package))
        installed = True
        payload_count = verify_payload()
        no_terminal = subprocess.run(
            ["/usr/sbin/mano-package-recovery", "create"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert no_terminal.returncode != 0 and "Root controlling terminal" in no_terminal.stderr
        recovery_code, recovery_output = native_terminal("mano_runtime.recovery", ("create",))
        assert recovery_code == 0, recovery_output[-4096:]
        recovery_rows = [
            json.loads(line)
            for line in recovery_output.decode().splitlines()
            if line.startswith("{")
        ]
        assert len(recovery_rows) == 1
        packaged_recovery = recovery_rows[0]
        assert packaged_recovery["snapshot_read_only"] is True
        assert packaged_recovery["package_install_authorized"] is False
        (OUT / "packaged-root-recovery.json").write_text(
            json.dumps(
                dict(
                    actual_installed_module=True,
                    native_root_tty=True,
                    non_tty_denied=True,
                    receipt=packaged_recovery,
                ),
                indent=2,
            )
            + "\n"
        )

        build = json.loads(Path("/usr/share/doc/mano-runtime/build-info.json").read_text())
        assert build["revision"] == source["revision"]
        assert build["source_date_epoch"] == source["epoch"]
        assert not POLICY.exists()
        sockets = installed_python(
            "import json;from mano_runtime.administration import SOCKETS;print(json.dumps(SOCKETS))"
        )
        for unit in (
            "mano-broker.service",
            "mano-controller.timer",
            "mano-stopd.service",
            *sockets,
        ):
            assert (
                subprocess.run(
                    ["systemctl", "is-active", "--quiet", unit], check=False, timeout=5
                ).returncode
                != 0
            )
        pipe = subprocess.run(
            ["/usr/sbin/mano-runtime-setup", "mano-human"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert pipe.returncode != 0 and not POLICY.exists()
        command(
            "/usr/bin/script",
            "--quiet",
            "--return",
            "--command",
            "/usr/sbin/mano-runtime-setup mano-human --enable",
            "/dev/null",
        )
        command("systemctl", "is-enabled", "--quiet", "mano-runtime.target")
        uid_bytes = POLICY.read_bytes()
        assert uid_bytes == (str(pwd.getpwnam("mano-human").pw_uid) + "\n").encode()
        assert stat.S_IMODE(POLICY.stat().st_mode) == 0o600
        # A different configured human must never silently replace the binding.
        refused = subprocess.run(
            [
                "/usr/bin/script",
                "--quiet",
                "--return",
                "--command",
                "/usr/sbin/mano-runtime-setup lab",
                "/dev/null",
            ],
            capture_output=True,
            text=True,
            timeout=15,
        )
        assert refused.returncode != 0 and POLICY.read_bytes() == uid_bytes
        command(
            "/usr/sbin/runuser",
            "-u",
            "mano-human",
            "--",
            "env",
            "-i",
            "PATH=/usr/bin:/bin",
            "/usr/bin/mano-prompt",
            "--help",
        )
        import secrets

        password = secrets.token_hex(24)
        command("chpasswd", input="mano-human:" + password + "\n")
        live = live_human(
            native_terminal,
            password,
            tasks.append,
            query,
            config_path=Path("/usr/share/mano-runtime/human-sway.conf"),
        )
        prompt = live["prompt"]["id"]
        managed = installed_python(
            """import json,sys
from mano_broker.task_factory import control_request,human_uid
print(json.dumps(control_request('prompt_context',dict(prompt_id=json.load(sys.stdin),
                                                     human_uid=human_uid()))['managed']))
""",
            body=prompt,
        )
        plan = dict(
            prompt_id=prompt,
            plan=dict(
                args=dict(
                    argv=[
                        "/usr/bin/python3",
                        "-c",
                        "from pathlib import Path;"
                        "Path('/workspace/package-proof').write_text('package-ok')",
                    ],
                    cwd=".",
                    timeout_seconds=2,
                ),
                reason="Explicit CI mock package execution witness",
            ),
        )
        deadline = time.monotonic() + 30
        while True:
            step = command("/usr/sbin/mano-core-step", "--mock", input=json.dumps(plan))
            task = json.loads(step.stdout)["task"]
            if task["status"] == "verifying":
                break
            assert task["status"] in {"queued", "running"} and time.monotonic() < deadline, task
            time.sleep(0.1)
        proof = Path(managed["workspace"]) / "package-proof"
        assert proof.read_text() == "package-ok"
        assert task["task_id"] == live["prompt"]["task_id"]
        edited = Path("/etc/mano/controller.json")
        edited.write_text(json.dumps(json.loads(edited.read_text()), indent=2) + "\n")
        before_uid = POLICY.read_bytes()
        before_configs = {
            name: Path("/etc/mano/" + name + ".json").read_bytes()
            for name in ("provider", "pricing", "controller", "egress")
        }
        command("dpkg", "--install", str(package))  # Real same-version reinstall/upgrade lifecycle.
        assert POLICY.read_bytes() == before_uid
        command("systemctl", "is-enabled", "--quiet", "mano-runtime.target")
        assert all(
            Path("/etc/mano/" + name + ".json").read_bytes() == data
            for name, data in before_configs.items()
        )
        assert proof.read_text() == "package-ok"
        command(
            "/usr/bin/script",
            "--quiet",
            "--return",
            "--command",
            "/usr/sbin/mano-runtime-setup mano-human --start",
            "/dev/null",
        )
        assert query(dict(mode="permission_status", id=prompt))["profile"]["automatic"] is False
        assert Path("/var/lib/mano-stopd/state").read_text().endswith(":latched\n")
        command("dpkg", "--remove", "mano-runtime")
        installed = False
        assert not CODE.exists() and not Path("/usr/libexec/mano-stop").exists()
        assert not Path("/etc/systemd/system/multi-user.target.wants/mano-runtime.target").exists()
        assert POLICY.read_bytes() == before_uid and proof.read_text() == "package-ok"
        for unit in ("mano-broker.service", "mano-controller.timer", "mano-stopd.service"):
            assert (
                subprocess.run(
                    ["systemctl", "is-active", "--quiet", unit], check=False, timeout=5
                ).returncode
                != 0
            )
        shutil.copyfile(package, OUT / package.name)
        report = dict(
            schema_version="1.0",
            package=dict(
                name=package.name,
                sha256=metadata[0]["sha256"],
                bytes=package.stat().st_size,
                build=build,
            ),
            reproducible_two_builds=True,
            reproducibility_scope="same guest source/wheels/toolchain; "
            "independent staging directories",
            verified_installed_payload_files=payload_count,
            services_inactive_on_install=True,
            no_key_and_disabled_defaults=True,
            explicit_enable_preserved_on_reinstall_removed_on_uninstall=True,
            root_tty_enrollment_and_conflicting_binding_denial=True,
            package_owned_production_gui_pam_profile=True,
            package_owned_langgraph_mock_effect=True,
            package_owned_root_recovery_snapshot=True,
            effect_verified=False,
            policy_data_preserved_on_reinstall=True,
            reinstall_no_old_authority=True,
            package_removed_services_stopped_data_preserved=True,
            old_lab_environment_disabled=True,
            physical_input_provenance=None,
            paid_model_execution=False,
            signed=False,
        )
        (OUT / "runtime-package.json").write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps(report))
    finally:
        if installed:
            subprocess.run(
                ["dpkg", "--remove", "mano-runtime"],
                capture_output=True,
                text=True,
                check=False,
                timeout=60,
            )
        if password is not None:
            subprocess.run(["usermod", "--lock", "mano-human"], check=False, capture_output=True)
        for name in tasks:
            subprocess.run(["userdel", name], check=False, capture_output=True)


if __name__ == "__main__":
    try:
        main()
    except subprocess.CalledProcessError as error:
        print((error.stdout or "")[-8000:], file=sys.stderr)
        print((error.stderr or "")[-8000:], file=sys.stderr)
        raise
