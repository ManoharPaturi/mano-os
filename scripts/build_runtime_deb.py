#!/usr/bin/env python3
"""Build an offline Debian13/amd64 runtime package. Never installs or starts it."""

import argparse
import base64
import csv
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VERSION = "0.1.0~prototype1"
VENDOR = "/usr/lib/mano-runtime/vendor"


def run(*argv, **kwargs):
    return subprocess.check_output(argv, text=True, **kwargs).strip()


def build(wheelhouse, output, *, revision=None, epoch=None):
    release = platform.freedesktop_os_release() if sys.platform == "linux" else {}
    if (
        release.get("ID") != "debian"
        or release.get("VERSION_ID") != "13"
        or sys.platform != "linux"
        or sys.version_info[:2] != (3, 13)
        or platform.machine() != "x86_64"
        or run("dpkg", "--print-architecture") != "amd64"
    ):
        raise ValueError("Build in Debian13 amd64 with Python3.13")
    if not wheelhouse.is_dir():
        raise ValueError("Provide an existing hash-locked binary wheelhouse")
    if (revision is None) != (epoch is None):
        raise ValueError("Provide both source revision and epoch, or neither")
    if revision is None:
        revision = run("git", "rev-parse", "HEAD", cwd=ROOT)
        epoch = int(run("git", "show", "-s", "--format=%ct", "HEAD", cwd=ROOT))
    if not re.fullmatch("[0-9a-f]{40}", revision) or not 1 <= epoch < 2**63:
        raise ValueError("Invalid build source metadata")
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="mano-runtime-build-") as temporary:
        stage = Path(temporary) / "root"
        stage.mkdir()

        def copy(source, destination, mode=0o444):
            path = stage / destination.lstrip("/")
            path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, path)
            path.chmod(mode)
            return path

        for package in (ROOT / "src").glob("mano_*"):
            for source in package.rglob("*.py"):
                copy(source, "/usr/lib/mano-os/" + str(source.relative_to(ROOT / "src")))
        binaries = {
            "mano_approve.c": ("/usr/libexec/mano-approve", ["json-c", "libsystemd"], ["-lpam"]),
            "mano_stopd.c": ("/usr/libexec/mano-stopd", ["libsystemd"], []),
            "mano_stop.c": ("/usr/libexec/mano-stop", [], []),
            "mano_sandbox_guard.c": ("/usr/libexec/mano-sandbox-guard", [], ["-lseccomp"]),
            "mano_resources.c": (
                "/usr/lib/mano-broker/libmano-resources.so",
                [],
                ["-fPIC", "-shared"],
            ),
        }
        for source, (destination, packages, extra) in binaries.items():
            path = stage / destination.lstrip("/")
            path.parent.mkdir(parents=True, exist_ok=True)
            flags = run("pkg-config", "--cflags", "--libs", *packages).split() if packages else []
            run(
                "cc",
                "-std=c11",
                "-O2",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-fstack-protector-strong",
                "-D_FORTIFY_SOURCE=2",
                "-ffile-prefix-map=" + str(ROOT) + "=/usr/src/mano-runtime",
                str(ROOT / "native" / source),
                *flags,
                *extra,
                "-Wl,-z,relro,-z,now",
                "-o",
                str(path),
            )
            path.chmod(0o644 if source == "mano_resources.c" else 0o555)
        vendor = stage / VENDOR.lstrip("/")
        vendor.mkdir(parents=True)
        run(
            sys.executable,
            "-m",
            "pip",
            "install",
            "--no-index",
            "--no-deps",
            "--no-compile",
            "--only-binary=:all:",
            "--require-hashes",
            "--find-links",
            str(wheelhouse.resolve()),
            "--target",
            str(vendor),
            "-r",
            str(ROOT / "packaging/runtime/requirements.lock"),
        )
        shutil.rmtree(vendor / "bin", ignore_errors=True)  # No dependency CLI entrypoints shipped.
        for direct in vendor.glob("*.dist-info/direct_url.json"):
            direct.unlink()  # Build-local wheelhouse paths are not runtime metadata.
        for record in vendor.glob("*.dist-info/RECORD"):
            rows = []
            with record.open(newline="") as stream:
                for row in csv.reader(stream):
                    path = (vendor / row[0]).resolve()
                    if not path.is_relative_to(vendor) or not path.is_file():
                        continue
                    if path == record:
                        rows.append([row[0], "", ""])
                    else:
                        data = path.read_bytes()
                        digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest())
                        rows.append(
                            [row[0], "sha256=" + digest.decode().rstrip("="), str(len(data))]
                        )
            with record.open("w", newline="") as stream:
                csv.writer(stream, lineterminator="\n").writerows(sorted(rows))
        for unit in (ROOT / "packaging/systemd").glob("*"):
            copy(unit, "/usr/lib/systemd/system/" + unit.name)
        copy(ROOT / "packaging/runtime/sysusers.conf", "/usr/lib/sysusers.d/mano-runtime.conf")
        copy(ROOT / "packaging/runtime/tmpfiles.conf", "/usr/lib/tmpfiles.d/mano-runtime.conf")
        copy(ROOT / "packaging/pam/mano-approve", "/etc/pam.d/mano-approve", 0o644)
        human_config = copy(
            ROOT / "packaging/sway/human.conf", "/usr/share/mano-runtime/human-sway.conf"
        )
        human_config.chmod(0o644)
        human_config.write_text(
            human_config.read_text().replace(
                "/usr/bin/python3 -m mano_prompt", "/usr/bin/mano-prompt"
            )
        )
        human_config.chmod(0o444)
        copy(ROOT / "packaging/runtime/mano.desktop", "/usr/share/wayland-sessions/mano.desktop")
        for name in ("pricing", "controller", "egress"):
            copy(ROOT / "packaging/config" / (name + ".json"), "/etc/mano/" + name + ".json", 0o600)
        copy(ROOT / "packaging/runtime/provider.json", "/etc/mano/provider.json", 0o600)
        for name, module in (
            ("mano-prompt", "mano_prompt"),
            ("mano-approve", "mano_prompt.approve"),
            ("mano-mode", "mano_prompt.mode"),
            ("mano-task", "mano_broker.task_factory"),
            ("mano-core-step", "mano_broker.lifecycle"),
            ("mano-runtime-setup", "mano_runtime.administration"),
        ):
            path = (
                stage
                / (
                    "usr/sbin/"
                    if name in {"mano-task", "mano-core-step", "mano-runtime-setup"}
                    else "usr/bin/"
                )
                / name
            )
            path.parent.mkdir(parents=True, exist_ok=True)
            safe = (
                "env -i PATH=/usr/sbin:/usr/bin:/bin LANG=C.UTF-8 "
                if name in {"mano-task", "mano-core-step", "mano-runtime-setup"}
                else "env "
            )
            path.write_text(
                "#!/bin/sh\nexec " + safe + "PYTHONDONTWRITEBYTECODE=1 "
                "PYTHONPATH=/usr/lib/mano-os:"
                + VENDOR
                + " /usr/bin/python3 -P -m "
                + module
                + ' "$@"\n'
            )
            path.chmod(0o555)
        copy(
            ROOT / "packaging/runtime/requirements.lock",
            "/usr/share/doc/mano-runtime/requirements.lock",
        )
        copy(ROOT / "docs/spec-v2.1.md", "/usr/share/doc/mano-runtime/spec-v2.1.md")
        copy(ROOT / "docs/operations.md", "/usr/share/doc/mano-runtime/operations.md")
        info = stage / "usr/share/doc/mano-runtime/build-info.json"
        info.write_text(
            json.dumps(
                dict(
                    version=VERSION,
                    revision=revision,
                    source_date_epoch=epoch,
                    python=sys.version,
                    architecture="amd64",
                    provider_enabled_by_default=False,
                    shipped_api_key=False,
                    signed=False,
                ),
                indent=2,
            )
            + "\n"
        )
        # Normalize ownership through dpkg-deb and timestamps/modes here. Nothing is setuid.
        for path in stage.rglob("*"):
            if path.is_dir():
                path.chmod(0o755)
            elif str(path).startswith(str(vendor) + "/"):
                path.chmod(0o444)
            os.utime(path, (epoch, epoch), follow_symlinks=False)
        manifest = {
            str(path.relative_to(stage)): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in stage.rglob("*")
            if path.is_file()
        }
        (stage / "usr/share/doc/mano-runtime/payload-sha256.json").write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n"
        )
        control = stage / "DEBIAN"
        control.mkdir()
        (control / "control").write_text(
            "Package: mano-runtime\nVersion: " + VERSION + "\nArchitecture: amd64\n"
            "Maintainer: mano-OS project <noreply@mano.invalid>\n"
            "Section: utils\nPriority: optional\n"
            "Depends: python3 (>= 3.13), python3 (<< 3.14), python3-gi, gir1.2-gtk-4.0, "
            "systemd (>= 257), libc6 (>= 2.41), libpam0g, libjson-c5, libsystemd0, libseccomp2, "
            "bubblewrap (>= 0.12.0-1~deb13u1), xdg-dbus-proxy (>= 0.1.6-1+deb13u3), "
            "acl, passwd, util-linux, dbus-user-session, at-spi2-core, sway, foot, grim, "
            "fonts-dejavu-core\n"
            "Description: mano prototype trusted broker, prompt and isolated runtime\n"
            " Disabled cloud/controller defaults; explicit Root human enrollment required.\n"
        )
        (control / "conffiles").write_text(
            "\n".join(
                "/etc/mano/" + name + ".json"
                for name in ("provider", "pricing", "controller", "egress")
            )
            + "\n/etc/pam.d/mano-approve\n"
        )
        for name in ("preinst", "postinst", "prerm", "postrm"):
            copy(ROOT / "packaging/runtime" / name, "/DEBIAN/" + name, 0o755)
        for path in stage.rglob("*"):
            os.utime(path, (epoch, epoch), follow_symlinks=False)
        os.utime(stage, (epoch, epoch))
        destination = output / ("mano-runtime_" + VERSION + "_amd64.deb")
        run(
            "dpkg-deb",
            "--root-owner-group",
            "-Zxz",
            "--build",
            str(stage),
            str(destination),
            env=dict(os.environ, SOURCE_DATE_EPOCH=str(epoch)),
        )
        return destination


def main():
    os.umask(0o022)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wheelhouse", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--revision")
    parser.add_argument("--source-date-epoch", type=int)
    args = parser.parse_args()
    package = build(
        args.wheelhouse, args.output, revision=args.revision, epoch=args.source_date_epoch
    )
    print(
        json.dumps(
            dict(
                package=str(package.resolve()),
                bytes=package.stat().st_size,
                sha256=hashlib.sha256(package.read_bytes()).hexdigest(),
            )
        )
    )


if __name__ == "__main__":
    main()
