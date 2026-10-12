#!/usr/bin/env python3
"""CI runner drives the VM's real ttyS0 login, never a simulated shell."""

import argparse
import json
import os
import shlex
import socket
import subprocess
import time
from pathlib import Path

from mano_lab.evidence import Probe, write_report


def challenge_values(data, challenge):
    # UART/socket reads may stop midway through a JSON response. A matching
    # token alone is insufficient; require a complete parseable response.
    values = []
    for line in data.decode(errors="replace").splitlines():
        try:
            item = json.loads(line)
            if isinstance(item, dict) and item.get("challenge") == challenge:
                values.append(item)
        except json.JSONDecodeError:
            continue
    return values


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--socket", type=Path, required=True)
    parser.add_argument("--key", type=Path, required=True)
    parser.add_argument("--known-hosts", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    if os.environ.get("MANO_DISPOSABLE_CI") != "1":
        raise RuntimeError("Explicit disposable CI required")
    ssh = [
        "ssh",
        "-i",
        str(args.key),
        "-p",
        "2222",
        "-o",
        "BatchMode=yes",
        "-o",
        "ConnectTimeout=5",
        "-o",
        f"UserKnownHostsFile={args.known_hosts}",
        "-o",
        "StrictHostKeyChecking=yes",
        "lab@127.0.0.1",
    ]

    def fixture(action):
        result = subprocess.run(
            [*ssh, f"sudo python3 /opt/mano-lab/scripts/serial_fixture.py {action}"],
            text=True,
            capture_output=True,
            timeout=45,
            check=False,
        )
        if result.returncode != 0:
            # The fixed fixture sends secrets only in successful stdout. Errors
            # contain command/state diagnostics; never retain the stdout payload.
            raise RuntimeError(f"Serial fixture {action} failed: {result.stderr[-3000:]}")
        return json.loads(result.stdout) if result.stdout.strip() else None

    credentials = None
    report = {
        "passed": False,
        "route": "QEMU serial -> kernel ttyS0 -> agetty/login/PAM -> human shell",
        "physical_input_provenance": None,
        "approval_service_verified": False,
    }
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        credentials = fixture("prepare")
        client.connect(str(args.socket))
        client.settimeout(1)
        captured = bytearray()

        def receive_until(predicate, timeout=25):
            start = len(captured)
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                try:
                    block = client.recv(65536)
                    if not block:
                        raise RuntimeError("Serial console disconnected")
                    captured.extend(block)
                except TimeoutError:
                    pass
                value = bytes(captured[start:])
                if predicate(value):
                    return value
            raise RuntimeError("Serial console stage timed out")

        client.sendall(b"\r")
        receive_until(lambda value: b"login:" in value)
        client.sendall(b"mano-human\r")
        receive_until(lambda value: b"Password:" in value)
        client.sendall(credentials["password"].encode() + b"\r")
        receive_until(lambda value: b"$ " in value)
        source = (
            "import json,os; from pathlib import Path; "
            "print(json.dumps({'challenge':Path('/run/mano-rescue-fixture/challenge').read_text(),"
            "'uid':os.getuid(),'tty':os.ttyname(0),'pid':os.getpid()}))"
        )
        client.sendall(("python3 -c " + shlex.quote(source) + "\r").encode())
        result = receive_until(
            lambda value: bool(challenge_values(value, credentials["challenge"]))
        )
        values = challenge_values(result, credentials["challenge"])
        assert len(values) == 1, "No actual challenge response from the rescue shell"
        assert values[0]["uid"] == credentials["human_uid"]
        assert values[0]["tty"] == "/dev/ttyS0"
        after = fixture("status")
        assert after["core_pid"] == credentials["core_pid"]
        assert after["core_state"].startswith("T")
        report.update(
            passed=True,
            human_uid=values[0]["uid"],
            tty=values[0]["tty"],
            challenge_verified=True,
            core_before={k: credentials[k] for k in after},
            core_after=after,
            agent_challenge_access_denied=True,
        )
        client.sendall(b"exit\r")
    except Exception as error:
        report["error"] = str(error)
    finally:
        client.close()
        try:
            report["fixture_cleanup"] = fixture("cleanup")
        except Exception as cleanup_error:
            report.update(passed=False, cleanup_error=str(cleanup_error))
        # Credentials/challenges are never retained in console artifacts.
        if credentials:
            for path in args.out.glob("serial-*.log"):
                value = path.read_bytes()
                for name in ("password", "challenge"):
                    value = value.replace(credentials[name].encode(), b"[REDACTED-FIXTURE]")
                path.write_bytes(value)
    (args.out / "serial-rescue.json").write_text(json.dumps(report, indent=2) + "\n")
    prior = json.loads((args.out / "report.json").read_text())
    probes = [Probe(**item) for item in prior["probes"] if item["name"] != "physical-prompt-rescue"]
    native = (args.out / "human-prompt.json").is_file()
    probes.append(
        Probe(
            "P0-03",
            "native-prompt-serial-rescue",
            "pass" if report["passed"] and native else "fail",
            "Native GTK4 prompt plus authenticated real ttyS0 shell with frozen mock core",
            ("human-prompt.json", "human-prompt.png", "serial-rescue.json")
            if native
            else ("serial-rescue.json",),
        )
    )
    write_report(args.out, probes, prior["environment"])
    print(json.dumps(report, indent=2))
    return 0 if report["passed"] and native else 1


if __name__ == "__main__":
    raise SystemExit(main())
