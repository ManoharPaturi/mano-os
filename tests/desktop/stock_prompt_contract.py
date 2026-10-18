"""Drive the unmodified installed prompt through AT-SPI on the fresh Debian VM."""

import argparse
import hashlib
import json
import re
import subprocess
import time
from pathlib import Path

import dbus

ROOT = Path("/run/mano-stock-human")


def wait(check, timeout=25):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = check()
        if value:
            return value
        time.sleep(0.1)
    raise AssertionError("Unmodified stock prompt stage timed out")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--duration", type=int, choices=(120, 900), default=120)
    args = parser.parse_args()
    status = dbus.SessionBus().get_object("org.a11y.Bus", "/org/a11y/bus")
    dbus.Interface(status, "org.freedesktop.DBus.Properties").Set(
        "org.a11y.Status", "IsEnabled", dbus.Boolean(True)
    )
    import pyatspi

    def nodes(node, depth=0):
        if depth > 12:
            return
        yield node
        for index in range(min(node.childCount, 200)):
            yield from nodes(node.getChildAtIndex(index), depth + 1)

    def tree():
        return list(nodes(pyatspi.Registry.getDesktop(0)))

    def text():
        return "\n".join(str(node.name) for node in tree())

    def control(name, roles):
        def find():
            matches = [
                node
                for node in tree()
                if node.name == name
                and node.getRoleName() in roles
                and node.getState().contains(pyatspi.STATE_SENSITIVE)
            ]
            return matches[0] if len(matches) == 1 else None

        return wait(find)

    def click(name, roles=frozenset({"button", "push button"})):
        action = control(name, roles).queryAction()
        assert action.nActions and action.doAction(0), name

    def editable():
        for node in tree():
            if node.getRoleName() in {"text", "entry", "text entry"}:
                try:
                    return node.queryEditableText()
                except NotImplementedError:
                    pass
        return None

    def identity(label):
        match = re.search(r"^" + label + r": ([0-9a-f]{32})$", text(), re.MULTILINE)
        return match.group(1) if match else None

    def capture(name):
        compositor = json.loads(
            subprocess.check_output(["swaymsg", "-r", "-t", "get_tree"], text=True, timeout=5)
        )

        def walk(node):
            yield node
            for child in node.get("nodes", []) + node.get("floating_nodes", []):
                yield from walk(child)

        dialogs = [node for node in walk(compositor) if node.get("name") == "Task permissions"]
        assert len(dialogs) == 1 and dialogs[0]["visible"] and dialogs[0]["focused"]
        # Accessibility text can precede the compositor's final paint. Require settled
        # pixels, rather than accepting one transitional damage/animation frame.
        time.sleep(1)
        previous = None
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            subprocess.run(["grim", str(ROOT / name)], check=True, capture_output=True, timeout=10)
            digest = hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
            if digest == previous:
                return
            previous = digest
            time.sleep(0.35)
        raise AssertionError("Stock GUI capture did not settle to consecutive identical frames")

    assert wait(editable).setTextContents("Clean Debian runtime reboot witness")
    click("Send")
    prompt_id = wait(lambda: identity("Request"))
    (ROOT / "received.json").write_text(json.dumps(dict(prompt_id=prompt_id)) + "\n")
    wait(lambda: (ROOT / "provisioned").exists(), 40)
    click("Check request status")
    task_id = wait(lambda: identity("Task"))
    click("Permissions")
    wait(lambda: "New automatic grants: unavailable" in text())
    click("Auto", {"radio button", "check box"})
    for label, value in (
        ("Duration (seconds)", args.duration),
        ("Automatic grants", 3),
        ("Action timeout (seconds)", 10),
    ):
        control(label, {"spin button", "spinbutton"}).queryValue().currentValue = value
    click("Request profile approval")
    approval_id = wait(lambda: identity("Approval"))
    pending = text()
    assert "Pending terminal review at acknowledgement" in pending
    assert "New automatic grants: unavailable" in pending
    assert not any(node.getRoleName() in {"password text", "password entry"} for node in tree())
    capture("stock-permissions-pending.png")
    (ROOT / "pending.json").write_text(
        json.dumps(dict(prompt_id=prompt_id, task_id=task_id, approval_id=approval_id)) + "\n"
    )
    wait(lambda: (ROOT / "approved").exists(), 40)
    click("Refresh permissions")
    wait(lambda: "New automatic grants: available" in text())
    effective = text()
    assert "Recorded mode: Auto" in effective and "Remaining: 3 grants" in effective
    assert "action timeout: 10 seconds" in effective
    capture("stock-permissions-effective.png")
    click("Close permissions")
    (ROOT / "result.json").write_text(
        json.dumps(
            dict(
                prompt_id=prompt_id,
                task_id=task_id,
                pending=pending,
                effective=effective,
                unmodified_packaged_prompt=True,
                app_observer_injected=False,
                physical_input_provenance=None,
            ),
            indent=2,
        )
        + "\n"
    )


if __name__ == "__main__":
    main()
