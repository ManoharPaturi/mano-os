"""Trusted human-session test driver; invokes real accessible widgets."""

import json
import os
import time
from pathlib import Path

import dbus
import gi

gi.require_version("Gtk", "4.0")
from gi.repository import Gtk  # noqa: E402

ROOT = Path("/run/mano-human")
EXPECTED = "Show system status"


def nodes(node, depth=0):
    if depth > 12:
        return
    yield node
    for index in range(min(node.childCount, 200)):
        yield from nodes(node.getChildAtIndex(index), depth + 1)


def main():
    receipt = Path.home() / ".local/state/mano/requests.jsonl"
    prior = len(receipt.read_text().splitlines()) if receipt.is_file() else 0
    bus = dbus.SessionBus()
    status = bus.get_object("org.a11y.Bus", "/org/a11y/bus")
    dbus.Interface(status, "org.freedesktop.DBus.Properties").Set(
        "org.a11y.Status", "IsEnabled", dbus.Boolean(True)
    )
    import pyatspi

    deadline = time.monotonic() + 25
    while time.monotonic() < deadline:
        try:
            tree = list(nodes(pyatspi.Registry.getDesktop(0)))
            buttons = [n for n in tree if n.name == "Send"]
            entries = [n for n in tree if n.getRoleName() in {"text", "entry", "text entry"}]
            if buttons and entries:
                editable = None
                for entry in entries:
                    try:
                        editable = entry.queryEditableText()
                        break
                    except NotImplementedError:
                        continue
                if editable:
                    assert editable.setTextContents(EXPECTED)
                    action = buttons[0].queryAction()
                    assert action.nActions and action.doAction(0)
                    break
        except (LookupError, NotImplementedError):
            pass
        time.sleep(0.2)
    else:
        raise RuntimeError("Native prompt did not expose editable entry and Send action")
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if receipt.is_file() and len(receipt.read_text().splitlines()) > prior:
            break
        time.sleep(0.1)
    assert receipt.is_file() and len(receipt.read_text().splitlines()) == prior + 1
    value = json.loads(receipt.read_text().splitlines()[-1])
    assert value["text"] == EXPECTED and value["uid"] == os.getuid()
    assert value["kind"] == "prompt_request"
    response_path = ROOT / 'submission-response.json'
    deadline = time.monotonic() + 5
    while not response_path.exists() and time.monotonic() < deadline:
        time.sleep(0.05)
    response = json.loads(response_path.read_text())
    assert response['responsive_during_slow_ack'] is True and response['ui_ticks'] >= 2
    result = {
        "gtk_version": ".".join(
            str(value)
            for value in (Gtk.get_major_version(), Gtk.get_minor_version(), Gtk.get_micro_version())
        ),
        "uid": os.getuid(),
        "request": value,
        "input_route": "private human AT-SPI test driver",
        "physical_input_provenance": None,
        "model_connected": False,
        "submission_responsiveness": response,
    }
    (ROOT / "prompt-test.json").write_text(json.dumps(result, indent=2) + "\n")


if __name__ == "__main__":
    main()
