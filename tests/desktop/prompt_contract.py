"""Trusted human-session test driver; invokes real accessible widgets."""

import json
import os
import subprocess
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
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        tree = list(nodes(pyatspi.Registry.getDesktop(0)))
        refresh = [node for node in tree if node.name == 'Check request status'
                   and node.getRoleName() in {'button', 'push button'}]
        if len(refresh) == 1 and refresh[0].getState().contains(pyatspi.STATE_SENSITIVE):
            break
        time.sleep(0.05)  # The accessibility bridge updates asynchronously.
    else:
        raise AssertionError('Expected one sensitive status button: ' + str([
            (node.name, node.getRoleName()) for node in tree
            if node.name == 'Check request status']))
    action = refresh[0].queryAction()
    assert action.nActions and action.doAction(0)  # Exactly one click; no action retry.
    status_path = ROOT / 'status-response.json'
    deadline = time.monotonic() + 5
    while not status_path.exists() and time.monotonic() < deadline:
        time.sleep(0.05)
    intake_status = json.loads(status_path.read_text())
    assert intake_status['responsive_during_slow_status'] and intake_status['ui_ticks'] >= 2
    assert 'Workspace ready; journal status below' in intake_status['display']
    assert 'Request: ' + 'a' * 32 in intake_status['display']
    assert 'Task: ' + 'b' * 32 in intake_status['display']
    assert 'effect not verified' in intake_status['display']
    assert 'c' * 32 in intake_status['display'] and 'pending' in intake_status['display']
    assert intake_status['journal']['actions'][0]['effect_verified'] is False
    assert intake_status['journal']['approvals'][0]['state'] == 'pending'
    tree = list(nodes(pyatspi.Registry.getDesktop(0)))
    assert any('Workspace ready; journal status below' in str(node.name)
               for node in tree)
    assert len(receipt.read_text().splitlines()) == prior + 1  # Status never resubmits.
    def wait_file(name):
        path = ROOT / name
        deadline = time.monotonic() + 6
        while not path.exists() and time.monotonic() < deadline:
            time.sleep(0.05)
        return json.loads(path.read_text())

    def accessible(name, roles):
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            matches = [node for node in nodes(pyatspi.Registry.getDesktop(0))
                       if node.name == name and node.getRoleName() in roles]
            if len(matches) == 1 and matches[0].getState().contains(pyatspi.STATE_SENSITIVE):
                return matches[0]
            time.sleep(0.05)
        raise AssertionError('Missing sensitive accessible control: ' + name)

    def click(name, roles=frozenset({'button', 'push button'})):
        action = accessible(name, roles).queryAction()
        assert action.nActions and action.doAction(0)

    click('Permissions')
    assert wait_file('permissions-ready.json')['ready'] is True
    duration = accessible('Duration (seconds)', {'spin button', 'spinbutton'}).queryValue()
    duration.currentValue = 900
    click('Full Access', {'radio button', 'check box'})
    deadline = time.monotonic() + 3
    while duration.maximumValue != 300 and time.monotonic() < deadline:
        time.sleep(0.05)
    assert duration.maximumValue == 300 and duration.currentValue <= 300
    click('Auto', {'radio button', 'check box'})
    duration.currentValue = 60
    click('Request profile approval')
    permissions = wait_file('permissions-complete.json')
    assert permissions['read_ticks'] >= 2 and permissions['request_ticks'] >= 2
    assert permissions['automatic_activated'] is False
    assert 'Pending terminal review' in permissions['review'] and 'e'*32 in permissions['review']
    tree = list(nodes(pyatspi.Registry.getDesktop(0)))
    assert any('Pending terminal review' in str(node.name) for node in tree)
    assert not any(node.getRoleName() in {'password text', 'password entry'} for node in tree)
    subprocess.run(['env', 'WAYLAND_DISPLAY=wayland-1', 'grim', str(ROOT / 'permissions.png')],
                   check=True, timeout=10, capture_output=True)
    click('Refresh permissions')
    click('Close permissions')
    closed = wait_file('permissions-closed.json')
    assert closed['closed'] is True and closed['late_reply_ignored'] is True
    permissions['late_reply_ignored'] = True
    assert len(receipt.read_text().splitlines()) == prior + 1
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
        "read_only_intake_status": intake_status,
        "permission_management": permissions,
    }
    (ROOT / "prompt-test.json").write_text(json.dumps(result, indent=2) + "\n")


if __name__ == "__main__":
    main()
