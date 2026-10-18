"""Private human AT-SPI driver for actual broker-backed permission workflow."""

import json
import subprocess
import time
from pathlib import Path

import dbus

ROOT = Path('/run/mano-live-human')
GOAL = 'Live GUI permission integration witness'


def wait(check, timeout=20):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = check()
        if value:
            return value
        time.sleep(0.1)
    raise AssertionError('Live human workflow stage timed out')


def main():
    status = dbus.SessionBus().get_object('org.a11y.Bus', '/org/a11y/bus')
    dbus.Interface(status, 'org.freedesktop.DBus.Properties').Set(
        'org.a11y.Status', 'IsEnabled', dbus.Boolean(True))
    import pyatspi

    def nodes(node, depth=0):
        if depth > 12:
            return
        yield node
        for index in range(min(node.childCount, 200)):
            yield from nodes(node.getChildAtIndex(index), depth + 1)

    def control(name, roles):
        def find():
            matches = [node for node in nodes(pyatspi.Registry.getDesktop(0))
                       if node.name == name and node.getRoleName() in roles
                       and node.getState().contains(pyatspi.STATE_SENSITIVE)]
            return matches[0] if len(matches) == 1 else None
        return wait(find)

    def click(name, roles=frozenset({'button', 'push button'})):
        action = control(name, roles).queryAction()
        assert action.nActions and action.doAction(0), name

    def view():
        path = ROOT / 'view.json'
        return json.loads(path.read_text()) if path.exists() else {}

    def has_permissions(check):
        panel = view().get('permissions', {})
        return panel if not panel.get('busy', True) and check(panel) else None

    def capture(name):
        tree = json.loads(subprocess.check_output(['swaymsg', '-t', 'get_tree', '-r'],
                                                  text=True, timeout=5))
        def walk(node):
            yield node
            for child in node.get('nodes', []) + node.get('floating_nodes', []):
                yield from walk(child)
        dialogs = [node for node in walk(tree) if node.get('name') == 'Task permissions']
        assert len(dialogs) == 1 and dialogs[0]['visible'] and dialogs[0]['focused']
        time.sleep(0.3)
        subprocess.run(['grim', str(ROOT / name)], timeout=10, check=True, capture_output=True)

    def editable_entry():
        for node in nodes(pyatspi.Registry.getDesktop(0)):
            if node.getRoleName() in {'text', 'entry', 'text entry'}:
                try:
                    return node.queryEditableText()
                except NotImplementedError:
                    pass
        return None
    assert wait(editable_entry).setTextContents(GOAL)
    click('Send')
    receipt = wait(lambda: view().get('prompt'))
    assert receipt['state'] == 'received' and receipt['task_id'] is None
    wait(lambda: (ROOT / 'provisioned').exists(), 40)
    click('Check request status')
    wait(lambda: view().get('prompt', {}).get('state') == 'task_created')
    click('Permissions')
    initial = wait(lambda: has_permissions(lambda p: p.get('status') is not None))
    assert initial['status']['automatic'] is False
    click('Auto', {'radio button', 'check box'})
    for label, value in (('Duration (seconds)', 120), ('Automatic grants', 3),
                         ('Action timeout (seconds)', 10)):
        control(label, {'spin button', 'spinbutton'}).queryValue().currentValue = value
    click('Request profile approval')
    pending = wait(lambda: has_permissions(lambda p: p.get('approval') is not None))
    assert pending['approval']['state'] == 'pending' and pending['approval']['grant_id'] is None
    assert pending['status']['automatic'] is False
    assert 'Pending terminal review' in pending['review']
    assert not any(n.getRoleName() in {'password text', 'password entry'}
                   for n in nodes(pyatspi.Registry.getDesktop(0)))
    capture('live-permissions-pending.png')
    (ROOT / 'pending-ready').touch()
    wait(lambda: (ROOT / 'approved').exists(), 40)
    click('Refresh permissions')
    effective = wait(lambda: has_permissions(lambda p: p.get('status', {}).get('automatic')))
    assert effective['status']['mode'] == 'auto'
    assert effective['status']['remaining_actions'] == 3
    assert 0 < effective['status']['seconds_remaining'] <= 120
    assert effective['status']['max_timeout_seconds'] == 10
    assert 'New automatic grants: available' in effective['summary']
    capture('live-permissions-effective.png')
    click('Close permissions')
    result = dict(prompt=view()['prompt'], initial=initial, pending=pending, effective=effective,
                  input_route='private human AT-SPI driver', physical_input_provenance=None,
                  transport='production Prompt defaults and installed native broker',
                  model_connected=False)
    (ROOT / 'result.json').write_text(json.dumps(result, indent=2) + '\n')


if __name__ == '__main__':
    main()
