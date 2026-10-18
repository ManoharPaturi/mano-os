"""Real prompt class with a private native-GTK observer for the CI fixture."""

import json
import os
import time
from pathlib import Path

from gi.repository import GLib

from mano_prompt.app import Prompt
from mano_prompt.requests import store_request
from mano_protocol.profiles import scope

ROOT = Path("/run/mano-human")
CANARY = "Human canary: agent input must leave this unchanged"


def main():
    def delayed_recorder(prompt):
        time.sleep(1)  # CI-only slow acknowledgement, never a production delay.
        store_request(prompt)
        return dict(id="a" * 32, state="received", task_id=None)

    def delayed_status(prompt_id):
        assert prompt_id == 'a' * 32
        time.sleep(1)  # Test-only slow read, never a production delay.
        return dict(prompt=dict(id=prompt_id, state='task_created', task_id='b' * 32),
            action_count=1, actions=[dict(action_id='d' * 32, capability='terminal.run',
                                         state='done', effect_verified=False)],
            approvals=[dict(approval_id='c' * 32, capability='terminal.run', state='pending')])

    permission_reads, permission_requests = [], []

    def permission_read(prompt_id):
        permission_reads.append(prompt_id)
        time.sleep(1)
        return dict(schema_version='1.0', ok=True, prompt_id='a'*32, task_id='b'*32,
            profile=dict(mode='supervised', automatic=False, remaining_actions=0,
                seconds_remaining=0, max_timeout_seconds=0, scope=scope('supervised')))

    def permission_request(prompt_id, request_key, args):
        permission_requests.append(dict(prompt_id=prompt_id, request_key=request_key, args=args))
        assert prompt_id == 'a'*32
        assert args == dict(mode='auto', duration_seconds=60, max_actions=4, max_timeout_seconds=10)
        time.sleep(1)
        return dict(schema_version='1.0', ok=True, prompt_id=prompt_id, task_id='b'*32,
                    approval=dict(approval_id='e'*32, state='pending', grant_id=None))

    app = Prompt(submit=delayed_recorder, status=delayed_status,
                 permission_read=permission_read, permission_request=permission_request)
    permission_ticks = dict(read=0, request=0)

    def permission_report(name, value):
        path = ROOT / name
        if not path.exists():
            temporary = path.with_suffix('.tmp')
            temporary.write_text(json.dumps(value) + '\n')
            temporary.replace(path)

    def permission_observer():
        panel = app.permission_window
        if panel is None:
            return True
        if not panel.alive:
            permission_report('permissions-closed.json', dict(closed=True))
            return False
        if panel.worker.busy:
            stage = 'request' if panel.model.pending is not None else 'read'
            permission_ticks[stage] += 1
        elif panel.model.approval is not None:
            assert panel.model.approval['state'] == 'pending'
            assert panel.model.status['automatic'] is False
            assert len(permission_reads) == len(permission_requests) == 1
            assert all(count >= 2 for count in permission_ticks.values())
            report = dict(read_ticks=permission_ticks['read'],
                request_ticks=permission_ticks['request'],
                request=permission_requests[0], summary=panel.summary.get_text(),
                review=panel.review.get_text(), automatic_activated=False,
                scope='synthetic local permission-management UI fixture',
                physical_input_provenance=None)
            permission_report('permissions-complete.json', report)
        elif panel.model.status is not None:
            assert panel.ask.get_sensitive()
            permission_report('permissions-ready.json', dict(ready=True))
        return True
    status_ticks = 0

    def status_responsiveness():
        nonlocal status_ticks
        if app.status_worker.busy:
            status_ticks += 1
        elif status_ticks:
            assert status_ticks >= 2, 'GTK did not run during slow status lookup'
            assert app.intake.current == dict(id='a' * 32, state='task_created', task_id='b' * 32)
            assert app.refresh.get_sensitive()
            (ROOT / 'status-response.json').write_text(json.dumps(dict(
                responsive_during_slow_status=True, ui_ticks=status_ticks,
                display=app.details.get_text(), intake=app.intake.current,
                journal=app.intake.activity,
                scope='synthetic local status UI fixture', physical_input_provenance=None)) + '\n')
            return False
        return True
    submission_ticks = 0

    def responsiveness():
        nonlocal submission_ticks
        if app.worker.busy:
            submission_ticks += 1
        elif submission_ticks:
            assert submission_ticks >= 2, 'GTK did not run during slow submission'
            (ROOT / 'submission-response.json').write_text(json.dumps(dict(
                responsive_during_slow_ack=True, ui_ticks=submission_ticks,
                injected_ack_delay_seconds=1, scope='synthetic local-recorder UI fixture',
                physical_input_provenance=None)) + '\n')
            return False
        return True
    report = {
        "passed": False,
        "uid": os.getuid(),
        "canary": CANARY,
        "violations": [],
        "samples": 0,
        "events": 0,
        "setup_signal_events": 0,
        "monitor_interval_ms": 50,
        "observation_api": "native GTK widget getters/signals",
        "physical_input_provenance": None,
    }
    armed = False
    installed = False
    before = None
    deadline = time.monotonic() + 600

    def snapshot():
        focus = app.window.get_focus()
        focused = focus is not None and (focus == app.entry or focus.is_ancestor(app.entry))
        receipt = Path.home() / ".local/state/mano/requests.jsonl"
        return {
            "text": app.entry.get_text(),
            "focused": focused,
            "active": app.window.is_active(),
            "receipt_count": len(receipt.read_text().splitlines()),
        }

    def check(reason):
        current = snapshot()
        report["samples"] += 1
        if current != before:
            report["violations"].append({"reason": reason, "snapshot": current})
        report["after"] = current

    def event(_obj, *_args):
        if armed:
            report["events"] += 1
            check("native GTK signal")
        else:
            report["setup_signal_events"] += 1

    def poll():
        nonlocal armed, before
        try:
            if not armed and (ROOT / "focus-arm").exists():
                setup_before = report["setup_signal_events"]
                app.entry.set_text(CANARY)
                assert app.entry.grab_focus()
                assert report["setup_signal_events"] > setup_before, (
                    "No native text signal observed"
                )
                before = snapshot()
                print(json.dumps({"initial_state": before}), flush=True)
                assert before["text"] == CANARY and before["focused"] and before["active"]
                report["before"] = before
                armed = True
                (ROOT / "focus-ready.json").write_text(json.dumps(before) + "\n")
            if armed:
                check("periodic snapshot")
                if (ROOT / "focus-stop").exists():
                    report["passed"] = not report["violations"] and report["samples"] > 1
                    (ROOT / "focus-report.json").write_text(json.dumps(report, indent=2) + "\n")
                    return False
            if time.monotonic() > deadline:
                raise RuntimeError("Native witness timeout")
        except Exception as error:
            report["violations"].append({"reason": str(error)})
            (ROOT / "focus-report.json").write_text(json.dumps(report, indent=2) + "\n")
            return False
        return True

    def install(_app):
        nonlocal installed
        if installed:
            return
        installed = True
        app.entry.connect("changed", event)
        app.window.connect("notify::focus-widget", event)
        app.window.connect("notify::is-active", event)
        GLib.timeout_add(50, poll)
        GLib.timeout_add(50, responsiveness)
        GLib.timeout_add(50, status_responsiveness)
        GLib.timeout_add(50, permission_observer)

    app.connect("activate", install)
    return app.run(None)


if __name__ == "__main__":
    raise SystemExit(main())
