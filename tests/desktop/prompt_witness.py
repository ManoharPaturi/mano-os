"""Real prompt class with a private native-GTK observer for the CI fixture."""

import json
import os
import time
from pathlib import Path

from gi.repository import GLib

from mano_prompt.app import Prompt
from mano_prompt.requests import store_request

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
        return dict(id=prompt_id, state='task_created', task_id='b' * 32)

    app = Prompt(submit=delayed_recorder, status=delayed_status)
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

    app.connect("activate", install)
    return app.run(None)


if __name__ == "__main__":
    raise SystemExit(main())
