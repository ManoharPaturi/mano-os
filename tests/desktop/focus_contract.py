"""Human-only event/snapshot witness while actual agent applications operate."""

import json
import os
import subprocess
import time
from pathlib import Path

import pyatspi
from gi.repository import GLib

ROOT = Path("/run/mano-human")
CANARY = "Human canary: agent input must leave this unchanged"


def nodes(node, depth=0):
    if depth > 12:
        return
    yield node
    for index in range(min(node.childCount, 200)):
        yield from nodes(node.getChildAtIndex(index), depth + 1)


def main():
    tree = list(nodes(pyatspi.Registry.getDesktop(0)))
    entry = None
    for node in tree:
        try:
            editable = node.queryEditableText()
            entry = node
            break
        except NotImplementedError:
            continue
    assert entry is not None
    assert editable.setTextContents(CANARY)
    assert entry.queryComponent().grabFocus()
    receipt = Path.home() / ".local/state/mano/requests.jsonl"
    baseline_count = len(receipt.read_text().splitlines())
    report = {
        "passed": False,
        "uid": os.getuid(),
        "canary": CANARY,
        "violations": [],
        "samples": 0,
        "events": 0,
        "physical_input_provenance": None,
        "monitor_interval_ms": 50,
    }

    def snapshot():
        return {
            "text": entry.queryText().getText(0, -1),
            "focused": entry.getState().contains(pyatspi.STATE_FOCUSED),
            "receipt_count": len(receipt.read_text().splitlines()),
        }

    before = snapshot()
    assert before["text"] == CANARY and before["focused"]
    report["before"] = before
    subprocess.run(["grim", str(ROOT / "focus-before.png")], check=True, timeout=20)

    def check(reason):
        current = snapshot()
        report["samples"] += 1
        if current != before:
            report["violations"].append({"reason": reason, "snapshot": current})
        report["after"] = current
        assert current["receipt_count"] >= baseline_count

    def event(event):
        report["events"] += 1
        if (
            event.type.startswith("object:state-changed:focused")
            and event.source == entry
            and event.detail1 == 0
        ):
            report["violations"].append({"reason": "human entry lost focus event"})
        check(event.type)

    pyatspi.Registry.registerEventListener(
        event, "object:state-changed:focused", "object:text-changed"
    )
    (ROOT / "focus-ready.json").write_text(json.dumps(before) + "\n")
    deadline = time.monotonic() + 600

    def poll():
        try:
            check("periodic snapshot")
            if (ROOT / "focus-stop").exists() or time.monotonic() > deadline:
                if time.monotonic() > deadline:
                    report["violations"].append({"reason": "monitor timeout"})
                pyatspi.Registry.stop()
                return False
        except Exception as error:
            report["violations"].append({"reason": str(error)})
            pyatspi.Registry.stop()
            return False
        return True

    GLib.timeout_add(50, poll)
    pyatspi.Registry.start()
    pyatspi.Registry.deregisterEventListener(
        event, "object:state-changed:focused", "object:text-changed"
    )
    report["passed"] = not report["violations"] and report["samples"] > 1
    subprocess.run(["grim", str(ROOT / "focus-after.png")], check=True, timeout=20)
    (ROOT / "focus-report.json").write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    main()
