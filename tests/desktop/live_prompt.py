"""CI observer of the production prompt. No injected transport or approval secrets."""

import json
from pathlib import Path

from gi.repository import GLib

from mano_prompt.app import Prompt

ROOT = Path('/run/mano-live-human')


def main():
    app = Prompt()

    def observe():
        current = app.intake.current
        if current is not None:
            snapshot = dict(prompt=current, display=app.details.get_text())
            panel = app.permission_window
            if panel is not None and panel.alive:
                snapshot['permissions'] = dict(status=panel.model.status,
                    approval=panel.model.approval, summary=panel.summary.get_text(),
                    review=panel.review.get_text(), busy=panel.worker.busy)
            temporary = ROOT / 'view.tmp'
            temporary.write_text(json.dumps(snapshot) + '\n')
            temporary.replace(ROOT / 'view.json')
        return True

    app.connect('activate', lambda _app: GLib.timeout_add(50, observe))
    return app.run(None)


if __name__ == '__main__':
    raise SystemExit(main())
