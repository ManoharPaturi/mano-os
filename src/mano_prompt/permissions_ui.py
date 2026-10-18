"""Human permission management UI. No passwords, confirmations or executable commands."""

import gi

gi.require_version('Gtk', '4.0')
from gi.repository import Gio, GLib, Gtk  # noqa: E402

from .dispatch import SubmissionWorker  # noqa: E402
from .mode import read_profile_status, request_profile  # noqa: E402
from .permissions import NAMES, Permissions  # noqa: E402


class PermissionsWindow(Gtk.Window):
    def __init__(self, parent, prompt_id, task_id, *, valid, read=None, request=None):
        super().__init__(title='Task permissions', transient_for=parent, modal=True)
        self.set_application(parent.get_application())
        self.set_default_size(800, 640)
        self.alive = True
        self.valid = valid
        self.model = Permissions(prompt_id, task_id)
        self.read = read or read_profile_status
        self.request = request or request_profile
        self.worker = SubmissionWorker(self.perform, GLib.idle_add)
        self.connect('close-request', self.closed)
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        for name in ('top', 'bottom', 'start', 'end'):
            getattr(box, 'set_margin_' + name)(20)
        heading = Gtk.Label(label='Task permissions')
        heading.add_css_class('subtitle')
        identity = Gtk.Label(label='Request: ' + prompt_id + '\nTask: ' + task_id)
        identity.set_selectable(True)
        self.summary = Gtk.Label(label=self.model.display(), wrap=True, xalign=0)
        self.message = Gtk.Label(label='Reading permissions…', wrap=True, xalign=0)
        self.review = Gtk.Label(label=self.model.review(), wrap=True, xalign=0, selectable=True)
        boundary = Gtk.Label(label='Workspace only. Network disabled. Model disclosure/spending '
            'need separate approval.\nIssued grants/running work may remain when counts run out; '
            'use independent Stop to revoke them.', wrap=True, xalign=0)
        choice = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=18)
        self.choices = {}
        self.mode_actions = {}
        group = None
        for mode, name in NAMES.items():
            button = Gtk.CheckButton(label=name)
            if group is None:
                group = button
            else:
                button.set_group(group)
            actions = Gio.SimpleActionGroup()
            action = Gio.SimpleAction.new_stateful(
                'select', None, GLib.Variant('b', mode == 'supervised'))
            action.connect('activate', self.select_mode, mode)
            actions.add_action(action)
            button.insert_action_group('choice', actions)
            button.set_action_name('choice.select')
            self.mode_actions[mode] = action
            self.choices[mode] = button
            choice.append(button)
        limits = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=18)
        self.limits = {}
        for key, label, maximum, default in (
                ('duration_seconds', 'Duration (seconds)', 900, 60),
                ('max_actions', 'Automatic grants', 32, 4),
                ('max_timeout_seconds', 'Action timeout (seconds)', 300, 10)):
            column = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=3)
            column.append(Gtk.Label(label=label, xalign=0))
            spin = Gtk.SpinButton.new_with_range(1, maximum, 1)
            spin.update_property([Gtk.AccessibleProperty.LABEL], [label])
            spin.set_value(default)
            spin.set_hexpand(True)
            column.append(spin)
            limits.append(column)
            self.limits[key] = spin
        for button in self.choices.values():
            button.connect('toggled', self.mode_changed)
        buttons = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        self.ask = Gtk.Button(label='Request profile approval')
        self.refresh = Gtk.Button(label='Refresh permissions')
        close = Gtk.Button(label='Close permissions')
        self.ask.connect('clicked', self.ask_profile)
        self.refresh.connect('clicked', lambda _button: self.start(('status',)))
        close.connect('clicked', lambda _button: self.close())
        for button in (self.ask, self.refresh, close):
            buttons.append(button)
        for widget in (heading, identity, boundary, self.summary,
                       Gtk.Label(label='Mode for next approval request', xalign=0), choice, limits,
                       buttons, self.message, self.review):
            box.append(widget)
        scroll = Gtk.ScrolledWindow()
        scroll.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        scroll.set_child(box)
        self.set_child(scroll)
        self.start(('status',))

    def select_mode(self, _action, _value, mode):
        if self.alive and self.valid() and mode in self.choices:
            for key, action in self.mode_actions.items():
                action.set_state(GLib.Variant('b', key == mode))

    def closed(self, *_args):
        self.alive = False
        return False

    def mode_changed(self, _button):
        maximum = 300 if self.choices['full-access'].get_active() else 900
        self.limits['duration_seconds'].set_range(1, maximum)

    def controls(self):
        busy = self.worker.busy
        self.refresh.set_sensitive(not busy)
        self.ask.set_sensitive(not busy and self.model.status is not None)
        locked = busy or self.model.pending is not None
        for action in self.mode_actions.values():
            action.set_enabled(not locked)
        for widget in (*self.choices.values(), *self.limits.values()):
            widget.set_sensitive(not locked)
        self.ask.set_label('Retry same request' if self.model.pending
                           else 'Request profile approval')

    def perform(self, operation):
        if operation[0] == 'status':
            return self.read(self.model.prompt_id)
        return self.request(*operation[1:])

    def ask_profile(self, _button):
        if self.worker.busy or not self.alive or not self.valid():
            return
        try:
            mode = next(key for key, button in self.choices.items() if button.get_active())
            args = dict(mode=mode, **{key: spin.get_value_as_int()
                                     for key, spin in self.limits.items()})
            prepared = self.model.prepare(args)
            self.start(('request', *prepared))
        except ValueError:
            self.message.set_text('Keep the same limits when retrying an uncertain request.')

    def start(self, operation):
        if not self.alive or not self.valid() or self.worker.busy:
            return

        def finished(result, error):
            if not self.alive or not self.valid():
                return
            try:
                if error:
                    raise ValueError('Protected request unavailable')
                if operation[0] == 'status':
                    self.model.accept_status(result)
                    self.summary.set_text(self.model.display())
                    self.message.set_text('Permissions read from the broker')
                else:
                    self.model.accept_request(result)
                    self.review.set_text(self.model.review())
                    self.message.set_text('Request recorded; no profile was activated here')
            except ValueError:
                text = ('Acknowledgement uncertain. Retry the same request.'
                        if operation[0] == 'request' else
                        'Permission status unavailable. Nothing was changed.')
                self.message.set_text(text)
            self.controls()

        try:
            if self.worker.start(operation, finished):
                self.message.set_text('Reading permissions…' if operation[0] == 'status'
                                      else 'Requesting terminal review…')
                self.controls()
        except RuntimeError:
            self.message.set_text('Operation could not start. Nothing was retried automatically.')
            self.controls()
