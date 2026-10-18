"""Small GTK4 human surface; prompt requests are data, never executable code."""

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Gdk", "4.0")
from gi.repository import Gdk, GLib, Gtk  # noqa: E402

from mano_prompt.dispatch import SubmissionWorker  # noqa: E402
from mano_prompt.intake import Intake, read_status  # noqa: E402
from mano_prompt.submit import Submission  # noqa: E402
from mano_protocol.actions import text  # noqa: E402


class Prompt(Gtk.Application):
    def __init__(self, *, submit=None, status=None):
        super().__init__(application_id="org.mano.Prompt")
        self.submit = submit if submit is not None else Submission().submit
        self.worker = SubmissionWorker(self.submit, GLib.idle_add)
        self.status_worker = SubmissionWorker(status or read_status, GLib.idle_add)
        self.intake = Intake()
        self.connect("activate", self.activate_window)

    def activate_window(self, _app):
        window = self.get_active_window()
        if window:
            window.present()
            return
        window = Gtk.ApplicationWindow(application=self, title="mano")
        window.set_default_size(1000, 650)
        outer = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=22)
        outer.set_halign(Gtk.Align.CENTER)
        outer.set_valign(Gtk.Align.CENTER)
        outer.set_size_request(740, -1)
        title = Gtk.Label(label="mano")
        title.add_css_class("brand")
        subtitle = Gtk.Label(label="What are we doing today?")
        subtitle.add_css_class("subtitle")
        row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        entry = Gtk.Entry(placeholder_text="Ask mano…")
        entry.set_hexpand(True)
        entry.set_max_length(8192)
        send = Gtk.Button(label="Send")
        send.add_css_class("suggested-action")
        status = Gtk.Label(label="Ready")
        status.add_css_class("status")

        details = Gtk.Label(label='')
        details.set_selectable(True)
        details.set_wrap(True)
        refresh = Gtk.Button(label='Check request status')
        refresh.set_sensitive(False)

        def check_status(_widget):
            if self.worker.busy or self.status_worker.busy or self.intake.current is None:
                return
            token = self.intake.token()

            def finished(result, error):
                refresh.set_sensitive(not self.worker.busy)
                if self.worker.busy or token != self.intake.token():
                    return
                try:
                    if error or not self.intake.update(token, result):
                        raise ValueError('Status unavailable')
                except ValueError:
                    status.set_text('Status unavailable. Your request was not resubmitted.')
                else:
                    details.set_text(self.intake.display())
                    status.set_text('Request status updated')

            try:
                if self.status_worker.start(token[1], finished):
                    refresh.set_sensitive(False)
                    status.set_text('Checking request status…')
            except RuntimeError:
                status.set_text('Status check could not start. Please retry.')

        refresh.connect('clicked', check_status)

        def submit(_widget):
            if self.worker.busy:
                return

            def finished(result, error):
                entry.set_sensitive(True)
                send.set_sensitive(True)
                refresh.set_sensitive(not self.status_worker.busy
                                      and self.intake.current is not None)
                if not error:
                    try:
                        self.intake.select(result)
                    except ValueError:
                        error = True
                if error:
                    status.set_text("Acknowledgement uncertain. Retry the same request to check.")
                else:
                    details.set_text(self.intake.display())
                    refresh.set_sensitive(not self.status_worker.busy)
                    status.set_text("Request received")
                    entry.set_text("")
                entry.grab_focus()

            try:
                text(entry.get_text(), 8192)
                if self.worker.start(entry.get_text(), finished):
                    entry.set_sensitive(False)
                    send.set_sensitive(False)
                    refresh.set_sensitive(False)
                    status.set_text("Sending…")
            except ValueError:
                status.set_text("Enter a request of up to 8192 UTF-8 bytes.")
            except RuntimeError:
                status.set_text("Submission could not start. Please retry.")

        entry.connect("activate", submit)
        send.connect("clicked", submit)
        row.append(entry)
        row.append(send)
        for widget in (title, subtitle, row, status, details, refresh):
            outer.append(widget)
        self.entry, self.window = entry, window
        self.details, self.refresh = details, refresh
        window.set_child(outer)
        css = Gtk.CssProvider()
        css.load_from_string("""
window { background: #101827; color: #eef4ff; }
.brand { font-size: 60px; font-weight: 700; color: #7ac8ff; }
.subtitle { font-size: 24px; margin-bottom: 12px; }
entry, button { font-size: 19px; min-height: 44px; padding: 8px 16px; }
.status { color: #a6b5ce; font-size: 15px; margin-top: 6px; }
""")
        Gtk.StyleContext.add_provider_for_display(
            Gdk.Display.get_default(), css, Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION
        )
        window.present()
        entry.grab_focus()


def main():
    return Prompt().run(None)
