"""Small GTK4 human surface; prompt requests are data, never executable code."""

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Gdk", "4.0")
from gi.repository import Gdk, Gtk  # noqa: E402

from mano_prompt.requests import store_request  # noqa: E402


class Prompt(Gtk.Application):
    def __init__(self):
        super().__init__(application_id="org.mano.Prompt")
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

        def submit(_widget):
            try:
                store_request(entry.get_text())
                status.set_text("Request received")
                entry.set_text("")
                entry.grab_focus()
            except (ValueError, OSError) as error:
                status.set_text(str(error))

        entry.connect("activate", submit)
        send.connect("clicked", submit)
        row.append(entry)
        row.append(send)
        for widget in (title, subtitle, row, status):
            outer.append(widget)
        self.entry, self.window = entry, window
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
