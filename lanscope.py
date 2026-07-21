#!/usr/bin/env python3
"""lanscope — LanScan-style LAN scanner for Linux (GTK3 frontend).

Unprivileged GUI; ARP discovery is delegated to `lanscope-helper` via pkexec.
"""

import ipaddress
import signal
import gi
gi.require_version("Gtk", "3.0")
from gi.repository import Gtk, GLib, Gdk, GObject, Pango  # noqa: E402

from engine import Scanner  # noqa: E402

# ListStore column indexes
(COL_IP, COL_IP_SORT, COL_MAC, COL_HOSTNAME, COL_PING, COL_VENDOR,
 COL_IDENT, COL_DNS, COL_MDNS, COL_SMB_NAME, COL_SMB_DOMAIN) = range(11)

PING_PENDING, PING_UP, PING_DOWN = 0, 1, 2
PING_DOT = {
    PING_PENDING: ("●", "#b0b0b0"),
    PING_UP:      ("●", "#34c759"),
    PING_DOWN:    ("●", "#ff3b30"),
}

FIELD_TO_COL = {
    "vendor": COL_VENDOR, "identification": COL_IDENT, "dns": COL_DNS,
    "mdns": COL_MDNS, "smb_name": COL_SMB_NAME, "smb_domain": COL_SMB_DOMAIN,
}

TEXT_COLUMNS = [
    ("MAC address", COL_MAC, True),
    ("Hostname", COL_HOSTNAME, False),
    # Ping dot column inserted here specially
    ("Vendor", COL_VENDOR, False),
    ("Identification", COL_IDENT, False),
    ("DNS Name", COL_DNS, False),
    ("mDNS Name", COL_MDNS, False),
    ("SMB Name", COL_SMB_NAME, False),
    ("SMB Domain", COL_SMB_DOMAIN, False),
]


class LanScopeWindow(Gtk.ApplicationWindow):
    def __init__(self, app):
        super().__init__(application=app, title="LanScope")
        self.set_default_size(1280, 640)
        self.scanner = None
        self.rows = {}          # ip -> Gtk.TreeRowReference
        self.filter_text = ""

        self._build_ui()
        self.show_all()
        self.filter_revealer.set_reveal_child(False)

    # ------------------------------------------------------------------ UI
    def _build_ui(self):
        header = Gtk.HeaderBar(show_close_button=True, title="LanScope")
        self.set_titlebar(header)

        self.btn_scan = Gtk.Button.new_from_icon_name(
            "media-playback-start-symbolic", Gtk.IconSize.BUTTON)
        self.btn_scan.set_tooltip_text("Start LanScan (Space)")
        self.btn_scan.connect("clicked", self.on_scan_clicked)
        header.pack_start(self.btn_scan)

        self.btn_stop = Gtk.Button.new_from_icon_name(
            "media-playback-stop-symbolic", Gtk.IconSize.BUTTON)
        self.btn_stop.set_tooltip_text("Stop scan")
        self.btn_stop.set_sensitive(False)
        self.btn_stop.connect("clicked", self.on_stop_clicked)
        header.pack_start(self.btn_stop)

        btn_clear = Gtk.Button.new_from_icon_name(
            "edit-clear-all-symbolic", Gtk.IconSize.BUTTON)
        btn_clear.set_tooltip_text("Clear Results (Ctrl+K)")
        btn_clear.connect("clicked", self.on_clear_clicked)
        header.pack_start(btn_clear)

        self.spinner = Gtk.Spinner()
        header.pack_end(self.spinner)

        btn_filter = Gtk.ToggleButton()
        btn_filter.add(Gtk.Image.new_from_icon_name(
            "edit-find-symbolic", Gtk.IconSize.BUTTON))
        btn_filter.set_tooltip_text("Filter (Ctrl+F)")
        btn_filter.connect("toggled", self.on_filter_toggled)
        self.btn_filter = btn_filter
        header.pack_end(btn_filter)

        vbox = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        self.add(vbox)

        # Filter bar (revealed with Ctrl+F, like LanScan's ⌘F)
        self.filter_revealer = Gtk.Revealer()
        fbox = Gtk.Box(spacing=6, margin=6)
        self.filter_entry = Gtk.SearchEntry(placeholder_text="Filter devices…")
        self.filter_entry.connect("search-changed", self.on_filter_changed)
        self.filter_entry.connect("stop-search", lambda *_: self._hide_filter())
        fbox.pack_start(self.filter_entry, True, True, 0)
        self.filter_revealer.add(fbox)
        vbox.pack_start(self.filter_revealer, False, False, 0)

        # Model: store -> filter -> sort -> view
        self.store = Gtk.ListStore(str, GObject.TYPE_UINT64, str, str, int,
                                   str, str, str, str, str, str)
        self.filtered = self.store.filter_new()
        self.filtered.set_visible_func(self._row_visible)
        self.sorted_model = Gtk.TreeModelSort(model=self.filtered)
        self.sorted_model.set_sort_column_id(COL_IP_SORT, Gtk.SortType.ASCENDING)

        self.view = Gtk.TreeView(model=self.sorted_model)
        self.view.set_enable_search(False)
        self.view.connect("button-press-event", self.on_button_press)

        self._add_text_column("IPv4 address", COL_IP, mono=True,
                              sort_col=COL_IP_SORT)
        for i, (title, col, mono) in enumerate(TEXT_COLUMNS):
            self._add_text_column(title, col, mono=mono)
            if title == "Hostname":
                self._add_ping_column()

        sw = Gtk.ScrolledWindow()
        sw.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
        sw.add(self.view)
        vbox.pack_start(sw, True, True, 0)

        # Status bar: message left, device count right (LanScan-style)
        sbox = Gtk.Box(spacing=12, margin=4)
        self.status_label = Gtk.Label(label="Ready", xalign=0)
        self.status_label.set_ellipsize(Pango.EllipsizeMode.END)
        self.count_label = Gtk.Label(label="Devices seen: 0", xalign=1)
        sbox.pack_start(self.status_label, True, True, 6)
        sbox.pack_end(self.count_label, False, False, 6)
        vbox.pack_end(sbox, False, False, 0)

        # Shortcuts
        accel = Gtk.AccelGroup()
        self.add_accel_group(accel)
        for key, mods, fn in (
            (Gdk.KEY_space, 0, lambda *_: self.btn_scan.get_sensitive()
                and self.on_scan_clicked(None)),
            (Gdk.KEY_f, Gdk.ModifierType.CONTROL_MASK,
                lambda *_: self.btn_filter.set_active(True)),
            (Gdk.KEY_k, Gdk.ModifierType.CONTROL_MASK,
                lambda *_: self.on_clear_clicked(None)),
            (Gdk.KEY_c, Gdk.ModifierType.CONTROL_MASK,
                lambda *_: self.on_copy_ip()),
        ):
            accel.connect(key, mods, 0, fn)

    ZEBRA = "rgba(128,128,128,0.12)"   # subtle, works on light & dark themes

    def _zebra_bg(self, model, it):
        return self.ZEBRA if model.get_path(it).get_indices()[0] % 2 else None

    def _add_text_column(self, title, col, mono=False, sort_col=None):
        r = Gtk.CellRendererText()
        r.set_property("xpad", 12)
        if mono:
            r.set_property("family", "Monospace")
        c = Gtk.TreeViewColumn(title, r, text=col)
        c.set_cell_data_func(r, lambda _c, cell, model, it, _d:
                             cell.set_property("cell-background",
                                               self._zebra_bg(model, it)))
        c.set_sort_column_id(sort_col if sort_col is not None else col)
        c.set_resizable(True)
        c.set_min_width(90)
        self.view.append_column(c)

    def _add_ping_column(self):
        r = Gtk.CellRendererText(xalign=0.5)
        c = Gtk.TreeViewColumn("Ping", r)
        c.set_sort_column_id(COL_PING)
        c.set_min_width(48)

        def render(_col, cell, model, it, _data):
            dot, color = PING_DOT[model[it][COL_PING]]
            cell.set_property("markup",
                              f'<span foreground="{color}">{dot}</span>')
            cell.set_property("cell-background", self._zebra_bg(model, it))
        c.set_cell_data_func(r, render)
        self.view.append_column(c)

    # ---------------------------------------------------- copy / context
    def _copy(self, text):
        if text:
            Gtk.Clipboard.get(Gdk.SELECTION_CLIPBOARD).set_text(text, -1)
            self.status_label.set_text(f"Copied: {text}")

    def _selected_row(self):
        model, it = self.view.get_selection().get_selected()
        return (model, it) if it else (None, None)

    def on_copy_ip(self, *_):
        model, it = self._selected_row()
        if it:
            self._copy(model[it][COL_IP])

    def on_button_press(self, view, event):
        if event.button != 3:
            return False
        hit = view.get_path_at_pos(int(event.x), int(event.y))
        if not hit:
            return True
        path = hit[0]
        view.get_selection().select_path(path)
        model = view.get_model()
        it = model.get_iter(path)
        ip, mac = model[it][COL_IP], model[it][COL_MAC]
        row_text = "\t".join(model[it][c] for c in
                             (COL_IP, COL_MAC, COL_HOSTNAME, COL_VENDOR,
                              COL_IDENT, COL_DNS, COL_MDNS,
                              COL_SMB_NAME, COL_SMB_DOMAIN))
        menu = Gtk.Menu()
        entries = [(f"Copy IP address  ({ip})", ip)]
        if mac:
            entries.append((f"Copy MAC address  ({mac})", mac))
        entries.append(("Copy row", row_text))
        for label, text in entries:
            item = Gtk.MenuItem(label=label)
            item.connect("activate",
                         lambda _w, t=text: self._copy(t))
            menu.append(item)
        menu.show_all()
        menu.popup_at_pointer(event)
        return True

    # ------------------------------------------------------------- filter
    def _row_visible(self, model, it, _data):
        if not self.filter_text:
            return True
        needle = self.filter_text.lower()
        return any(needle in (model[it][c] or "").lower()
                   for c in (COL_IP, COL_MAC, COL_HOSTNAME, COL_VENDOR,
                             COL_IDENT, COL_DNS, COL_MDNS,
                             COL_SMB_NAME, COL_SMB_DOMAIN))

    def on_filter_toggled(self, btn):
        show = btn.get_active()
        self.filter_revealer.set_reveal_child(show)
        if show:
            self.filter_entry.grab_focus()
        else:
            self.filter_entry.set_text("")

    def _hide_filter(self):
        self.btn_filter.set_active(False)

    def on_filter_changed(self, entry):
        self.filter_text = entry.get_text()
        self.filtered.refilter()

    # -------------------------------------------------------------- scan
    def on_scan_clicked(self, _btn):
        self.on_clear_clicked(None)
        self.btn_scan.set_sensitive(False)
        self.btn_stop.set_sensitive(True)
        self.spinner.start()
        self.status_label.set_text("Scanning…")
        self.scanner = Scanner(
            on_device=lambda ip, mac: GLib.idle_add(self._add_device, ip, mac),
            on_update=lambda ip, f, v: GLib.idle_add(self._update, ip, f, v),
            on_status=lambda s: GLib.idle_add(self.status_label.set_text, s),
            on_done=lambda n: GLib.idle_add(self._scan_done, n),
        )
        self.scanner.start()

    def on_stop_clicked(self, _btn):
        if self.scanner:
            self.scanner.stop()
        self.status_label.set_text("Stopping…")

    def on_clear_clicked(self, _btn):
        self.store.clear()
        self.rows.clear()
        self.count_label.set_text("Devices seen: 0")

    def _scan_done(self, _count):
        self.spinner.stop()
        self.btn_scan.set_sensitive(True)
        self.btn_stop.set_sensitive(False)
        self.status_label.set_text("Scan complete")

    # ------------------------------------------------- model manipulation
    def _add_device(self, ip, mac):
        if ip in self.rows:
            return
        try:
            ip_sort = int(ipaddress.ip_address(ip))
        except ValueError:
            ip_sort = 0
        it = self.store.append([ip, ip_sort, mac or "", "", PING_PENDING,
                                "", "", "", "", "", ""])
        self.rows[ip] = Gtk.TreeRowReference(
            self.store, self.store.get_path(it))
        self.count_label.set_text(f"Devices seen: {len(self.rows)}")

    def _update(self, ip, field, value):
        ref = self.rows.get(ip)
        if not ref or not ref.valid():
            return
        it = self.store.get_iter(ref.get_path())
        if field == "ping":
            self.store[it][COL_PING] = PING_UP if value == "up" else PING_DOWN
            return
        col = FIELD_TO_COL.get(field)
        if col is None or not value:
            return
        self.store[it][col] = value
        # Hostname column: best available short name (mDNS > DNS > SMB)
        if col in (COL_MDNS, COL_DNS, COL_SMB_NAME):
            host = (self.store[it][COL_MDNS] or self.store[it][COL_DNS]
                    or self.store[it][COL_SMB_NAME])
            self.store[it][COL_HOSTNAME] = host.split(".")[0] if host else ""


class LanScopeApp(Gtk.Application):
    def __init__(self):
        super().__init__(application_id="io.github.lanscope")

    def do_activate(self):
        win = self.get_active_window() or LanScopeWindow(self)
        win.present()


if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal.SIG_DFL)
    LanScopeApp().run(None)
