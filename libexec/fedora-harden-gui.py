"""fedora-harden --gui: one window for the whole run.

fedora-harden.sh starts this app and talks to it over a pipe, one event per line,
fields separated by tabs (backslash, tab and newline escaped as \\, \t and \n):

  in  (script -> window)              out (window -> script)
  MODE   <subtitle>                   READY
  PLAN   <section> <title>            ANSWER <id> <yes|no|text>
  SECTION <section> <title>           CANCEL
  LOG    <info|ok|warn|error|dry|run|out> <text>
  NOTICE <info|warning|error> <text>
  ASK    <id> <confirm|input> <default> <text>
  SUMMARY <headline> <details>
  ITEMS                               (clears the follow-up list)
  ITEM   <HIGH|MEDIUM|LOW|DONE> <section> <text>
  SCORE  <ok|no|na|info> <label> <detail> <fix>   (protection scorecard row)
  END    <exit code> <message>

The window stays open after the script exits so the summary can be read; closing
it while the run is going asks before stopping the run.
"""

import os
import sys
import time

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gdk, Gio, GLib, GObject, Gtk, Pango

try:  # GLib 2.80+ moved the Unix streams to GioUnix
    gi.require_version("GioUnix", "2.0")
    from gi.repository import GioUnix

    UnixInputStream = GioUnix.InputStream
except (ImportError, ValueError):
    UnixInputStream = Gio.UnixInputStream

APP_TITLE = "Fedora Hardening"
MAX_LINES = 20000  # activity lines kept in memory; older ones are dropped

CSS = """
/* Material Design 3, dark: surface #141218, containers #211F26 / #2B2930, primary #D0BCFF */
:root {
  --window-bg-color: #141218; --window-fg-color: #E6E0E9;
  --view-bg-color: #211F26; --view-fg-color: #E6E0E9;
  --headerbar-bg-color: #141218; --headerbar-fg-color: #E6E0E9;
  --headerbar-backdrop-color: #141218; --headerbar-shade-color: transparent;
  --sidebar-bg-color: #1D1B20; --sidebar-fg-color: #E6E0E9;
  --sidebar-backdrop-color: #1D1B20; --sidebar-shade-color: transparent;
  --card-bg-color: #211F26; --card-fg-color: #E6E0E9;
  --dialog-bg-color: #2B2930; --dialog-fg-color: #E6E0E9;
  --popover-bg-color: #2B2930; --popover-fg-color: #E6E0E9;
  --accent-bg-color: #D0BCFF; --accent-fg-color: #381E72; --accent-color: #D0BCFF;
  --destructive-bg-color: #8C1D18; --destructive-fg-color: #F9DEDC;
  --destructive-color: #F2B8B5;
  --success-color: #8BD5A5; --warning-color: #FFB95C; --error-color: #F2B8B5;
}
* { font-family: "Roboto", "Noto Sans", "Cantarell", sans-serif; }
.status-card { background: #2B2930; border-radius: 20px; padding: 18px 20px; }
.status-section { font-size: 1.25em; font-weight: 600; }
.status-step { color: #CAC4D0; }
.status-clock { color: #CAC4D0; font-feature-settings: "tnum"; }
progressbar trough { background: #4A4458; border-radius: 9999px; min-height: 8px; }
progressbar progress { background: #D0BCFF; border-radius: 9999px; min-height: 8px; }
progressbar.failed progress { background: #F2B8B5; }
progressbar text { color: #CAC4D0; font-feature-settings: "tnum"; }
.chip { border-radius: 9999px; padding: 2px 12px; min-height: 30px; background: #2B2930; color: #E6E0E9; }
.chip:checked { background: #4F378B; color: #EADDFF; }
.chip .count { font-weight: 700; font-feature-settings: "tnum"; }
.chip.warn .count { color: #FFB95C; }
.chip.error .count { color: #F2B8B5; }
.chip.ok .count { color: #8BD5A5; }
.question { background: #4F378B; color: #EADDFF; border-radius: 20px; padding: 16px 18px; }
.question label { color: #EADDFF; }
.question entry { background: #381E72; color: #EADDFF; }
.notice { border-radius: 16px; padding: 12px 14px; background: #2B2930; }
.notice.warning { background: #4A3A1F; }
.notice.error { background: #601410; }
.log-view, .log-view text { background: #0F0D13; color: #E6E0E9; }
.log-view { border-radius: 16px; padding: 10px 12px;
  font-family: "Roboto Mono", "Noto Sans Mono", "DejaVu Sans Mono", monospace; font-size: 0.92em; }
.section-row { padding: 6px 4px; }
.section-num { color: #938F99; font-feature-settings: "tnum"; min-width: 2.2em; }
.section-row.running .section-title { font-weight: 700; color: #D0BCFF; }
.section-row.pending .section-title, .section-row.skipped .section-title { color: #938F99; }
.st-ok { color: #8BD5A5; } .st-warn { color: #FFB95C; } .st-error { color: #F2B8B5; }
.st-running { color: #D0BCFF; } .st-pending { color: #4A4458; }
.summary-icon.ok { color: #8BD5A5; } .summary-icon.warn { color: #FFB95C; }
.summary-icon.error { color: #F2B8B5; }
.prio { border-radius: 9999px; padding: 0 10px; font-size: 0.85em; font-weight: 700; }
.prio.HIGH { background: #601410; color: #F9DEDC; }
.prio.MEDIUM { background: #4A3A1F; color: #FFDDB3; }
.prio.LOW { background: #36343B; color: #CAC4D0; }
.prio.DONE { background: #1F3A2A; color: #B7F1C8; }
"""

# Activity-log levels: (prefix shown, text tag, counted as)
LEVELS = {
    "info": ("INFO", "info", None),
    "ok": ("OK", "ok", "ok"),
    "warn": ("WARN", "warn", "warn"),
    "error": ("FAIL", "error", "error"),
    "dry": ("DRY", "dry", None),
    "run": ("RUN", "run", None),
    "out": ("", "out", None),
}
STATUS_ICON = {
    "pending": ("media-record-symbolic", "st-pending"),
    "running": ("media-playback-start-symbolic", "st-running"),
    "ok": ("object-select-symbolic", "st-ok"),
    "warn": ("dialog-warning-symbolic", "st-warn"),
    "error": ("dialog-error-symbolic", "st-error"),
    "skipped": ("media-skip-forward-symbolic", "st-pending"),
}
FINAL = ("ok", "warn", "error", "skipped")


def unescape(s):
    out, i = [], 0
    while i < len(s):
        c = s[i]
        if c == "\\" and i + 1 < len(s):
            n = s[i + 1]
            out.append({"n": "\n", "t": "\t", "\\": "\\"}.get(n, "\\" + n))
            i += 2
            continue
        out.append(c)
        i += 1
    return "".join(out)


def escape(s):
    return s.replace("\\", "\\\\").replace("\t", "\\t").replace("\n", "\\n")


def fmt_clock(seconds):
    seconds = int(seconds)
    h, rest = divmod(seconds, 3600)
    m, s = divmod(rest, 60)
    return f"{h}:{m:02d}:{s:02d}" if h else f"{m:02d}:{s:02d}"


class SectionRow(Gtk.ListBoxRow):
    def __init__(self, num, title):
        super().__init__(activatable=False, selectable=False)
        self.num, self.status = num, "pending"
        box = Gtk.Box(spacing=10)
        box.add_css_class("section-row")
        self.icon = Gtk.Image(pixel_size=14)
        self.num_label = Gtk.Label(label=f"§{num}", xalign=0)
        self.num_label.add_css_class("section-num")
        self.title = Gtk.Label(label=title, xalign=0, hexpand=True, wrap=True,
                               wrap_mode=Pango.WrapMode.WORD_CHAR, lines=2,
                               ellipsize=Pango.EllipsizeMode.END)
        self.title.add_css_class("section-title")
        box.append(self.icon)
        box.append(self.num_label)
        box.append(self.title)
        self.set_child(box)
        self.box = box
        self.set_status("pending")

    def set_status(self, status):
        for s in STATUS_ICON:
            self.box.remove_css_class(s)
        self.status = status
        self.box.add_css_class(status)
        name, cls = STATUS_ICON[status]
        self.icon.set_from_icon_name(name)
        for c in ("st-pending", "st-running", "st-ok", "st-warn", "st-error"):
            self.icon.remove_css_class(c)
        self.icon.add_css_class(cls)
        self.icon.set_tooltip_text(
            {"pending": "Not started", "running": "Running", "ok": "Done",
             "warn": "Done with warnings", "error": "Done with errors",
             "skipped": "Skipped: not applicable on this system"}[status])


class HardenWindow(Adw.ApplicationWindow):
    def __init__(self, app):
        super().__init__(application=app, title=APP_TITLE, default_width=1080,
                         default_height=720)
        self.set_size_request(380, 480)
        self.started = time.monotonic()
        self.finished = False
        self.exit_code = None
        self.cancel_sent = False
        self.lines = []  # (level, time, text)
        self.counts = {"ok": 0, "warn": 0, "error": 0}
        self.sections = {}  # num -> SectionRow
        self.order = []
        self.current = None
        self.section_started = {}
        self.section_durations = []
        self.section_level = "ok"
        self.pending_ask = None
        self.asks = 0
        self.filter = "all"
        self.follow = True

        self.toasts = Adw.ToastOverlay()
        self.set_content(self.toasts)
        view = Adw.ToolbarView()
        self.toasts.set_child(view)

        # Header: title + mode, sidebar toggle, stop/close, log menu
        header = Adw.HeaderBar()
        self.title_widget = Adw.WindowTitle(title=APP_TITLE, subtitle="Starting…")
        header.set_title_widget(self.title_widget)
        self.sidebar_btn = Gtk.ToggleButton(icon_name="sidebar-show-symbolic", active=True,
                                            tooltip_text="Show sections (F9)")
        header.pack_start(self.sidebar_btn)
        self.stop_btn = Gtk.Button(label="_Stop", use_underline=True,
                                   tooltip_text="Stop the run after the current step (Ctrl+W)")
        self.stop_btn.add_css_class("destructive-action")
        self.stop_btn.connect("clicked", lambda *_: self.request_close())
        header.pack_end(self.stop_btn)
        menu = Gio.Menu()
        menu.append("Copy activity log", "win.copy-log")
        menu.append("Copy problems only", "win.copy-problems")
        header.pack_end(Gtk.MenuButton(icon_name="open-menu-symbolic", menu_model=menu,
                                       tooltip_text="Activity log"))
        view.add_top_bar(header)

        # Sidebar: the sections this run will go through, in execution order
        self.split = Adw.OverlaySplitView(min_sidebar_width=230, max_sidebar_width=300)
        self.sidebar_btn.bind_property("active", self.split, "show-sidebar",
                                       GObject.BindingFlags.BIDIRECTIONAL |
                                       GObject.BindingFlags.SYNC_CREATE)
        side = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        side_head = Gtk.Label(label="Sections", xalign=0, margin_start=16, margin_top=12,
                              margin_bottom=6)
        side_head.add_css_class("heading")
        self.section_list = Gtk.ListBox(selection_mode=Gtk.SelectionMode.NONE)
        self.section_list.add_css_class("navigation-sidebar")
        side_scroll = Gtk.ScrolledWindow(vexpand=True,
                                         hscrollbar_policy=Gtk.PolicyType.NEVER)
        side_scroll.set_child(self.section_list)
        side.append(side_head)
        side.append(side_scroll)
        self.split.set_sidebar(side)
        view.set_content(self.split)

        main = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=14, margin_top=16,
                       margin_bottom=16, margin_start=18, margin_end=18)
        self.split.set_content(main)

        # Status card: what is running now, progress, time
        card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        card.add_css_class("status-card")
        top = Gtk.Box(spacing=12)
        self.spinner = Gtk.Spinner(spinning=True, width_request=22, height_request=22)
        self.status_icon = Gtk.Image(pixel_size=22, visible=False)
        texts = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2, hexpand=True)
        self.section_label = Gtk.Label(label="Preparing", xalign=0, wrap=True)
        self.section_label.add_css_class("status-section")
        self.step_label = Gtk.Label(label="Checking this system…", xalign=0,
                                    ellipsize=Pango.EllipsizeMode.END)
        self.step_label.add_css_class("status-step")
        texts.append(self.section_label)
        texts.append(self.step_label)
        self.clock_label = Gtk.Label(label="00:00", xalign=1, valign=Gtk.Align.START,
                                     justify=Gtk.Justification.RIGHT)
        self.clock_label.add_css_class("status-clock")
        top.append(self.spinner)
        top.append(self.status_icon)
        top.append(texts)
        top.append(self.clock_label)
        self.progress = Gtk.ProgressBar(show_text=True, text="Starting")
        card.append(top)
        card.append(self.progress)
        main.append(card)

        # Question: shown inline when the script asks something
        self.question = Gtk.Revealer(transition_type=Gtk.RevealerTransitionType.SLIDE_DOWN)
        qbox = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        qbox.add_css_class("question")
        qrow = Gtk.Box(spacing=12)
        qrow.append(Gtk.Image(icon_name="dialog-question-symbolic", pixel_size=24,
                              valign=Gtk.Align.START))
        self.q_label = Gtk.Label(xalign=0, wrap=True, hexpand=True, selectable=True,
                                 wrap_mode=Pango.WrapMode.WORD_CHAR)
        qrow.append(self.q_label)
        self.q_entry = Gtk.Entry(hexpand=True)
        self.q_entry.connect("activate", lambda *_: self.answer(None))
        buttons = Gtk.Box(spacing=8, halign=Gtk.Align.END)
        self.q_no = Gtk.Button(label="_No", use_underline=True)
        self.q_no.connect("clicked", lambda *_: self.answer("no"))
        self.q_yes = Gtk.Button(label="_Yes", use_underline=True)
        self.q_yes.add_css_class("suggested-action")
        self.q_yes.connect("clicked", lambda *_: self.answer("yes"))
        buttons.append(self.q_no)
        buttons.append(self.q_yes)
        qbox.append(qrow)
        qbox.append(self.q_entry)
        qbox.append(buttons)
        self.question.set_child(qbox)
        main.append(self.question)

        # Notices: things the script wants the user to read (stay until dismissed)
        self.notices = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        main.append(self.notices)

        # Two pages: the live activity, and the summary once the run is done
        self.stack = Adw.ViewStack(vexpand=True)
        self.switcher = Adw.InlineViewSwitcher(stack=self.stack, visible=False,
                                               halign=Gtk.Align.CENTER)
        main.append(self.switcher)
        main.append(self.stack)
        self.stack.add_titled_with_icon(self.build_activity(), "activity", "Activity",
                                        "utilities-terminal-symbolic")
        self.stack.add_titled_with_icon(self.build_summary(), "summary", "Summary",
                                        "view-list-bullet-symbolic")

        # Narrow windows: the sidebar slides over the content instead
        bp = Adw.Breakpoint.new(Adw.BreakpointCondition.parse("max-width: 720sp"))
        bp.add_setter(self.split, "collapsed", True)
        bp.add_setter(self.sidebar_btn, "active", False)
        self.add_breakpoint(bp)

        for name, cb in (("copy-log", lambda *_: self.copy_log(False)),
                         ("copy-problems", lambda *_: self.copy_log(True))):
            act = Gio.SimpleAction.new(name, None)
            act.connect("activate", cb)
            self.add_action(act)
        keys = Gtk.ShortcutController(scope=Gtk.ShortcutScope.MANAGED)
        keys.add_shortcut(Gtk.Shortcut.new(Gtk.ShortcutTrigger.parse_string("<Control>w"),
                                           Gtk.CallbackAction.new(self.on_close_key)))
        keys.add_shortcut(Gtk.Shortcut.new(Gtk.ShortcutTrigger.parse_string("F9"),
                                           Gtk.CallbackAction.new(self.on_f9)))
        self.add_controller(keys)
        self.connect("close-request", self.on_close_request)
        GLib.timeout_add_seconds(1, self.tick)

    # ── Activity page ────────────────────────────────────────────────────────
    def build_activity(self):
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        bar = Gtk.Box(spacing=8)
        self.chips = {}
        first = None
        for key, label, cls in (("all", "All", None), ("ok", "Done", "ok"),
                                ("warn", "Warnings", "warn"), ("error", "Errors", "error"),
                                ("run", "Commands", None)):
            chip = Gtk.ToggleButton(group=first)
            first = first or chip
            chip.add_css_class("chip")
            if cls:
                chip.add_css_class(cls)
            inner = Gtk.Box(spacing=6)
            inner.append(Gtk.Label(label=label))
            count = Gtk.Label(label="", visible=key in self.counts)
            count.add_css_class("count")
            inner.append(count)
            chip.set_child(inner)
            chip.connect("toggled", self.on_filter, key)
            self.chips[key] = count
            bar.append(chip)
        self.first_chip = first
        bar.append(Gtk.Box(hexpand=True))
        self.search = Gtk.SearchEntry(placeholder_text="Find in activity", width_chars=18)
        self.search.connect("search-changed", lambda *_: self.refilter())
        bar.append(self.search)
        follow = Gtk.ToggleButton(icon_name="go-bottom-symbolic", active=True,
                                  tooltip_text="Follow new activity")
        follow.connect("toggled", lambda b: self.set_follow(b.get_active()))
        bar.append(follow)
        self.follow_btn = follow
        wrap = Gtk.ScrolledWindow(child=bar, vscrollbar_policy=Gtk.PolicyType.NEVER,
                                  hscrollbar_policy=Gtk.PolicyType.AUTOMATIC)
        box.append(wrap)

        self.buffer = Gtk.TextBuffer()
        for tag, props in (
            ("time", {"foreground": "#938F99"}),
            ("info", {"foreground": "#E6E0E9"}),
            ("ok", {"foreground": "#8BD5A5"}),
            ("warn", {"foreground": "#FFB95C"}),
            ("error", {"foreground": "#F2B8B5", "weight": 700}),
            ("dry", {"foreground": "#CCC2DC"}),
            ("run", {"foreground": "#D0BCFF"}),
            ("out", {"foreground": "#A9A4B0"}),
            ("section", {"foreground": "#D0BCFF", "weight": 700,
                         "pixels-above-lines": 10}),
        ):
            self.buffer.create_tag(tag, **props)
        self.text = Gtk.TextView(buffer=self.buffer, editable=False, cursor_visible=False,
                                 monospace=True, wrap_mode=Gtk.WrapMode.WORD_CHAR,
                                 top_margin=8, bottom_margin=8, left_margin=10,
                                 right_margin=10)
        self.text.add_css_class("log-view")
        self.text.update_property([Gtk.AccessibleProperty.LABEL], ["Activity log"])
        self.log_scroll = Gtk.ScrolledWindow(child=self.text, vexpand=True)
        self.log_scroll.get_vadjustment().connect("value-changed", self.on_scrolled)
        box.append(self.log_scroll)
        self.end_mark = self.buffer.create_mark("end", self.buffer.get_end_iter(), False)
        self.first_chip.set_active(True)
        return box

    # ── Summary page ─────────────────────────────────────────────────────────
    def build_summary(self):
        page = Adw.PreferencesPage()
        head = Adw.PreferencesGroup()
        top = Gtk.Box(spacing=16, margin_bottom=6)
        self.sum_icon = Gtk.Image(icon_name="object-select-symbolic", pixel_size=48,
                                  valign=Gtk.Align.START)
        self.sum_icon.add_css_class("summary-icon")
        texts = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6, hexpand=True)
        self.sum_head = Gtk.Label(xalign=0, wrap=True)
        self.sum_head.add_css_class("title-2")
        self.sum_body = Gtk.Label(xalign=0, wrap=True, selectable=True,
                                  wrap_mode=Pango.WrapMode.WORD_CHAR)
        self.sum_body.add_css_class("dim-label")
        texts.append(self.sum_head)
        texts.append(self.sum_body)
        top.append(self.sum_icon)
        top.append(texts)
        head.add(top)
        page.add(head)
        self.items_page = page
        self.item_groups = []
        self.item_count = 0
        self.score_group = None
        self.score = {"ok": 0, "no": 0}
        return page

    # ── Event handling ───────────────────────────────────────────────────────
    def handle(self, line):
        parts = [unescape(p) for p in line.split("\t")]
        kind, args = parts[0], parts[1:] + [""] * 4
        if kind == "MODE":
            self.title_widget.set_subtitle(args[0])
        elif kind == "PLAN":
            self.add_section(args[0], args[1])
        elif kind == "SECTION":
            self.start_section(args[0], args[1])
        elif kind == "LOG":
            self.add_line(args[0] if args[0] in LEVELS else "info", args[1])
        elif kind == "NOTICE":
            self.add_notice(args[0], args[1])
        elif kind == "ASK":
            self.ask(args[0], args[1], args[2], args[3])
        elif kind == "SUMMARY":
            self.show_summary(args[0], args[1])
        elif kind == "ITEMS":
            self.clear_items()
        elif kind == "ITEM":
            self.add_item(args[0], args[1], args[2])
        elif kind == "SCORE":
            self.add_score(args[0], args[1], args[2], args[3])
        elif kind == "END":
            self.end(args[0], args[1])

    def add_section(self, num, title):
        if num in self.sections:
            return
        row = SectionRow(num, title)
        self.sections[num] = row
        self.order.append(num)
        self.section_list.append(row)
        self.update_progress()

    def close_current(self):
        if self.current and self.current in self.sections:
            self.sections[self.current].set_status(self.section_level)
            started = self.section_started.get(self.current)
            if started:
                self.section_durations.append(time.monotonic() - started)

    def start_section(self, num, title):
        self.close_current()
        if num not in self.sections:
            self.add_section(num, title)
        # Sections run in plan order; one that never started was not applicable here.
        for earlier in self.order[: self.order.index(num)]:
            if self.sections[earlier].status == "pending":
                self.sections[earlier].set_status("skipped")
        row = self.sections[num]
        row.title.set_label(title)
        row.set_status("running")
        self.current, self.section_level = num, "ok"
        self.section_started[num] = time.monotonic()
        self.section_label.set_label(f"Section {num} · {title}")
        self.add_line("section", f"Section {num}: {title}")
        self.update_progress()

    def done_count(self):
        return sum(1 for r in self.sections.values() if r.status in FINAL)

    def update_progress(self):
        total = len(self.order)
        if not total:
            return
        done = self.done_count()
        position = done + (1 if self.current and not self.finished else 0)
        frac = 1.0 if self.finished and self.exit_code == "0" else min(done / total, 0.99)
        self.progress.set_fraction(frac)
        if self.finished:
            self.progress.set_text(f"{done} of {total} sections · {int(frac * 100)}%")
        else:
            self.progress.set_text(f"Step {position} of {total} · {int(frac * 100)}%")

    def add_line(self, level, text):
        if level != "section":
            counted = LEVELS[level][2]
            if counted:
                self.counts[counted] += 1
                self.chips[counted].set_label(str(self.counts[counted]))
            if level == "warn" and self.section_level == "ok":
                self.section_level = "warn"
            elif level == "error":
                self.section_level = "error"
            if level not in ("out",):
                self.step_label.set_label(text.split("\n")[0])
        entry = (level, time.strftime("%H:%M:%S"), text)
        self.lines.append(entry)
        if len(self.lines) > MAX_LINES:
            del self.lines[: len(self.lines) - MAX_LINES]
        if self.matches(entry):
            self.write(entry)

    def matches(self, entry):
        level, _, text = entry
        if self.filter == "run" and level not in ("run", "dry", "out", "section"):
            return False
        if self.filter in ("ok", "warn", "error") and level not in (self.filter, "section"):
            return False
        q = self.search.get_text().strip().lower()
        return not q or q in text.lower()

    def write(self, entry):
        level, ts, text = entry
        end = self.buffer.get_end_iter()
        self.buffer.insert_with_tags_by_name(end, ts + "  ", "time")
        prefix = "" if level == "section" else LEVELS[level][0]
        label = f"{prefix:<5} " if prefix else ("      │ " if level == "out" else "")
        self.buffer.insert_with_tags_by_name(self.buffer.get_end_iter(),
                                             label + text + "\n",
                                             "section" if level == "section" else LEVELS[level][1])
        if self.follow:
            self.buffer.move_mark(self.end_mark, self.buffer.get_end_iter())
            self.text.scroll_mark_onscreen(self.end_mark)

    def refilter(self):
        self.buffer.set_text("")
        for entry in self.lines:
            if self.matches(entry):
                self.write(entry)

    def on_filter(self, button, key):
        if button.get_active():
            self.filter = key
            self.refilter()

    def set_follow(self, on):
        self.follow = on
        if on:
            self.buffer.move_mark(self.end_mark, self.buffer.get_end_iter())
            self.text.scroll_mark_onscreen(self.end_mark)

    def on_scrolled(self, adj):
        # Scrolling up to read pauses following; scrolling back to the end resumes it.
        at_end = adj.get_value() + adj.get_page_size() >= adj.get_upper() - 4
        if self.follow != at_end and adj.get_upper() > adj.get_page_size():
            self.follow_btn.set_active(at_end)

    def add_notice(self, level, text):
        box = Gtk.Box(spacing=12)
        box.add_css_class("notice")
        box.add_css_class(level)
        icon = {"warning": "dialog-warning-symbolic",
                "error": "dialog-error-symbolic"}.get(level, "dialog-information-symbolic")
        box.append(Gtk.Image(icon_name=icon, pixel_size=20, valign=Gtk.Align.START))
        box.append(Gtk.Label(label=text, xalign=0, wrap=True, hexpand=True,
                             wrap_mode=Pango.WrapMode.WORD_CHAR))
        close = Gtk.Button(icon_name="window-close-symbolic", valign=Gtk.Align.START,
                           tooltip_text="Dismiss")
        close.add_css_class("flat")
        close.connect("clicked", lambda *_: self.notices.remove(box))
        box.append(close)
        self.notices.append(box)
        self.add_line({"warning": "warn", "error": "error"}.get(level, "info"), text)

    # ── Questions ────────────────────────────────────────────────────────────
    def ask(self, ask_id, kind, default, text):
        self.pending_ask = (ask_id, kind)
        self.q_label.set_label(text)
        is_input = kind == "input"
        self.q_entry.set_visible(is_input)
        self.q_no.set_visible(not is_input)
        self.q_yes.set_label("_OK" if is_input else "_Yes")
        if is_input:
            self.q_entry.set_text(default)
            self.question.set_reveal_child(True)
            self.q_entry.grab_focus()
        else:
            self.question.set_reveal_child(True)
            (self.q_no if default == "no" else self.q_yes).grab_focus()
        self.step_label.set_label("Waiting for your answer")
        self.add_line("info", f"Question: {text}")
        self.asks += 1
        self.present()
        self.dump_state()

    def answer(self, value):
        if not self.pending_ask:
            return
        ask_id, kind = self.pending_ask
        if kind == "input":
            value = self.q_entry.get_text()
        self.pending_ask = None
        self.question.set_reveal_child(False)
        self.add_line("info", f"Answer: {value if value != '' else '(blank)'}")
        self.send("ANSWER", ask_id, value)
        self.dump_state()

    # ── Summary ──────────────────────────────────────────────────────────────
    def show_summary(self, headline, details):
        self.sum_head.set_label(headline)
        self.sum_body.set_label(details)
        self.switcher.set_visible(True)
        self.stack.set_visible_child_name("summary")

    def clear_items(self):
        for g in self.item_groups:
            self.items_page.remove(g)
        self.item_groups = []
        self.item_count = 0

    def add_score(self, state, label, detail, fix):
        if self.score_group is None:
            self.score_group = Adw.PreferencesGroup(
                title="Protection now", description="Checked on the live system")
            self.items_page.add(self.score_group)
            if not self.sum_head.get_label():  # --score: no run summary
                self.sum_head.set_label("Protection now")
                self.switcher.set_visible(True)
                self.stack.set_visible_child_name("summary")
        icon, cls = {"ok": ("object-select-symbolic", "st-ok"),
                     "no": ("dialog-error-symbolic", "st-error"),
                     "info": ("dialog-information-symbolic", "st-running")}.get(
            state, ("media-skip-forward-symbolic", "st-pending"))
        text = detail if state == "ok" or not fix else f"{detail}\nFix: {fix}"
        row = Adw.ActionRow(title=GLib.markup_escape_text(label),
                            subtitle=GLib.markup_escape_text(text), subtitle_lines=0)
        image = Gtk.Image(icon_name=icon, pixel_size=16)
        image.add_css_class(cls)
        row.add_prefix(image)
        self.score_group.add(row)
        if state in self.score:
            self.score[state] += 1

    def add_item(self, priority, section, text):
        titles = {"HIGH": "Needs attention", "MEDIUM": "Recommended", "LOW": "Optional",
                  "DONE": "Resolved this run"}
        group = next((g for g in self.item_groups if g.prio == priority), None)
        if group is None:
            group = Adw.PreferencesGroup(title=titles.get(priority, priority))
            group.prio = priority
            order = list(titles)
            self.item_groups.append(group)
            self.item_groups.sort(key=lambda g: order.index(g.prio) if g.prio in order else 9)
            for g in self.item_groups:
                if g.get_parent():
                    self.items_page.remove(g)
            for g in self.item_groups:
                self.items_page.add(g)
        row = Adw.ActionRow(title=GLib.markup_escape_text(text),
                            subtitle=f"Section {section.lstrip('S')}" if section else "",
                            title_lines=0)
        badge = Gtk.Label(label=priority.title(), valign=Gtk.Align.CENTER)
        badge.add_css_class("prio")
        badge.add_css_class(priority)
        row.add_prefix(badge)
        copy = Gtk.Button(icon_name="edit-copy-symbolic", valign=Gtk.Align.CENTER,
                          tooltip_text="Copy")
        copy.add_css_class("flat")
        copy.connect("clicked", lambda *_: self.copy_text(text, "Copied"))
        row.add_suffix(copy)
        group.add(row)
        self.item_count += 1

    def end(self, code, message):
        self.close_current()
        if code == "0":
            for row in self.sections.values():
                if row.status == "pending":
                    row.set_status("skipped")
        self.finished, self.exit_code = True, code
        self.current = None
        self.spinner.set_spinning(False)
        self.spinner.set_visible(False)
        self.status_icon.set_visible(True)
        self.sum_icon.remove_css_class("ok")
        if code == "0":
            state, icon = ("warn", "dialog-warning-symbolic") if self.counts["error"] or \
                self.counts["warn"] else ("ok", "object-select-symbolic")
            self.section_label.set_label("Finished")
        elif code == "130":
            state, icon = "warn", "media-playback-stop-symbolic"
            self.section_label.set_label("Stopped")
        else:
            state, icon = "error", "dialog-error-symbolic"
            self.section_label.set_label("Stopped by an error")
            self.progress.add_css_class("failed")
        self.status_icon.set_from_icon_name(icon)
        self.status_icon.add_css_class(f"st-{state}")
        self.sum_icon.set_from_icon_name(icon)
        self.sum_icon.add_css_class(state)
        if message:
            self.step_label.set_label(message)
        if not self.sum_head.get_label():
            self.sum_head.set_label(self.section_label.get_label())
            self.sum_body.set_label(message)
        self.switcher.set_visible(True)
        if code != "0":
            self.stack.set_visible_child_name("activity")
        self.stop_btn.set_label("_Close")
        self.stop_btn.remove_css_class("destructive-action")
        self.stop_btn.add_css_class("suggested-action")
        self.stop_btn.set_tooltip_text("Close this window (Ctrl+W)")
        self.stop_btn.grab_focus()
        self.question.set_reveal_child(False)
        self.pending_ask = None
        self.update_progress()
        self.tick()
        self.dump_state()

    def dump_state(self):
        """Test hook: with FH_GUI_STATE set, write what the window shows to that file."""
        path = os.environ.get("FH_GUI_STATE")
        if not path:
            return
        asking = f"{self.pending_ask[1]}|{self.q_label.get_label()}" if self.pending_ask else ""
        with open(path + ".tmp", "w", encoding="utf-8") as fh:
            print(f"exit={self.exit_code if self.finished else ''}", file=fh)
            print(f"sections={len(self.order)} done={self.done_count()}", file=fh)
            print(f"ok={self.counts['ok']} warn={self.counts['warn']} "
                  f"error={self.counts['error']} lines={len(self.lines)}", file=fh)
            print(f"items={self.item_count}", file=fh)
            print(f"score_ok={self.score['ok']} score_no={self.score['no']}", file=fh)
            print(f"headline={self.sum_head.get_label()}", file=fh)
            print(f"asks={self.asks}", file=fh)
            print(f"asking={asking}", file=fh)
        os.replace(path + ".tmp", path)

    def tick(self):
        if self.finished and getattr(self, "_clock_frozen", False):
            return True
        text = fmt_clock(time.monotonic() - self.started)
        remaining = len(self.order) - self.done_count()
        if not self.finished and self.section_durations and remaining > 0:
            per = sum(self.section_durations) / len(self.section_durations)
            mins = max(1, round(per * remaining / 60))
            text += f"\nabout {mins} min left"
        self.clock_label.set_label(text)
        self._clock_frozen = self.finished
        return True

    # ── Closing, copying, output ─────────────────────────────────────────────
    def request_close(self):
        if self.finished or self.exit_code is not None:
            self.get_application().quit()
            return
        dialog = Adw.AlertDialog(
            heading="Stop the run?",
            body="The current step finishes first. Changes made so far stay in place; "
                 "undo them with: sudo ./fedora-harden.sh --rollback")
        dialog.add_response("keep", "_Keep running")
        dialog.add_response("stop", "_Stop")
        dialog.set_response_appearance("stop", Adw.ResponseAppearance.DESTRUCTIVE)
        dialog.set_default_response("keep")
        dialog.set_close_response("keep")
        dialog.connect("response", self.on_stop_response)
        dialog.present(self)

    def on_stop_response(self, _dialog, response):
        if response != "stop" or self.cancel_sent:
            return
        self.cancel_sent = True
        self.stop_btn.set_sensitive(False)
        self.section_label.set_label("Stopping…")
        self.step_label.set_label("Waiting for the current step to finish")
        if self.pending_ask:
            self.question.set_reveal_child(False)
            self.pending_ask = None
        self.send("CANCEL")

    def on_close_request(self, *_):
        if self.finished:
            return False
        self.request_close()
        return True

    def on_close_key(self, *_):
        self.request_close()
        return True

    def on_f9(self, *_):
        self.sidebar_btn.set_active(not self.sidebar_btn.get_active())
        return True

    def copy_text(self, text, toast):
        Gdk.Display.get_default().get_clipboard().set_content(
            Gdk.ContentProvider.new_for_bytes("text/plain;charset=utf-8",
                                              GLib.Bytes.new(text.encode())))
        self.toasts.add_toast(Adw.Toast(title=toast, timeout=2))

    def copy_log(self, problems_only):
        keep = ("warn", "error", "section") if problems_only else None
        text = "\n".join(f"{ts}  {LEVELS[lv][0] if lv in LEVELS else ''} {t}".rstrip()
                         for lv, ts, t in self.lines if keep is None or lv in keep)
        self.copy_text(text, "Problems copied" if problems_only else "Activity log copied")

    def send(self, *fields):
        try:
            sys.stdout.write("\t".join(escape(str(f)) for f in fields) + "\n")
            sys.stdout.flush()
        except (BrokenPipeError, OSError):
            pass  # the script has exited; the window stays for reading


class HardenApp(Adw.Application):
    def __init__(self):
        super().__init__(application_id=None, flags=Gio.ApplicationFlags.NON_UNIQUE)
        self.win = None

    def do_activate(self):
        Adw.StyleManager.get_default().set_color_scheme(Adw.ColorScheme.FORCE_DARK)
        css = Gtk.CssProvider()
        css.load_from_string(CSS)
        Gtk.StyleContext.add_provider_for_display(
            Gdk.Display.get_default(), css, Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION + 1)
        self.win = HardenWindow(self)
        self.win.present()
        self.stream = Gio.DataInputStream.new(UnixInputStream.new(0, False))
        self.read_next()
        self.win.send("READY")

    def read_next(self):
        self.stream.read_line_async(GLib.PRIORITY_DEFAULT, None, self.on_line)

    def on_line(self, stream, result):
        try:
            data, _ = stream.read_line_finish_utf8(result)
        except GLib.Error:
            data = None
        if data is None:  # the script exited
            if not self.win.finished:
                self.win.end("1", "The run ended without saying how; see the log.")
            return
        if data:
            self.win.handle(data)
        self.read_next()


if __name__ == "__main__":
    sys.exit(HardenApp().run([sys.argv[0]]))
