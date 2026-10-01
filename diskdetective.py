"""Disk Detective - see what is using your disk space, what it is, and whether it is safe to delete.

It only ever *moves* things to the Recycle Bin, and only items rated "safe to delete", and only when you confirm.
"""
import ctypes
import json
import os
import shutil
import stat
import subprocess
import sys
import threading
import time
import tkinter as tk
import traceback
import urllib.parse
import webbrowser
from tkinter import filedialog, messagebox, ttk
from tkinter import font as tkfont

import cleaner
import knowledge as K
from appicon import ICON_PNG_B64
from scanner import (Scanner, find_cleanup_candidates, fmt_size, is_cloud_only, is_link, long_path, rescan_path,
                     under)
from treemap import squarify

APP = 'Disk Detective'
MAX_ROWS = 500          # rows shown per folder; the rest are summed into one "smaller items" row
MAX_BLOCKS = 70         # blocks drawn in the size map
DUMMY = '\x00dummy'     # placeholder child that makes the expander arrow show
MORE = '\x00more'

THEMES = {
    'light': dict(bg='#f0f0f0', panel='#ffffff', fg='#1a1a1a', muted='#666666', border='#c8c8c8', head='#e6e6e6',
                  sel_bg='#0078d7', sel_fg='#ffffff', detail='#fafafa', canvas='#f4f4f4'),
    'dark': dict(bg='#1e2227', panel='#262b32', fg='#e8eaed', muted='#9aa0a6', border='#3b424b', head='#2f353d',
                 sel_bg='#3a6ea5', sel_fg='#ffffff', detail='#23282e', canvas='#1e2227'),
}
LEVEL_COLORS = {        # row tint, text colour, badge colour, size-map colour
    'light': {
        K.SAFE: dict(bg='#e3f4e7', fg='#14632b', badge='#1f9d47', map='#9bd8a9'),
        K.CAUTION: dict(bg='#fff3d1', fg='#7a5200', badge='#c98200', map='#f6d58a'),
        K.DANGER: dict(bg='#fde6e6', fg='#8f1d1d', badge='#d33a3a', map='#f1a5a5'),
        K.PERSONAL: dict(bg='#e6eefb', fg='#1d4b8f', badge='#3b78d8', map='#a9c1f0'),
        K.UNKNOWN: dict(bg='#f2f2f2', fg='#555555', badge='#7d7d7d', map='#d4d4d4'),
    },
    'dark': {
        K.SAFE: dict(bg='#1d3a2a', fg='#8fe0a8', badge='#2b9a56', map='#2f6e47'),
        K.CAUTION: dict(bg='#3b3318', fg='#f2d27a', badge='#b97a00', map='#7d6118'),
        K.DANGER: dict(bg='#3d2227', fg='#ff9d9d', badge='#c93434', map='#843a3f'),
        K.PERSONAL: dict(bg='#222f48', fg='#9dbdf5', badge='#3b78d8', map='#38548a'),
        K.UNKNOWN: dict(bg='#2c3035', fg='#b0b4b8', badge='#6f7377', map='#4a4e53'),
    },
}
LINK_INFO = K.Info(K.UNKNOWN, 'Link to another folder',
                   'A junction or symbolic link. It is not followed, so its target is not counted twice.',
                   'Leave it. Deleting a link does not delete its target, but programs may rely on it.')
TAB_TREE, TAB_MAP, TAB_BIG, TAB_WINS = range(4)


class Meta:
    __slots__ = ('path', 'name', 'is_dir', 'size', 'files', 'dirs', 'info', 'node', 'kind', 'denied', 'extra')

    def __init__(self, path, name, is_dir, size, files, info, node=None, kind='item', dirs=0, denied=False, extra=0):
        self.path, self.name, self.is_dir, self.size, self.files, self.info = path, name, is_dir, size, files, info
        self.node, self.kind, self.dirs, self.denied, self.extra = node, kind, dirs, denied, extra


# ------------------------------------------------------------------ helpers
def is_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def share_bar(frac):
    """'42%  ▆▆▆▆' - percentage first so the numbers line up, then a bar sized to the share."""
    if frac >= 0.995:
        return '100%  ' + '\u2586' * 10
    if frac < 0.01:
        return ' <1%'
    return f'{frac * 100:.0f}%'.rjust(4) + '  ' + '\u2586' * max(1, int(round(frac * 10)))


def shorten(text, limit):
    return text if len(text) <= limit else text[:limit // 2 - 1] + '\u2026' + text[-(limit // 2):]


def drive_list():
    out = []
    try:
        mask = ctypes.windll.kernel32.GetLogicalDrives()
        out = [f'{chr(65 + i)}:\\' for i in range(26) if mask & (1 << i)]
    except Exception:
        pass
    out.append(os.path.expanduser('~'))
    return out


def safe_candidates(sc):
    """Quick-wins list: folders rated safe, minus any that hold saved logins, cookies, bookmarks or keys."""
    keep, held = [], []
    for node in find_cleanup_candidates(sc, K.classify_dir, K.SAFE):
        (held if cleaner.find_sensitive(node.path()) else keep).append(node)
    sc.held_back = held
    return keep


def settings_file():
    return os.path.join(os.environ.get('APPDATA', os.path.expanduser('~')), 'DiskDetective', 'settings.json')


def load_settings():
    try:
        with open(settings_file(), encoding='utf-8') as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return {}


def save_settings(data):
    try:
        os.makedirs(os.path.dirname(settings_file()), exist_ok=True)
        with open(settings_file(), 'w', encoding='utf-8') as fh:
            json.dump(data, fh)
    except OSError:
        pass


def system_theme():
    try:
        import winreg
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r'Software\Microsoft\Windows\CurrentVersion\Themes\Personalize')
        return 'light' if winreg.QueryValueEx(key, 'AppsUseLightTheme')[0] else 'dark'
    except Exception:
        return 'light'


class DiskDetective:
    def __init__(self, root, start_path=None):
        self.root = root
        self.scanner = None
        self.scan_done = False
        self.busy = False
        self.expected = None
        self.current = None
        self.selection = []
        self.metas = {}
        self.sort_state = {}
        self.heading_text = {}
        self.map_node = None
        self.map_blocks = {}
        self.map_hover = None
        self._map_after = None
        self.settings = load_settings()

        root.title(APP)
        try:
            root.iconphoto(True, tk.PhotoImage(data=ICON_PNG_B64))
        except tk.TclError:
            pass
        width = min(1240, root.winfo_screenwidth() - 60)
        height = min(850, root.winfo_screenheight() - 110)
        root.geometry(f'{width}x{height}+{(root.winfo_screenwidth() - width) // 2}+{max(0, (root.winfo_screenheight() - height) // 2 - 20)}')
        root.minsize(900, 580)
        self.scale = max(1.0, root.winfo_fpixels('1i') / 96)
        for name in ('TkDefaultFont', 'TkTextFont', 'TkMenuFont', 'TkHeadingFont'):
            try:
                tkfont.nametofont(name).configure(family='Segoe UI', size=10)
            except tk.TclError:
                pass
        self.style = ttk.Style(root)
        self._icons()
        self._build()
        self.apply_theme(self.settings.get('theme') or system_theme())
        root.report_callback_exception = self._on_error

        default = start_path or (os.environ.get('SystemDrive', 'C:') + '\\')
        self.path_var.set(default)
        self._update_drive_info()
        self._show_welcome()
        if start_path:
            root.after(200, self.start_scan)

    # ------------------------------------------------------------------ theme
    def apply_theme(self, name):
        self.theme_name = name
        t, lc, st, root = THEMES[name], LEVEL_COLORS[name], self.style, self.root
        self.t, self.lc = t, lc
        st.theme_use('clam' if name == 'dark' or 'vista' not in st.theme_names() else 'vista')
        if name == 'dark' or st.theme_use() == 'clam':
            st.configure('.', background=t['bg'], foreground=t['fg'], fieldbackground=t['panel'], bordercolor=t['border'],
                         lightcolor=t['bg'], darkcolor=t['bg'], troughcolor=t['panel'], insertcolor=t['fg'])
            st.configure('TButton', background=t['head'], foreground=t['fg'], bordercolor=t['border'], padding=(10, 4))
            st.map('TButton', background=[('active', t['border']), ('disabled', t['bg'])],
                   foreground=[('disabled', t['muted'])])
            st.configure('TNotebook', background=t['bg'], bordercolor=t['border'])
            st.configure('TNotebook.Tab', background=t['head'], foreground=t['fg'], padding=(12, 5), bordercolor=t['border'])
            st.map('TNotebook.Tab', background=[('selected', t['panel'])], foreground=[('selected', t['fg'])])
            st.configure('TCombobox', fieldbackground=t['panel'], background=t['head'], foreground=t['fg'],
                         arrowcolor=t['fg'], bordercolor=t['border'])
            st.map('TCombobox', fieldbackground=[('readonly', t['panel'])], foreground=[('readonly', t['fg'])])
            for sb in ('Vertical.TScrollbar', 'Horizontal.TScrollbar'):
                st.configure(sb, background=t['head'], troughcolor=t['bg'], bordercolor=t['border'], arrowcolor=t['fg'],
                             lightcolor=t['head'], darkcolor=t['head'])
                # clam paints a full-length ("disabled") scrollbar light grey unless told otherwise
                st.map(sb, background=[('disabled', t['bg']), ('pressed', t['border']), ('active', t['border'])],
                       arrowcolor=[('disabled', t['muted'])], lightcolor=[('disabled', t['bg'])], darkcolor=[('disabled', t['bg'])])
            st.configure('Horizontal.TProgressbar', background='#2fb85a', troughcolor=t['panel'], bordercolor=t['border'])
            st.configure('Treeview.Heading', background=t['head'], foreground=t['fg'], bordercolor=t['border'], relief='flat')
            st.map('Treeview.Heading', background=[('active', t['border'])])
            st.map('Treeview', background=[('selected', t['sel_bg'])], foreground=[('selected', t['sel_fg'])])
            root.option_add('*TCombobox*Listbox.background', t['panel'])
            root.option_add('*TCombobox*Listbox.foreground', t['fg'])
            root.option_add('*TCombobox*Listbox.selectBackground', t['sel_bg'])
        st.configure('Treeview', rowheight=int(26 * self.scale), font=('Segoe UI', 10), background=t['panel'],
                     fieldbackground=t['panel'], foreground=t['fg'])
        st.configure('Treeview.Heading', font=('Segoe UI', 9, 'bold'))
        st.configure('Accent.TButton', font=('Segoe UI', 10, 'bold'), padding=(18, 5))
        st.configure('Clean.TButton', font=('Segoe UI', 10, 'bold'))
        st.configure('Title.TLabel', font=('Segoe UI', 15, 'bold'))
        st.configure('Muted.TLabel', foreground=t['muted'])
        st.configure('Bold.TLabel', font=('Segoe UI', 10, 'bold'))
        root.configure(bg=t['bg'])
        for tree in (self.tree, self.big, self.wins):
            for level, c in lc.items():
                tree.tag_configure(level, background=c['bg'], foreground=t['fg'])
        d = self.detail
        d.configure(bg=t['detail'], fg=t['fg'], insertbackground=t['fg'], highlightbackground=t['border'])
        d.tag_configure('path', foreground=t['muted'])
        d.tag_configure('note', foreground='#e0a030' if name == 'dark' else '#8f5b00')
        for level, c in lc.items():
            d.tag_configure('badge_' + level, background=c['badge'], foreground='white')
            self.legend[level].configure(bg=c['bg'], fg=c['fg'])
        self.menu.configure(bg=t['panel'], fg=t['fg'], activebackground=t['sel_bg'], activeforeground=t['sel_fg'])
        self.map_canvas.configure(bg=t['canvas'])
        self.theme_btn.config(text='\u2600 Light mode' if name == 'dark' else '\u263E Dark mode')
        self._dark_titlebar(name == 'dark')
        self._draw_map()

    def toggle_theme(self):
        name = 'light' if self.theme_name == 'dark' else 'dark'
        self.apply_theme(name)
        self.settings['theme'] = name
        save_settings(self.settings)

    def _dark_titlebar(self, on):
        try:
            self.root.update_idletasks()
            hwnd = ctypes.windll.user32.GetParent(self.root.winfo_id())
            value = ctypes.c_int(1 if on else 0)
            for attr in (20, 19):
                if ctypes.windll.dwmapi.DwmSetWindowAttribute(hwnd, attr, ctypes.byref(value), 4) == 0:
                    break
        except Exception:
            pass

    # --------------------------------------------------------------------- UI
    def _icons(self):
        zoom = 2 if self.scale >= 1.5 else 1

        def make(paint):
            img = tk.PhotoImage(width=16, height=16)
            paint(img)
            return img.zoom(zoom) if zoom > 1 else img

        def folder(img):
            img.put('#d99a00', to=(1, 3, 7, 5))
            img.put('#f7c948', to=(1, 5, 15, 14))
            img.put('#ffe08a', to=(2, 6, 14, 8))

        def file(img):
            img.put('#8a9199', to=(3, 1, 13, 15))
            img.put('#ffffff', to=(4, 2, 12, 14))
            for y in (5, 7, 9, 11):
                img.put('#b4bac1', to=(5, y, 11, y + 1))

        self.icon_dir, self.icon_file = make(folder), make(file)

    def _build(self):
        root = self.root
        top = ttk.Frame(root, padding=(14, 10, 14, 2))
        top.pack(fill='x')
        ttk.Label(top, text='Disk Detective', style='Title.TLabel').grid(row=0, column=0, sticky='w')
        ttk.Label(top, text='See what takes up space, what it is, and whether it is safe to delete.',
                  style='Muted.TLabel').grid(row=0, column=1, columnspan=3, sticky='w', padx=(14, 0))
        self.theme_btn = ttk.Button(top, text='', command=self.toggle_theme)
        self.theme_btn.grid(row=0, column=4, columnspan=2, sticky='e')
        self.path_var = tk.StringVar()
        self.combo = ttk.Combobox(top, textvariable=self.path_var, values=drive_list(), font=('Segoe UI', 11))
        self.combo.grid(row=1, column=0, columnspan=2, sticky='ew', pady=(10, 0), padx=(0, 8), ipady=2)
        self.combo.bind('<Return>', lambda e: self.start_scan())
        self.combo.bind('<<ComboboxSelected>>', lambda e: self._update_drive_info())
        self.combo.bind('<FocusOut>', lambda e: self._update_drive_info())
        ttk.Button(top, text='Browse\u2026', command=self.browse).grid(row=1, column=2, pady=(10, 0), padx=2)
        self.scan_btn = ttk.Button(top, text='Scan', style='Accent.TButton', command=self.start_scan)
        self.scan_btn.grid(row=1, column=3, pady=(10, 0), padx=2)
        self.stop_btn = ttk.Button(top, text='Stop', command=self.stop_scan, state='disabled')
        self.stop_btn.grid(row=1, column=4, pady=(10, 0), padx=2)
        if not is_admin():
            ttk.Button(top, text='\U0001F6E1 Run as administrator', command=self.elevate).grid(row=1, column=5, pady=(10, 0), padx=(10, 0))
        top.columnconfigure(1, weight=1)
        self.drive_lbl = ttk.Label(top, text='', style='Muted.TLabel')
        self.drive_lbl.grid(row=2, column=0, columnspan=2, sticky='w', pady=(4, 0))
        self.drive_bar = ttk.Progressbar(top, maximum=100, length=220)
        self.drive_bar.grid(row=2, column=2, columnspan=4, sticky='e', pady=(4, 0))

        legend = ttk.Frame(root, padding=(14, 6, 14, 2))
        legend.pack(fill='x')
        ttk.Label(legend, text='Verdicts:  ', style='Muted.TLabel').pack(side='left')
        self.legend = {}
        for level, text in ((K.SAFE, 'Safe to delete'), (K.CAUTION, 'Be careful'), (K.DANGER, "Don't delete"),
                            (K.PERSONAL, 'Your files'), (K.UNKNOWN, 'Unknown')):
            lbl = tk.Label(legend, text=f' {K.LEVEL_LABEL[level]} ', font=('Segoe UI', 9, 'bold'))
            lbl.pack(side='left', padx=(0, 6))
            self.legend[level] = lbl

        # footer widgets are packed first so the expanding pane below can never squeeze them out
        ttk.Label(root, text='Advice is based on built-in rules of thumb, not a guarantee. When in doubt, don\'t delete. '
                  'Cleaning only moves safe-rated items to the Recycle Bin.', style='Muted.TLabel',
                  padding=(14, 0, 14, 8)).pack(side='bottom', fill='x')
        bar = ttk.Frame(root, padding=(14, 4, 14, 4))
        bar.pack(side='bottom', fill='x')
        self.status = tk.StringVar(value='Ready.')
        ttk.Label(bar, textvariable=self.status).pack(side='left')
        self.progress = ttk.Progressbar(bar, length=200, maximum=100)
        self.progress.pack(side='right')

        paned = ttk.PanedWindow(root, orient='vertical')
        paned.pack(fill='both', expand=True, padx=14, pady=(4, 0))
        self.nb = ttk.Notebook(paned)
        paned.add(self.nb, weight=4)
        self.nb.bind('<<NotebookTabChanged>>', self._on_tab)

        tab1 = ttk.Frame(self.nb)
        self.nb.add(tab1, text='  Folders & files  ')
        self.tree = self._make_tree(tab1, 'tree headings', [
            ('size', 'Size', 90, 'e'), ('share', 'Share of parent', 140, 'w'), ('files', 'Files', 90, 'e'),
            ('verdict', 'Safe to delete?', 160, 'w'), ('what', 'What it is', 330, 'w')], name_width=340)
        self.tree.bind('<<TreeviewOpen>>', self._on_open)

        tab_map = ttk.Frame(self.nb)
        self.nb.add(tab_map, text='  Size map  ')
        mtop = ttk.Frame(tab_map, padding=(4, 6))
        mtop.pack(fill='x')
        ttk.Button(mtop, text='\u2191 Up', width=6, command=self._map_up).pack(side='left')
        self.map_path = tk.StringVar()
        ttk.Label(mtop, textvariable=self.map_path, style='Bold.TLabel').pack(side='left', padx=10)
        ttk.Label(mtop, text='click a block to inspect it \u00b7 double-click to zoom in', style='Muted.TLabel').pack(side='right')
        self.map_canvas = tk.Canvas(tab_map, highlightthickness=0)
        self.map_canvas.pack(fill='both', expand=True)
        self.map_canvas.bind('<Configure>', lambda e: self._schedule_map())
        self.map_canvas.bind('<Motion>', self._map_motion)
        self.map_canvas.bind('<Leave>', lambda e: self._map_unhover())
        self.map_canvas.bind('<Button-1>', self._map_click)
        self.map_canvas.bind('<Double-Button-1>', self._map_double)
        self.map_canvas.bind('<Button-3>', self._map_right_click)

        tab2 = ttk.Frame(self.nb)
        self.nb.add(tab2, text='  Biggest files  ')
        self.big = self._make_tree(tab2, 'headings', [
            ('name', 'File', 260, 'w'), ('size', 'Size', 90, 'e'), ('verdict', 'Safe to delete?', 160, 'w'),
            ('what', 'What it is', 240, 'w'), ('folder', 'Folder', 420, 'w')], stretch='folder')

        tab3 = ttk.Frame(self.nb)
        self.nb.add(tab3, text='  Quick wins  ')
        wtop = ttk.Frame(tab3, padding=(4, 6))
        wtop.pack(fill='x')
        self.wins_lbl = ttk.Label(wtop, text='Scan a drive to see what can be cleaned up safely.', style='Bold.TLabel')
        self.wins_lbl.pack(side='left')
        self.btn_wins_clean = ttk.Button(wtop, text='Clean selected \u2192 Recycle Bin', style='Clean.TButton',
                                         command=self.clean_selected, state='disabled')
        self.btn_wins_clean.pack(side='right')
        ttk.Button(wtop, text='Select all', command=self._wins_select_all).pack(side='right', padx=6)
        self.wins = self._make_tree(tab3, 'headings', [
            ('name', 'Folder', 420, 'w'), ('size', 'Size', 90, 'e'), ('what', 'What it is', 220, 'w'),
            ('how', 'How to clean it', 380, 'w')], stretch='how', multi=True)

        dframe = ttk.Frame(paned, padding=(0, 6, 0, 0))
        paned.add(dframe, weight=1)
        btns = ttk.Frame(dframe)
        btns.pack(side='right', fill='y', padx=(8, 0))
        self.btn_open = ttk.Button(btns, text='Show in Explorer', command=lambda: self.open_explorer(self.current), state='disabled')
        self.btn_copy = ttk.Button(btns, text='Copy path', command=lambda: self.copy_path(self.current), state='disabled')
        self.btn_web = ttk.Button(btns, text='Search the web', command=lambda: self.search_web(self.current), state='disabled')
        self.btn_clean = ttk.Button(btns, text='Move to Recycle Bin', style='Clean.TButton', command=self.clean_selected, state='disabled')
        for b in (self.btn_open, self.btn_copy, self.btn_web):
            b.pack(fill='x', pady=2)
        self.btn_clean.pack(fill='x', pady=(10, 2))
        dscroll = ttk.Scrollbar(dframe, orient='vertical')
        dscroll.pack(side='right', fill='y')
        self.detail = tk.Text(dframe, height=10, wrap='word', relief='flat', borderwidth=0, padx=10, pady=8,
                              font=('Segoe UI', 10), cursor='arrow', highlightthickness=1, yscrollcommand=dscroll.set)
        dscroll.config(command=self.detail.yview)
        self.detail.pack(side='left', fill='both', expand=True)
        self.detail.tag_configure('h1', font=('Segoe UI', 13, 'bold'))
        self.detail.tag_configure('path', font=('Segoe UI', 9))
        self.detail.tag_configure('b', font=('Segoe UI', 10, 'bold'))
        self.detail.tag_configure('size', font=('Segoe UI', 11, 'bold'))
        self.detail.tag_configure('gap', spacing1=6)
        for level in LEVEL_COLORS['light']:
            self.detail.tag_configure('badge_' + level, font=('Segoe UI', 10, 'bold'))
        self.detail.configure(state='disabled')

        self.menu = tk.Menu(self.root, tearoff=0)
        self.menu.add_command(label='Show in Explorer', command=lambda: self.open_explorer(self.current))
        self.menu.add_command(label='Copy path', command=lambda: self.copy_path(self.current))
        self.menu.add_command(label='Search the web for this name', command=lambda: self.search_web(self.current))
        self.menu.add_separator()
        self.menu.add_command(label='Open Recycle Bin', command=cleaner.open_recycle_bin)

    def _make_tree(self, parent, show, columns, name_width=0, stretch='what', multi=False):
        frame = ttk.Frame(parent)
        frame.pack(fill='both', expand=True)
        tree = ttk.Treeview(frame, columns=[c[0] for c in columns], show=show, height=8,
                            selectmode='extended' if multi else 'browse')
        vsb = ttk.Scrollbar(frame, orient='vertical', command=tree.yview)
        tree.configure(yscrollcommand=vsb.set)
        vsb.pack(side='right', fill='y')
        tree.pack(side='left', fill='both', expand=True)
        labels = {}
        if show == 'tree headings':
            labels['#0'] = 'Name'
            tree.heading('#0', text='Name', anchor='w', command=lambda t=tree: self._sort(t, '#0'))
            tree.column('#0', width=name_width, minwidth=180, stretch=False)
        for cid, label, width, anchor in columns:
            labels[cid] = label
            tree.heading(cid, text=label, anchor='w' if anchor == 'w' else 'e', command=lambda t=tree, c=cid: self._sort(t, c))
            tree.column(cid, width=width, minwidth=60, anchor=anchor, stretch=(cid == stretch))
        tree.bind('<<TreeviewSelect>>', self._on_select)
        tree.bind('<Button-3>', self._on_right_click)
        self.metas[tree] = {}
        self.heading_text[tree] = labels
        return tree

    # --------------------------------------------------------------- actions
    def browse(self):
        path = filedialog.askdirectory(initialdir=self.path_var.get() or None, title='Choose a folder or drive to analyse')
        if path:
            self.path_var.set(os.path.normpath(path))
            self._update_drive_info()
            self.start_scan()

    def elevate(self):
        path = self.path_var.get().strip()
        if getattr(sys, 'frozen', False):
            exe, params = sys.executable, ''
        else:
            exe, params = sys.executable, f'"{os.path.abspath(sys.argv[0])}"'
        if os.path.isdir(path):
            # a trailing backslash would escape the closing quote ("C:\" -> C:"), so end such paths with "."
            params += f' "{path + "." if path.endswith(chr(92)) else path}"'
        try:
            code = ctypes.windll.shell32.ShellExecuteW(None, 'runas', exe, params.strip(), None, 1)
        except Exception:
            code = 0
        if code > 32:
            self.root.destroy()
        else:
            messagebox.showinfo(APP, 'Administrator mode was not started (the permission prompt was cancelled).')

    def _update_drive_info(self):
        path = self.path_var.get().strip().strip('"')
        try:
            drive = os.path.splitdrive(path)[0]
            total, used, free = shutil.disk_usage(drive + os.sep if drive else path)
        except Exception:
            self.drive_lbl.config(text='')
            self.drive_bar.config(value=0)
            return
        self.drive_lbl.config(text=f'{drive or path}   {fmt_size(used)} used of {fmt_size(total)}   \u00b7   {fmt_size(free)} free')
        self.drive_bar.config(value=100 * used / total if total else 0)

    def start_scan(self):
        if self.busy or (self.scanner is not None and not self.scanner.finished):
            return
        path = self.path_var.get().strip().strip('"')
        if not os.path.isdir(path):
            messagebox.showerror(APP, f'"{path}" is not a folder or drive that exists.')
            return
        self._update_drive_info()
        for tree in (self.tree, self.big, self.wins):
            tree.delete(*tree.get_children())
            self.metas[tree].clear()
        self.scan_done = False
        self.map_node = None
        self._draw_map()
        self._select_metas([])
        self.wins_lbl.config(text='Scanning\u2026')
        self._show_text('Scanning\u2026', 'Results appear here when the scan finishes. Large drives take a minute or two.')
        norm = os.path.normpath(path)
        self.expected = None
        if len(os.path.splitdrive(norm)[1].strip('\\')) == 0:
            try:
                self.expected = shutil.disk_usage(norm if norm.endswith('\\') else norm + '\\').used
            except OSError:
                pass
        self.scanner = Scanner(path, post=safe_candidates)
        self.scanner.start()
        self.scan_btn.config(state='disabled')
        self.stop_btn.config(state='normal')
        if self.expected:
            self.progress.config(mode='determinate', value=0)
        else:
            self.progress.config(mode='indeterminate')
            self.progress.start(15)
        self._poll()

    def stop_scan(self):
        if self.scanner is not None and not self.scanner.finished:
            self.scanner.cancel()
            self.status.set('Stopping\u2026')

    def _poll(self):
        sc = self.scanner
        s = sc.snapshot()
        elapsed = time.time() - sc.started
        self.status.set(f'Scanning\u2026  {s["files"]:,} files \u00b7 {s["dirs"]:,} folders \u00b7 {fmt_size(s["bytes"])} \u00b7 {elapsed:.0f}s    '
                        f'{shorten(s["current"], 70)}')
        if self.expected:
            self.progress.config(value=min(99, 100 * s['bytes'] / self.expected))
        if sc.finished:
            self._finish()
        else:
            self.root.after(120, self._poll)

    def _finish(self):
        sc = self.scanner
        self.progress.stop()
        self.progress.config(mode='determinate', value=100)
        self.scan_btn.config(state='normal')
        self.stop_btn.config(state='disabled')
        self.scan_done = True
        self.status.set(self._summary())
        self.map_node = sc.root_node
        self._insert_root()
        self._fill_big()
        self._fill_wins()
        self._draw_map()

    def _summary(self):
        sc = self.scanner
        s = sc.snapshot()
        node = sc.root_node
        elapsed = (sc.ended or time.time()) - sc.started
        parts = [f'{"Stopped (partial)" if sc.cancelled else "Done"}: {fmt_size(node.size)} \u00b7 {node.files:,} files \u00b7 '
                 f'{node.dirs:,} folders \u00b7 {elapsed:.0f}s']
        if s['errors']:
            parts.append(f'{s["errors"]:,} unreadable (try administrator mode)')
        if s['cloud_files']:
            parts.append(f'{fmt_size(s["cloud_bytes"])} online-only')
        return ' \u00b7 '.join(parts)

    # --------------------------------------------------------------- filling
    def _values(self, m, parent_size):
        share = ''
        if parent_size and m.size and m.kind != 'more':
            share = share_bar(min(1.0, m.size / parent_size))
        files = f'{m.files:,}' if (m.is_dir or m.kind == 'more') and m.files is not None else ''
        return (fmt_size(m.size), share, files, K.LEVEL_LABEL[m.info.level], m.info.title)

    def _insert_root(self, focus_tab=True):
        node = self.scanner.root_node
        path = node.path()
        info = K.classify_dir(path)
        m = Meta(path, path, True, node.size, node.files, info, node=node, dirs=node.dirs, denied=node.denied)
        self.metas[self.tree][path] = m
        self.tree.insert('', 'end', iid=path, text=path, image=self.icon_dir, values=self._values(m, None), tags=(info.level,))
        self.tree.insert(path, 'end', iid=path + DUMMY, text='')
        self._populate(path)
        self.tree.item(path, open=True)
        if focus_tab:
            self.tree.selection_set(path)
            self.nb.select(TAB_TREE)

    def _on_open(self, _event):
        iid = self.tree.focus()
        kids = self.tree.get_children(iid)
        if len(kids) == 1 and kids[0].endswith(DUMMY):
            self._populate(iid)

    def _populate(self, iid):
        tree, metas = self.tree, self.metas[self.tree]
        pm = metas[iid]
        tree.delete(*tree.get_children(iid))
        child_nodes = pm.node.child_map() if pm.node is not None else {}
        entries = []
        try:
            with os.scandir(long_path(pm.path)) as it:
                for e in it:
                    try:
                        st = e.stat(follow_symlinks=False)
                    except OSError:
                        continue
                    if stat.S_ISDIR(st.st_mode):
                        if is_link(st):
                            entries.append((0, e.name, 'link', 0, None))
                        else:
                            n = child_nodes.get(e.name.lower())
                            entries.append((n.size if n else 0, e.name, 'dir', n.files if n else 0, n))
                    elif stat.S_ISREG(st.st_mode):
                        entries.append((0 if is_cloud_only(st) else st.st_size, e.name, 'file', 1, None))
        except OSError:
            pass
        entries.sort(key=lambda t: (-t[0], t[1].lower()))
        shown, rest = entries[:MAX_ROWS], entries[MAX_ROWS:]
        for size, name, kind, files, node in shown:
            full = os.path.join(pm.path, name)
            if kind == 'link':
                m = Meta(full, name, True, 0, 0, LINK_INFO, kind='link')
            elif kind == 'dir':
                m = Meta(full, name, True, size, files, K.classify_dir(full), node=node,
                         dirs=node.dirs if node else 0, denied=bool(node and node.denied))
            else:
                m = Meta(full, name, False, size, 1, K.classify_file(full))
            metas[full] = m
            tree.insert(iid, 'end', iid=full, text=name, image=self.icon_dir if m.is_dir else self.icon_file,
                        values=self._values(m, pm.size), tags=(m.info.level,))
            if kind == 'dir' and (node is None or node.children or node.own_files):
                tree.insert(full, 'end', iid=full + DUMMY, text='')
        if rest:
            more = pm.path + MORE
            m = Meta(more, f'\u2026 {len(rest):,} smaller items', False, sum(t[0] for t in rest), sum(t[3] for t in rest),
                     K.Info(K.UNKNOWN, '', '', ''), kind='more', extra=len(rest))
            metas[more] = m
            tree.insert(iid, 'end', iid=more, text=m.name, tags=(),
                        values=(fmt_size(m.size), '', f'{m.files:,}', '', ''))

    def _fill_big(self):
        tree, metas = self.big, self.metas[self.big]
        for size, path in self.scanner.biggest:
            info = K.classify_file(path)
            m = Meta(path, os.path.basename(path), False, size, 1, info)
            metas[path] = m
            tree.insert('', 'end', iid=path, values=(m.name, fmt_size(size), K.LEVEL_LABEL[info.level], info.title,
                                                    os.path.dirname(path)), tags=(info.level,))

    def _fill_wins(self):
        tree, metas = self.wins, self.metas[self.wins]
        nodes = self.scanner.result or []
        total = sum(n.size for n in nodes)
        for n in nodes:
            path = n.path()
            info = K.classify_dir(path)
            m = Meta(path, os.path.basename(path) or path, True, n.size, n.files, info, node=n, dirs=n.dirs)
            metas[path] = m
            tree.insert('', 'end', iid=path, values=(path, fmt_size(n.size), info.title, info.how or info.advice), tags=(K.SAFE,))
        held = getattr(self.scanner, 'held_back', [])
        extra = f' {len(held):,} more were held back because they contain logins/cookies.' if held else ''
        if nodes:
            self.wins_lbl.config(text=f'About {fmt_size(total)} can be cleaned: {len(nodes):,} folders rated "safe to delete".' + extra)
        else:
            self.wins_lbl.config(text='Nothing obviously safe to clean was found in this scan.')

    def _wins_select_all(self):
        self.wins.selection_set(self.wins.get_children(''))

    # ---------------------------------------------------------------- sorting
    def _sort(self, tree, col):
        metas = self.metas[tree]
        prev_col, prev_rev = self.sort_state.get(tree, (None, False))
        reverse = (not prev_rev) if prev_col == col else (col in ('size', 'files', 'share'))
        self.sort_state[tree] = (col, reverse)
        keys = {
            '#0': lambda m: m.name.lower(), 'name': lambda m: m.name.lower(),
            'size': lambda m: m.size or 0, 'share': lambda m: m.size or 0, 'files': lambda m: m.files or 0,
            'verdict': lambda m: K.LEVEL_RANK[m.info.level], 'what': lambda m: m.info.title.lower(),
            'folder': lambda m: os.path.dirname(m.path).lower(), 'how': lambda m: m.info.how.lower(),
        }
        keyf = keys[col]
        stack = ['']
        while stack:
            parent = stack.pop()
            kids = tree.get_children(parent)
            real = [k for k in kids if k in metas and metas[k].kind != 'more']
            tail = [k for k in kids if k not in real]
            real.sort(key=lambda k: keyf(metas[k]), reverse=reverse)
            for i, k in enumerate(real + tail):
                tree.move(k, parent, i)
            for k in real:
                ch = tree.get_children(k)
                if ch and not ch[0].endswith(DUMMY):
                    stack.append(k)
        for cid, label in self.heading_text[tree].items():
            arrow = (' \u25bc' if reverse else ' \u25b2') if cid == col else ''
            tree.heading(cid, text=label + arrow)

    # ------------------------------------------------------- selection/detail
    def _on_select(self, event):
        tree = event.widget
        metas = [self.metas[tree][i] for i in tree.selection() if i in self.metas[tree]]
        self._select_metas(metas)

    def _select_metas(self, metas):
        self.selection = metas
        single = metas[0] if len(metas) == 1 else None
        self.current = single if single is not None and single.kind != 'more' else None
        if not metas:
            pass
        elif single is not None:
            self._show_detail(single)
        else:
            self._show_multi(metas)
        self._set_buttons()

    def _cleanable(self, m):
        return (self.scan_done and not self.busy and m.kind == 'item' and m.info.level == K.SAFE and m.size > 0
                and os.path.dirname(m.path) != m.path)

    def _set_buttons(self):
        on = 'normal' if self.current is not None else 'disabled'
        for b in (self.btn_open, self.btn_copy, self.btn_web):
            b.config(state=on)
        metas = self.selection
        can = bool(metas) and all(self._cleanable(m) for m in metas)
        self.btn_clean.config(state='normal' if can else 'disabled')
        self.btn_wins_clean.config(state='normal' if can and self.wins.selection() else 'disabled')
        if len(metas) > 1:
            text = f'Clean {len(metas)} items \u2192 Recycle Bin'
        elif metas and not metas[0].is_dir:
            text = 'Move to Recycle Bin'
        else:
            text = 'Clear contents \u2192 Recycle Bin'
        self.btn_clean.config(text=text)

    def _show_text(self, heading, body):
        t = self.detail
        t.configure(state='normal')
        t.delete('1.0', 'end')
        t.insert('end', heading + '\n', 'h1')
        t.insert('end', body + '\n', 'gap')
        t.configure(state='disabled')

    def _show_welcome(self):
        self._show_text('Welcome', 'Pick a drive or folder above and press Scan. Then click any folder or file to see what it is, '
                        'how big it is and whether it is safe to delete.\n\nTip: the "Size map" tab shows your disk as coloured blocks, '
                        'and "Quick wins" lists what you can clean up right away. Run as administrator for a complete scan of C:\\.')

    def _show_multi(self, metas):
        total = sum(m.size for m in metas)
        t = self.detail
        t.configure(state='normal')
        t.delete('1.0', 'end')
        t.insert('end', f'{len(metas):,} items selected\n', 'h1')
        t.insert('end', f'{fmt_size(total)} in total\n', ('size', 'gap'))
        levels = {m.info.level for m in metas}
        if levels == {K.SAFE}:
            t.insert('end', 'All of them are rated safe to delete. ', 'gap')
            t.insert('end', 'Press "Clean" to move their contents to the Recycle Bin (you will be asked to confirm first).')
        else:
            t.insert('end', 'The selection mixes different kinds of items, so cleaning is disabled. Select only items rated "Safe to delete".', 'gap')
        t.configure(state='disabled')

    def _show_detail(self, m):
        t = self.detail
        t.configure(state='normal')
        t.delete('1.0', 'end')
        if m.kind == 'more':
            t.insert('end', m.name + '\n', 'h1')
            t.insert('end', f'{m.extra:,} items too small to list individually, {fmt_size(m.size)} in total.\n', 'gap')
            t.configure(state='disabled')
            return
        info = m.info
        t.insert('end', m.name + '\n', 'h1')
        t.insert('end', m.path + '\n', 'path')
        bits = [fmt_size(m.size)]
        if m.is_dir and m.kind != 'link':
            bits.append(f'{m.files:,} files')
            bits.append(f'{m.dirs:,} folders')
        t.insert('end', '  \u00b7  '.join(bits) + '\n', ('size', 'gap'))
        t.insert('end', f' {K.LEVEL_LABEL[info.level]} ', ('badge_' + info.level, 'gap'))
        t.insert('end', '   ' + info.title + '\n', 'b')
        if info.what:
            t.insert('end', 'What it is: ', ('b', 'gap'))
            t.insert('end', info.what + '\n')
        if info.advice:
            t.insert('end', 'Should you delete it? ', 'b')
            t.insert('end', info.advice + '\n')
        if info.how:
            t.insert('end', 'How to free the space safely: ', 'b')
            t.insert('end', info.how + '\n')
        if info.inherited:
            t.insert('end', 'This verdict comes from the folder it sits in.\n', 'path')
        if m.denied:
            t.insert('end', 'Windows blocked access to part of this folder, so the size shown may be too small. '
                     'Run as administrator for the full picture.\n', 'note')
        t.configure(state='disabled')

    # ------------------------------------------------------------ context menu
    def _on_right_click(self, event):
        tree = event.widget
        iid = tree.identify_row(event.y)
        if not iid:
            return
        if iid not in tree.selection():
            tree.selection_set(iid)
        m = self.metas[tree].get(iid)
        if m is not None and m.kind != 'more':
            self.current = m
            self.menu.tk_popup(event.x_root, event.y_root)

    def open_explorer(self, m):
        if m is None:
            return
        try:
            if m.is_dir:
                os.startfile(m.path)
            else:
                subprocess.Popen(f'explorer /select,"{m.path}"')
        except OSError as exc:
            messagebox.showerror(APP, f'Could not open Explorer: {exc}')

    def copy_path(self, m):
        if m is not None:
            self.root.clipboard_clear()
            self.root.clipboard_append(m.path)
            self.status.set(f'Copied: {m.path}')

    def search_web(self, m):
        if m is not None:
            kind = 'folder' if m.is_dir else 'file'
            query = f'what is "{m.name}" {kind} windows can I delete it'
            webbrowser.open('https://www.google.com/search?q=' + urllib.parse.quote_plus(query))

    # --------------------------------------------------------------- cleaning
    def clean_selected(self):
        if self.busy or not self.scan_done:
            return
        # work from the tab the user is looking at, so "selection" means what they can see highlighted
        metas = [m for m in self.selection if self._cleanable(m)]
        if not metas or len(metas) != len(self.selection):
            return
        # never trust the screen: re-check each verdict and drop items nested inside another selected item
        checked = []
        for m in sorted(metas, key=lambda m: len(m.path)):
            level = (K.classify_dir if m.is_dir else K.classify_file)(m.path).level
            if level != K.SAFE or not os.path.lexists(m.path):
                continue
            if any(under(m.path, c.path) for c in checked):
                continue
            checked.append(m)
        self.status.set('Checking the selection…')
        self.root.update_idletasks()
        held = []
        for m in list(checked):
            hit = cleaner.find_sensitive(m.path) if m.is_dir else (m.path if cleaner.is_sensitive_name(os.path.basename(m.path)) else None)
            if hit:
                held.append((m, hit))
                checked.remove(m)
        if held:
            shown = '\n'.join(f'  • {shorten(m.path, 60)}\n      contains {shorten(hit, 70)}' for m, hit in held[:6])
            messagebox.showwarning(APP, 'Held back for safety - these look like they contain saved logins, cookies, bookmarks or keys, '
                                   'so they will not be touched:\n\n' + shown + ('\n  …' if len(held) > 6 else ''))
        if not checked:
            self.status.set(self._summary())
            return
        targets = []
        for m in checked:
            targets += cleaner.targets_for(m.path, m.is_dir)
        if not targets:
            messagebox.showinfo(APP, 'Nothing to move - the selected folders are already empty.')
            return
        total = sum(m.size for m in checked)
        lines = [f'  \u2022 {shorten(m.path, 62)}  ({fmt_size(m.size)})' for m in sorted(checked, key=lambda m: -m.size)[:8]]
        if len(checked) > 8:
            lines.append(f'  \u2026 and {len(checked) - 8:,} more')
        msg = (f'Move to the Recycle Bin?\n\n' + '\n'.join(lines) + f'\n\nTotal: {fmt_size(total)} in {len(checked):,} item(s).\n\n'
               'For folders, only what is inside is moved; the folder itself stays. '
               'Everything can be restored from the Recycle Bin, and the disk space is only released when you empty it.')
        if not messagebox.askyesno(APP, msg, icon='warning', default='no'):
            return
        self.busy = True
        self._set_buttons()
        self.scan_btn.config(state='disabled')
        before = self.scanner.root_node.size
        self.status.set('Moving to the Recycle Bin\u2026')
        self.progress.config(mode='indeterminate')
        self.progress.start(15)
        job = {'done': False, 'left': 0, 'aborted': False, 'error': None, 'stage': 'Moving to the Recycle Bin\u2026'}

        def work():                          # runs off the UI thread: never touch Tk widgets or variables in here
            try:
                _ok, job['aborted'] = cleaner.recycle_in_chunks(targets)
                job['left'] = sum(1 for t in targets if os.path.lexists(t))
                job['stage'] = 'Updating the numbers\u2026'
                touched = {m.path if m.is_dir else os.path.dirname(m.path) for m in checked}
                for path in sorted(touched, key=len):
                    if not any(under(path, o) and o != path for o in touched):
                        rescan_path(self.scanner, path)
            except Exception as exc:        # reported to the user below
                job['error'] = exc
            finally:
                job['done'] = True

        threading.Thread(target=work, daemon=True).start()
        self.root.after(150, lambda: self._poll_job(job, before, len(targets)))

    def _poll_job(self, job, before, n_targets):
        if not job['done']:
            self.status.set(job['stage'])
            self.root.after(150, lambda: self._poll_job(job, before, n_targets))
            return
        self.progress.stop()
        self.progress.config(mode='determinate', value=100)
        self.busy = False
        self.scan_btn.config(state='normal')
        sc = self.scanner
        sc.result = safe_candidates(sc)
        self._refresh_views()
        freed = max(0, before - sc.root_node.size)
        moved = n_targets - job['left']
        note = ''
        if job['left']:
            note = f' {job["left"]:,} item(s) could not be moved (in use or access denied - close the program, or try administrator mode).'
        if job['aborted']:
            note += ' The operation was cancelled.'
        self.status.set(f'Moved {moved:,} item(s) to the Recycle Bin \u00b7 {fmt_size(freed)} less here.' + note)
        if job['error'] is not None:
            messagebox.showerror(APP, f'Something went wrong while cleaning:\n\n{job["error"]}')
        elif moved and messagebox.askyesno(APP, f'Moved {moved:,} item(s) ({fmt_size(freed)}) to the Recycle Bin.\n\n'
                                           'The disk space is released when you empty the Recycle Bin.\n\nOpen the Recycle Bin now?'
                                           + (('\n\n' + note.strip()) if note else '')):
            cleaner.open_recycle_bin()
        elif job['left'] and not moved:
            messagebox.showwarning(APP, note.strip())

    def _refresh_views(self):
        """Redraw all tabs from the updated scan, keeping the expanded folders open."""
        tree, metas = self.tree, self.metas[self.tree]
        open_paths = [i for i, m in metas.items() if m.is_dir and m.kind == 'item' and tree.exists(i) and tree.item(i, 'open')]
        sel = tree.selection()
        for t in (self.tree, self.big, self.wins):
            t.delete(*t.get_children())
            self.metas[t].clear()
        self._insert_root(focus_tab=False)
        for p in sorted(open_paths, key=len):
            if tree.exists(p):
                kids = tree.get_children(p)
                if len(kids) == 1 and kids[0].endswith(DUMMY):
                    self._populate(p)
                tree.item(p, open=True)
        keep = [i for i in sel if tree.exists(i)]
        if keep:
            tree.selection_set(keep)
        self._fill_big()
        self._fill_wins()
        self._update_drive_info()
        self._select_metas([])
        self.map_node = self._map_valid_node()
        self._draw_map()

    # -------------------------------------------------------------- size map
    def _on_tab(self, _event):
        if self.nb.index('current') == TAB_MAP and self.scan_done:
            sel = self.metas[self.tree].get(self.tree.selection()[0]) if self.tree.selection() else None
            if sel is not None and sel.is_dir and sel.node is not None:
                self.map_node = sel.node
            self._draw_map()

    def _map_valid_node(self):
        sc = self.scanner
        if sc is None:
            return None
        node = self.map_node
        while node is not None:                  # a rescan can replace nodes; walk up until we are inside the live tree
            n = node
            while n.parent is not None:
                n = n.parent
            if n is sc.root_node:
                return node
            node = None
        return sc.root_node

    def _schedule_map(self):
        if self._map_after is not None:
            self.root.after_cancel(self._map_after)
        self._map_after = self.root.after(80, self._draw_map)

    def _map_up(self):
        if self.map_node is not None and self.map_node.parent is not None:
            self.map_node = self.map_node.parent
            self._draw_map()

    def _draw_map(self):
        self._map_after = None
        c, t = self.map_canvas, self.t
        c.delete('all')
        self.map_blocks = {}
        self.map_hover = None
        node = self.map_node
        if self.scanner is None or not self.scan_done or node is None:
            self.map_path.set('')
            c.create_text(24, 24, anchor='nw', text='Scan a drive or folder to see its size map.', fill=t['muted'], font=('Segoe UI', 11))
            return
        w, h = c.winfo_width(), c.winfo_height()
        if w < 60 or h < 60:
            return
        self.map_path.set(f'{node.path()}  \u00b7  {fmt_size(node.size)}')
        items = [(ch.size, ch.name, ch) for ch in (node.children or ()) if ch.size > 0]
        if node.own_size > 0:
            items.append((node.own_size, '(files in this folder)', None))
        items.sort(key=lambda i: -i[0])
        if len(items) > MAX_BLOCKS:
            rest = items[MAX_BLOCKS:]
            items = items[:MAX_BLOCKS] + [(sum(i[0] for i in rest), f'{len(rest):,} smaller items', 'other')]
        if not items:
            c.create_text(24, 24, anchor='nw', text='This folder is empty.', fill=t['muted'], font=('Segoe UI', 11))
            return
        rects = squarify([i[0] for i in items], 2, 2, w - 4, h - 4)
        folder_level = K.classify_dir(node.path()).level
        for (x, y, rw, rh), (size, label, ch) in zip(rects, items):
            level = K.UNKNOWN if ch == 'other' else folder_level if ch is None else K.classify_dir(ch.path()).level
            rid = c.create_rectangle(x, y, x + rw, y + rh, fill=self.lc[level]['map'], outline=t['canvas'], width=2)
            self.map_blocks[rid] = (size, label, ch, level)
            if rw > 60 and rh > 32:
                chars = max(4, int((rw - 12) / 6.6))
                c.create_text(x + 6, y + 5, anchor='nw', text=f'{shorten(label, chars)}\n{fmt_size(size)}',
                              fill=t['fg'], font=('Segoe UI', 9, 'bold'), state='disabled')

    def _map_block_at(self, event):
        for rid in self.map_canvas.find_overlapping(event.x, event.y, event.x, event.y):
            if rid in self.map_blocks:
                return rid
        return None

    def _map_unhover(self):
        if self.map_hover is not None:
            self.map_canvas.itemconfigure(self.map_hover, outline=self.t['canvas'])
            self.map_hover = None

    def _map_motion(self, event):
        rid = self._map_block_at(event)
        if rid == self.map_hover:
            return
        self._map_unhover()
        if rid is not None:
            size, label, ch, level = self.map_blocks[rid]
            self.map_hover = rid
            self.map_canvas.itemconfigure(rid, outline=self.t['fg'])
            self.map_canvas.tag_raise(rid)
            for text_id in self.map_canvas.find_withtag('all'):
                if self.map_canvas.type(text_id) == 'text':
                    self.map_canvas.tag_raise(text_id)
            what = K.classify_dir(ch.path()).title if ch not in (None, 'other') else ''
            self.status.set(f'{label} \u00b7 {fmt_size(size)} \u00b7 {K.LEVEL_LABEL[level]}' + (f' \u00b7 {what}' if what else ''))

    def _map_meta(self, rid):
        size, label, ch, level = self.map_blocks[rid]
        if ch in (None, 'other'):
            return None
        path = ch.path()
        return Meta(path, ch.name, True, ch.size, ch.files, K.classify_dir(path), node=ch, dirs=ch.dirs, denied=ch.denied)

    def _map_click(self, event):
        rid = self._map_block_at(event)
        if rid is not None:
            m = self._map_meta(rid)
            if m is not None:
                self._select_metas([m])

    def _map_double(self, event):
        rid = self._map_block_at(event)
        if rid is not None:
            ch = self.map_blocks[rid][2]
            if ch not in (None, 'other') and (ch.children or ch.own_size):
                self.map_node = ch
                self._draw_map()

    def _map_right_click(self, event):
        rid = self._map_block_at(event)
        if rid is not None:
            m = self._map_meta(rid)
            if m is not None:
                self._select_metas([m])
                self.menu.tk_popup(event.x_root, event.y_root)

    def _on_error(self, exc, val, tb):
        traceback.print_exception(exc, val, tb)
        messagebox.showerror(APP, f'Something went wrong:\n\n{val}')


def main():
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except Exception:
        try:
            ctypes.windll.user32.SetProcessDPIAware()
        except Exception:
            pass
    start = sys.argv[1] if len(sys.argv) > 1 and os.path.isdir(sys.argv[1]) else None
    root = tk.Tk()
    DiskDetective(root, start)
    root.mainloop()


if __name__ == '__main__':
    main()
