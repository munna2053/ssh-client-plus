use super::{
    crypto::Secret, paths::AppPaths, ssh::SshSession, storage::RecordStore, vault::UnlockedVault,
    wide,
};
use super::{
    terminal_view,
    theme::{self, Theme},
};
use crate::{
    Result,
    core::{Authentication, Host, ReadOnlyAction},
};
use std::{
    cell::RefCell,
    ptr::{null, null_mut},
    time::{Duration, Instant},
};
use windows_sys::Win32::{
    Foundation::{HWND, LPARAM, LRESULT, RECT, WPARAM},
    Graphics::{
        Dwm::{DWMWA_USE_IMMERSIVE_DARK_MODE, DwmSetWindowAttribute},
        Gdi::*,
    },
    System::{LibraryLoader::GetModuleHandleW, RemoteDesktop::*, SystemServices::SS_ENDELLIPSIS},
    UI::{
        Controls::*,
        HiDpi::*,
        Input::KeyboardAndMouse::{EnableWindow, GetFocus, SetFocus},
        WindowsAndMessaging::*,
    },
};

const PASSWORD: usize = 101;
const CONFIRM: usize = 102;
const UNLOCK: usize = 103;
const LOCK: usize = 104;
const SHOW_MASTER: usize = 105;
const LIST: usize = 110;
const NAME: usize = 111;
const ADDRESS: usize = 112;
const PORT: usize = 113;
const USERNAME: usize = 114;
const IDENTITY: usize = 115;
const AUTHENTICATION: usize = 116;
const SERVER_PASSWORD: usize = 117;
const NEW: usize = 120;
const SAVE: usize = 121;
const DELETE: usize = 122;
const CONNECT: usize = 123;
const SYSTEM: usize = 130;
const UPTIME: usize = 131;
const DISK: usize = 132;
const MEMORY: usize = 133;
const STATUS: usize = 140;
const IDENTITY_NOTE: usize = 141;
const TERMINAL: usize = 150;
const TAB_TERMINAL: usize = 151;
const TAB_DETAILS: usize = 152;
const DISCONNECT: usize = 153;
const ACTIVE_TITLE: usize = 154;
const TERMINAL_HINT: usize = 155;
const LIST_HINT: usize = 156;
const VAULT_BADGE: usize = 157;

struct State {
    paths: AppPaths,
    store: RecordStore,
    envelope: Option<Vec<u8>>,
    vault: Option<UnlockedVault>,
    hosts: Vec<Host>,
    selected: Option<usize>,
    controls: Vec<(usize, HWND)>,
    last_activity: Instant,
    retry_after: Instant,
    failures: u32,
    children: Vec<SshSession>,
    window: HWND,
    theme: Theme,
    details: bool,
    active_label: String,
}

impl State {
    fn new(paths: AppPaths) -> Result<Self> {
        let store = RecordStore::open(&paths.database_dir)?;
        let envelope = store.read()?;
        Ok(Self {
            paths,
            store,
            envelope,
            vault: None,
            hosts: vec![],
            selected: None,
            controls: vec![],
            last_activity: Instant::now(),
            retry_after: Instant::now(),
            failures: 0,
            children: vec![],
            window: null_mut(),
            theme: Theme::new(96)?,
            details: false,
            active_label: String::new(),
        })
    }

    fn control(&self, id: usize) -> HWND {
        self.controls
            .iter()
            .find(|(candidate, _)| *candidate == id)
            .map_or(null_mut(), |(_, handle)| *handle)
    }

    fn add(
        &mut self,
        parent: HWND,
        class: &str,
        text: &str,
        id: usize,
        style: u32,
        bounds: [i32; 4],
    ) -> Result<()> {
        let class = wide(class);
        let text = wide(text);
        // SAFETY: parent and all UTF-16 buffers are valid; child IDs are small integer menu values.
        let handle = unsafe {
            CreateWindowExW(
                0,
                class.as_ptr(),
                text.as_ptr(),
                WS_CHILD | WS_VISIBLE | style,
                bounds[0],
                bounds[1],
                bounds[2],
                bounds[3],
                parent,
                id as *mut _,
                GetModuleHandleW(null()),
                null(),
            )
        };
        if handle.is_null() {
            return Err("Cannot create a native Windows control.".into());
        }
        // SAFETY: DEFAULT_GUI_FONT is an OS-owned stock font; control handles are valid.
        unsafe {
            SendMessageW(handle, WM_SETFONT, self.theme.body.0 as usize, 1);
        }
        self.controls.push((id, handle));
        Ok(())
    }

    fn initialize(&mut self, window: HWND) -> Result<()> {
        self.window = window;
        // SAFETY: live window has a valid DPI; theme resources are attached before any controls use them.
        self.theme = Theme::new(unsafe { GetDpiForWindow(window) }.max(96))?;
        let edit = WS_TABSTOP | ES_AUTOHSCROLL as u32;
        let button = WS_TABSTOP | BS_OWNERDRAW as u32;
        for (id, text) in [
            (200, "SentinelSSH"),
            (202, "Your private server workspace"),
            (205, "SERVERS"),
            (206, "Select a server"),
            (207, "Add a server or choose one from the sidebar."),
            (203, "Vault master passphrase"),
            (204, "Confirm passphrase"),
            (208, "Unlock your workspace"),
            (
                209,
                "Your servers and saved passwords are protected by your vault key.",
            ),
            (220, "QUICK CHECKS"),
            (ACTIVE_TITLE, "No active session"),
            (
                TERMINAL_HINT,
                "Ctrl+Shift+C to copy   |   Ctrl+Shift+V to paste   |   Scroll for history",
            ),
            (LIST_HINT, "Unlock your vault to load servers."),
            (VAULT_BADGE, "VAULT LOCKED"),
            (STATUS, ""),
        ] {
            self.add(
                window,
                "STATIC",
                text,
                id,
                if matches!(id, 206 | 207 | ACTIVE_TITLE) {
                    SS_ENDELLIPSIS
                } else {
                    0
                },
                [0, 0, 1, 1],
            )?;
        }
        for (id, label) in [
            (NAME, "Display name"),
            (ADDRESS, "Hostname / IP"),
            (PORT, "SSH port"),
            (USERNAME, "Username"),
            (IDENTITY, "Identity file path"),
            (SERVER_PASSWORD, "Server password"),
        ] {
            self.add(window, "STATIC", label, id + 300, 0, [0, 0, 1, 1])?;
            self.add(
                window,
                "EDIT",
                "",
                id,
                edit | if id == SERVER_PASSWORD {
                    ES_PASSWORD as u32
                } else {
                    0
                },
                [0, 0, 1, 1],
            )?;
        }
        self.add(window, "STATIC", "Login method", 416, 0, [0, 0, 1, 1])?;
        self.add(window, "STATIC", "", IDENTITY_NOTE, 0, [0, 0, 1, 1])?;
        for id in [PASSWORD, CONFIRM] {
            self.add(
                window,
                "EDIT",
                "",
                id,
                edit | ES_PASSWORD as u32,
                [0, 0, 1, 1],
            )?;
        }
        self.add(
            window,
            "BUTTON",
            "Show master passphrase",
            SHOW_MASTER,
            WS_TABSTOP | BS_AUTOCHECKBOX as u32,
            [0, 0, 1, 1],
        )?;
        for (id, label) in [
            (UNLOCK, "Unlock vault"),
            (LOCK, "Lock vault"),
            (NEW, "+ New server"),
            (DELETE, "Delete"),
            (SAVE, "Save server"),
            (CONNECT, "Connect"),
            (DISCONNECT, "Disconnect"),
            (TAB_TERMINAL, "Terminal"),
            (TAB_DETAILS, "Server details"),
            (SYSTEM, "System"),
            (UPTIME, "Uptime"),
            (DISK, "Disk"),
            (MEMORY, "Memory"),
        ] {
            self.add(window, "BUTTON", label, id, button, [0, 0, 1, 1])?;
        }
        self.add(
            window,
            "LISTBOX",
            "",
            LIST,
            WS_VSCROLL
                | WS_TABSTOP
                | LBS_NOTIFY as u32
                | LBS_OWNERDRAWFIXED as u32
                | LBS_HASSTRINGS as u32
                | LBS_NOINTEGRALHEIGHT as u32,
            [0, 0, 1, 1],
        )?;
        self.add(
            window,
            "COMBOBOX",
            "",
            AUTHENTICATION,
            WS_TABSTOP | WS_VSCROLL | CBS_DROPDOWNLIST as u32,
            [0, 0, 1, 1],
        )?;
        let terminal = terminal_view::create(window, TERMINAL)?;
        self.controls.push((TERMINAL, terminal));
        // SAFETY: controls exist; native messages copy the input strings synchronously.
        unsafe {
            for label in ["SSH key / agent", "Saved password"] {
                let label = wide(label);
                SendMessageW(
                    self.control(AUTHENTICATION),
                    CB_ADDSTRING,
                    0,
                    label.as_ptr() as isize,
                );
            }
            SendMessageW(self.control(AUTHENTICATION), CB_SETCURSEL, 0, 0);
            SendMessageW(
                self.control(LIST),
                LB_SETITEMHEIGHT,
                0,
                theme::scale(58, self.theme.dpi) as isize,
            );
            for id in [PASSWORD, CONFIRM] {
                SendMessageW(self.control(id), EM_SETLIMITTEXT, 1024, 0);
            }
            SendMessageW(self.control(SERVER_PASSWORD), EM_SETLIMITTEXT, 1022, 0);
            for id in [NAME, ADDRESS, PORT, USERNAME, IDENTITY] {
                SendMessageW(self.control(id), EM_SETLIMITTEXT, 2048, 0);
            }
            for id in [
                PASSWORD,
                CONFIRM,
                NAME,
                ADDRESS,
                PORT,
                USERNAME,
                IDENTITY,
                SERVER_PASSWORD,
            ] {
                let margin = theme::scale(10, self.theme.dpi) as usize;
                SendMessageW(
                    self.control(id),
                    EM_SETMARGINS,
                    (EC_LEFTMARGIN | EC_RIGHTMARGIN) as usize,
                    (margin | (margin << 16)) as isize,
                );
            }
            for id in [200, 208] {
                SendMessageW(self.control(id), WM_SETFONT, self.theme.title.0 as usize, 1);
            }
            SendMessageW(
                self.control(206),
                WM_SETFONT,
                self.theme.heading.0 as usize,
                1,
            );
            if SetTimer(window, 1, 50, None) == 0 {
                return Err("Cannot start the workspace refresh timer.".into());
            }
            if WTSRegisterSessionNotification(window, NOTIFY_FOR_THIS_SESSION) == 0 {
                return Err("Cannot register vault lock notifications with Windows.".into());
            }
        }
        self.set(
            UNLOCK,
            if self.envelope.is_some() {
                "Unlock vault"
            } else {
                "Create vault"
            },
        );
        self.set(
            208,
            if self.envelope.is_some() {
                "Unlock your workspace"
            } else {
                "Create your private vault"
            },
        );
        self.refresh_enabled();
        self.layout();
        self.set(
            STATUS,
            if self.paths.ssh.is_file() {
                "Ready. Unlock your vault to connect to a server."
            } else {
                "OpenSSH Client is missing. Enable it in Windows Settings > Optional features."
            },
        );
        Ok(())
    }

    fn set(&self, id: usize, value: &str) {
        let value = wide(value);
        // SAFETY: handle belongs to this window and UTF-16 text lives until the synchronous call returns.
        unsafe {
            SetWindowTextW(self.control(id), value.as_ptr());
        }
    }

    fn bounds(&self) -> (i32, i32) {
        let mut rect = RECT::default();
        // SAFETY: the state belongs to this live parent window.
        unsafe {
            GetClientRect(self.window, &mut rect);
        }
        (
            rect.right * 96 / self.theme.dpi as i32,
            rect.bottom * 96 / self.theme.dpi as i32,
        )
    }

    fn place(&self, id: usize, x: i32, y: i32, width: i32, height: i32) {
        let s = |v| theme::scale(v, self.theme.dpi);
        // SAFETY: this live child is owned by the window; all dimensions are scaled scalar values.
        unsafe {
            MoveWindow(
                self.control(id),
                s(x),
                s(y),
                s(width.max(1)),
                s(height.max(1)),
                0,
            );
        }
    }

    fn visible(&self, id: usize, visible: bool) {
        // SAFETY: handle is an owned child. Showing a child does not activate the top-level window.
        unsafe {
            ShowWindow(self.control(id), if visible { SW_SHOWNA } else { SW_HIDE });
        }
    }

    fn workspace_labels(&self) {
        let unlocked = self.vault.is_some();
        self.set(
            VAULT_BADGE,
            if unlocked {
                "VAULT UNLOCKED"
            } else {
                "VAULT LOCKED"
            },
        );
        self.set(
            LIST_HINT,
            if !unlocked {
                "Unlock to see your servers."
            } else {
                "No servers yet.\r\nAdd your first server below."
            },
        );
        if let Some(host) = self.selected.and_then(|index| self.hosts.get(index)) {
            self.set(206, &host.name);
            self.set(
                207,
                &format!("{}@{}:{}", host.username, host.address, host.port),
            );
        } else {
            self.set(
                206,
                if self.details {
                    "New server"
                } else {
                    "Select a server"
                },
            );
            self.set(207, "Add a server or choose one from the sidebar.");
        }
        self.set(
            ACTIVE_TITLE,
            if self.children.is_empty() {
                "No active session"
            } else {
                &self.active_label
            },
        );
    }

    fn layout(&self) {
        let (width, height) = self.bounds();
        let unlocked = self.vault.is_some();
        let left = 338;
        let main = (width - left - 24).max(220);
        self.place(200, 72, 13, 300, 34);
        self.place(202, 72, 48, 410, 22);
        self.place(LOCK, width - 158, 24, 134, 34);
        self.place(VAULT_BADGE, width - 352, 32, 178, 23);
        self.place(205, 36, 110, 240, 22);
        self.place(LIST, 32, 148, 268, (height - 386).max(70));
        self.place(LIST_HINT, 48, 175, 232, 70);
        self.visible(LIST_HINT, self.hosts.is_empty());
        self.place(220, 36, height - 218, 240, 20);
        for (id, x, y) in [
            (SYSTEM, 32, height - 188),
            (UPTIME, 172, height - 188),
            (DISK, 32, height - 147),
            (MEMORY, 172, height - 147),
            (NEW, 32, height - 104),
            (DELETE, 172, height - 104),
        ] {
            self.place(id, x, y, 128, 34);
        }
        self.place(STATUS, 24, height - 49, width - 48, 40);
        self.place(206, left, 106, main - 265, 28);
        self.place(207, left, 139, main - 265, 22);
        self.place(CONNECT, width - 277, 112, 139, 38);
        self.place(DISCONNECT, width - 128, 112, 104, 38);
        self.place(TAB_TERMINAL, left, 176, 103, 32);
        self.place(TAB_DETAILS, left + 112, 176, 130, 32);
        self.place(ACTIVE_TITLE, left + 260, 184, main - 260, 22);
        self.place(TERMINAL, left, 224, main, height - 312);
        self.place(TERMINAL_HINT, left, height - 79, main, 23);
        for id in [
            206,
            207,
            CONNECT,
            DISCONNECT,
            TAB_TERMINAL,
            TAB_DETAILS,
            ACTIVE_TITLE,
        ] {
            self.visible(id, unlocked);
        }
        self.visible(TERMINAL, unlocked && !self.details);
        self.visible(TERMINAL_HINT, unlocked && !self.details);
        let form = main.min(760);
        let step = ((height - 385) / 5).clamp(49, 68);
        for (id, x, y, w) in [
            (NAME, left, 225, form),
            (ADDRESS, left, 225 + step, form - 120),
            (PORT, left + form - 102, 225 + step, 102),
            (USERNAME, left, 225 + step * 2, form / 2 - 10),
            (IDENTITY, left, 225 + step * 3, form),
            (SERVER_PASSWORD, left, 225 + step * 4, form),
        ] {
            self.place(id + 300, x, y, w, 20);
            self.place(id, x, y + 23, w, 26);
            self.visible(id + 300, unlocked && self.details);
            self.visible(id, unlocked && self.details);
        }
        self.place(416, left + form / 2 + 10, 225 + step * 2, form / 2 - 10, 20);
        self.place(
            AUTHENTICATION,
            left + form / 2 + 10,
            248 + step * 2,
            form / 2 - 10,
            160,
        );
        self.place(IDENTITY_NOTE, left, 278 + step * 4, form, 33);
        self.place(SAVE, left, 320 + step * 4, 146, 34);
        for id in [416, AUTHENTICATION, IDENTITY_NOTE, SAVE] {
            self.visible(id, unlocked && self.details);
        }
        let card_width = main.min(580);
        let card_x = left + (main - card_width) / 2;
        let creating = self.envelope.is_none();
        let card_height = if creating { 342 } else { 270 };
        let card_y = ((height - card_height) / 2).max(118);
        self.place(208, card_x, card_y, card_width, 40);
        self.place(203, card_x, card_y + 66, card_width, 23);
        self.place(PASSWORD, card_x, card_y + 95, card_width, 36);
        self.place(204, card_x, card_y + 144, card_width, 23);
        self.place(CONFIRM, card_x, card_y + 171, card_width, 36);
        let extra = if creating { 76 } else { 0 };
        self.place(SHOW_MASTER, card_x, card_y + 145 + extra, card_width, 25);
        self.place(UNLOCK, card_x, card_y + 184 + extra, card_width, 38);
        self.place(209, card_x, card_y + 235 + extra, card_width, 48);
        for id in [208, 203, PASSWORD, SHOW_MASTER, UNLOCK, 209] {
            self.visible(id, !unlocked);
        }
        for id in [204, CONFIRM] {
            self.visible(id, !unlocked && creating);
        }
        self.workspace_labels();
        // SAFETY: repaint is deferred, avoiding synchronous mutable state reentry during layout.
        unsafe {
            InvalidateRect(self.window, null(), 0);
            for &(_, control) in &self.controls {
                InvalidateRect(control, null(), 1);
            }
        }
    }

    fn paint(&self) {
        // SAFETY: painting is paired; the DC is borrowed only during this callback.
        unsafe {
            let mut paint = PAINTSTRUCT::default();
            let dc = BeginPaint(self.window, &mut paint);
            self.render(dc);
            EndPaint(self.window, &paint);
        }
    }

    fn render(&self, dc: HDC) {
        // SAFETY: paint/print callbacks supply a live DC; state resources remain owned during drawing.
        unsafe {
            let mut client = RECT::default();
            GetClientRect(self.window, &mut client);
            FillRect(dc, &client, self.theme.canvas.0);
            let (width, height) = self.bounds();
            let s = |v| theme::scale(v, self.theme.dpi);
            let rect = |x, y, w, h| RECT {
                left: s(x),
                top: s(y),
                right: s(x + w),
                bottom: s(y + h),
            };
            theme::rounded(dc, &rect(20, 94, 292, height - 154), theme::PANEL, s(16));
            theme::rounded(dc, &rect(24, 22, 33, 33), theme::ACCENT, s(10));
            theme::text(
                dc,
                rect(24, 22, 33, 33),
                ">_",
                self.theme.body.0,
                theme::TEXT,
                DT_CENTER | DT_VCENTER | DT_SINGLELINE,
            );
            theme::fill(dc, &rect(24, height - 60, width - 48, 1), theme::BORDER);
            if self.vault.is_some() && !self.details {
                theme::rounded(
                    dc,
                    &rect(337, 223, width - 360, height - 310),
                    theme::BORDER,
                    s(8),
                );
            }
        }
    }

    fn draw_item(&self, item: &DRAWITEMSTRUCT) {
        let dc = item.hDC;
        let id = item.CtlID as usize;
        let s = |v| theme::scale(v, self.theme.dpi);
        if id == LIST {
            theme::fill(dc, &item.rcItem, theme::PANEL);
            let Some(host) = self.hosts.get(item.itemID as usize) else {
                return;
            };
            let chosen = item.itemState & ODS_SELECTED != 0;
            if chosen {
                theme::rounded(dc, &item.rcItem, theme::SELECTED, s(10));
            }
            let rect = item.rcItem;
            if chosen {
                theme::rounded(
                    dc,
                    &RECT {
                        left: rect.left + s(3),
                        top: rect.top + s(12),
                        right: rect.left + s(6),
                        bottom: rect.bottom - s(12),
                    },
                    theme::ACCENT,
                    s(3),
                );
            }
            theme::text(
                dc,
                RECT {
                    left: rect.left + s(16),
                    top: rect.top + s(7),
                    right: rect.right - s(10),
                    bottom: rect.top + s(29),
                },
                &host.name,
                self.theme.body.0,
                theme::TEXT,
                DT_SINGLELINE | DT_END_ELLIPSIS,
            );
            theme::text(
                dc,
                RECT {
                    left: rect.left + s(16),
                    top: rect.top + s(30),
                    right: rect.right - s(10),
                    bottom: rect.bottom - s(4),
                },
                &format!("{}@{}:{}", host.username, host.address, host.port),
                self.theme.body.0,
                theme::MUTED,
                DT_SINGLELINE | DT_END_ELLIPSIS,
            );
        } else {
            let disabled = item.itemState & ODS_DISABLED != 0;
            let primary = matches!(id, UNLOCK | CONNECT | SAVE)
                || (id == TAB_TERMINAL && !self.details)
                || (id == TAB_DETAILS && self.details);
            let background = if disabled {
                theme::PANEL
            } else if item.itemState & ODS_SELECTED != 0 {
                theme::SELECTED
            } else if primary {
                theme::ACCENT
            } else {
                theme::INPUT
            };
            theme::fill(
                dc,
                &item.rcItem,
                if matches!(id, NEW | DELETE | SYSTEM | UPTIME | DISK | MEMORY) {
                    theme::PANEL
                } else {
                    theme::CANVAS
                },
            );
            theme::rounded(dc, &item.rcItem, background, s(9));
            theme::text(
                dc,
                item.rcItem,
                &self.text(id),
                self.theme.body.0,
                if disabled { theme::MUTED } else { theme::TEXT },
                DT_SINGLELINE | DT_CENTER | DT_VCENTER,
            );
            if item.itemState & ODS_FOCUS != 0 {
                let mut rect = item.rcItem;
                rect.left += s(4);
                rect.top += s(4);
                rect.right -= s(4);
                rect.bottom -= s(4);
                // SAFETY: provided owner-draw DC and local focus rectangle are valid for this callback.
                unsafe {
                    DrawFocusRect(dc, &rect);
                }
            }
        }
    }

    fn dpi_changed(&mut self, dpi: u32) -> Result<()> {
        let theme = Theme::new(dpi.max(96))?;
        // SAFETY: replace control fonts before releasing the old resources; controls borrow these handles.
        unsafe {
            for &(id, handle) in &self.controls {
                if id == TERMINAL {
                    continue;
                }
                let font = if matches!(id, 200 | 208) {
                    theme.title.0
                } else if id == 206 {
                    theme.heading.0
                } else {
                    theme.body.0
                };
                SendMessageW(handle, WM_SETFONT, font as usize, 1);
            }
            SendMessageW(
                self.control(LIST),
                LB_SETITEMHEIGHT,
                0,
                theme::scale(58, dpi) as isize,
            );
        }
        self.theme = theme;
        self.layout();
        Ok(())
    }

    fn text(&self, id: usize) -> String {
        // SAFETY: control is live; buffer holds the text and terminating code unit.
        unsafe {
            let handle = self.control(id);
            let length = GetWindowTextLengthW(handle).max(0) as usize;
            let mut buffer = vec![0_u16; length + 1];
            let written =
                GetWindowTextW(handle, buffer.as_mut_ptr(), buffer.len() as i32).max(0) as usize;
            String::from_utf16_lossy(&buffer[..written])
        }
    }

    fn password(&self, id: usize) -> Result<Secret> {
        // SAFETY: control is live and the buffer is sized for its text and terminator.
        let mut buffer = unsafe {
            let handle = self.control(id);
            let length = GetWindowTextLengthW(handle).max(0) as usize;
            let mut buffer = vec![0_u16; length + 1];
            let written =
                GetWindowTextW(handle, buffer.as_mut_ptr(), buffer.len() as i32).max(0) as usize;
            buffer.truncate(written);
            buffer
        };
        let result = String::from_utf16(&buffer)
            .map(|text| Secret(text.into_bytes()))
            .map_err(|_| "Invalid passphrase text.".into());
        for code in &mut buffer {
            // SAFETY: code points into an exclusively owned UTF-16 buffer.
            unsafe { std::ptr::write_volatile(code, 0) };
        }
        self.set(id, "");
        result
    }

    fn refresh_enabled(&self) {
        let unlocked = self.vault.is_some();
        // SAFETY: every referenced control has been created before this method is used.
        unsafe {
            for id in [
                LIST,
                NAME,
                ADDRESS,
                PORT,
                USERNAME,
                AUTHENTICATION,
                NEW,
                SAVE,
                DELETE,
                CONNECT,
                SYSTEM,
                UPTIME,
                DISK,
                MEMORY,
                LOCK,
                TAB_TERMINAL,
                TAB_DETAILS,
            ] {
                EnableWindow(self.control(id), i32::from(unlocked));
            }
            EnableWindow(self.control(PASSWORD), i32::from(!unlocked));
            EnableWindow(
                self.control(CONFIRM),
                i32::from(!unlocked && self.envelope.is_none()),
            );
            EnableWindow(self.control(UNLOCK), i32::from(!unlocked));
            EnableWindow(self.control(SHOW_MASTER), i32::from(!unlocked));
            EnableWindow(
                self.control(DISCONNECT),
                i32::from(unlocked && !self.children.is_empty()),
            );
        }
        self.refresh_authentication();
        terminal_view::attach(
            self.control(TERMINAL),
            if unlocked {
                self.children.first().map(SshSession::input)
            } else {
                None
            },
            false,
        );
        self.layout();
    }

    fn authentication(&self) -> Authentication {
        // SAFETY: asks the live combo for its selected entry.
        if unsafe { SendMessageW(self.control(AUTHENTICATION), CB_GETCURSEL, 0, 0) } == 1 {
            Authentication::Password
        } else {
            Authentication::Key
        }
    }

    fn refresh_authentication(&self) {
        let password = self.authentication() == Authentication::Password;
        // SAFETY: both edit controls exist and are owned by this window.
        unsafe {
            EnableWindow(
                self.control(IDENTITY),
                i32::from(self.vault.is_some() && !password),
            );
            EnableWindow(
                self.control(SERVER_PASSWORD),
                i32::from(self.vault.is_some() && password),
            );
        }
        if !password {
            self.set(SERVER_PASSWORD, "");
            let has_saved_password = self
                .selected
                .and_then(|index| self.hosts.get(index))
                .is_some_and(|host| host.password.is_some());
            self.set(IDENTITY_NOTE, if has_saved_password {
                "Saving key login removes the saved password. Blank identity path uses your Windows SSH agent."
            } else {
                "Use a passphrase-protected OpenSSH key. Blank path uses your Windows SSH agent."
            });
        } else if self
            .selected
            .and_then(|index| self.hosts.get(index))
            .is_some_and(|host| host.password.is_some())
        {
            self.set(IDENTITY_NOTE, "Password stored encrypted. Leave blank to keep it, or enter a replacement. Decrypted only for login.");
        } else {
            self.set(IDENTITY_NOTE, "Enter the server password. It is encrypted with your vault key when saved and decrypted only for login.");
        }
    }

    fn refresh_list(&self) {
        // SAFETY: listbox is live; LB_ADDSTRING copies each null-terminated string synchronously.
        unsafe {
            SendMessageW(self.control(LIST), LB_RESETCONTENT, 0, 0);
            for host in &self.hosts {
                let label = wide(&format!(
                    "{}  ({}@{}:{})",
                    host.name, host.username, host.address, host.port
                ));
                SendMessageW(self.control(LIST), LB_ADDSTRING, 0, label.as_ptr() as isize);
            }
            if let Some(index) = self.selected {
                SendMessageW(self.control(LIST), LB_SETCURSEL, index, 0);
            }
        }
        self.layout();
    }

    fn reset_form(&mut self) {
        self.selected = None;
        for id in [NAME, ADDRESS, USERNAME, IDENTITY, SERVER_PASSWORD] {
            self.set(id, "");
        }
        self.set(PORT, "22");
        // SAFETY: -1 clears selection in a live listbox.
        unsafe {
            SendMessageW(self.control(LIST), LB_SETCURSEL, usize::MAX, 0);
            SendMessageW(self.control(AUTHENTICATION), CB_SETCURSEL, 0, 0);
        }
        self.refresh_authentication();
        self.workspace_labels();
    }

    fn unlock(&mut self) -> Result<()> {
        if Instant::now() < self.retry_after {
            return Err("Please wait a few seconds before trying the passphrase again.".into());
        }
        self.show_master(false);
        let password = self.password(PASSWORD)?;
        if self.envelope.is_some() && password.0.is_empty() {
            return Err("Enter the original vault master passphrase to unlock.".into());
        }
        let result = if let Some(envelope) = &self.envelope {
            UnlockedVault::unlock(&password, envelope)
        } else {
            let confirmation = self.password(CONFIRM)?;
            if password.0 != confirmation.0 {
                return Err("The master passphrases do not match.".into());
            }
            let vault = UnlockedVault::create(&password)?;
            let sealed = vault.seal(&[])?;
            self.store.write(&sealed)?;
            // Verify the durable record with the same master passphrase before reporting setup success.
            self.envelope = Some(
                self.store
                    .read()?
                    .ok_or("The new vault record could not be read back.")?,
            );
            self.set(UNLOCK, "Unlock vault");
            self.refresh_enabled();
            UnlockedVault::unlock(&password, self.envelope.as_ref().unwrap())
        };
        match result {
            Ok((vault, hosts)) => {
                self.vault = Some(vault);
                self.hosts = hosts;
                self.failures = 0;
                self.last_activity = Instant::now();
                self.set(UNLOCK, "Unlock vault");
                self.refresh_enabled();
                self.refresh_list();
                self.reset_form();
                self.layout();
                self.set(
                    STATUS,
                    "Vault unlocked. Select a server to connect, or add a new server.",
                );
                Ok(())
            }
            Err(error) => {
                self.failures = self.failures.saturating_add(1);
                self.retry_after =
                    Instant::now() + Duration::from_secs(u64::from(self.failures).min(10));
                Err(error)
            }
        }
    }

    fn lock(&mut self) {
        self.show_master(false);
        for child in &mut self.children {
            child.cancel_pending_credentials();
        }
        self.vault = None;
        for host in &mut self.hosts {
            for field in [
                &mut host.name,
                &mut host.address,
                &mut host.username,
                &mut host.identity_path,
            ] {
                // SAFETY: overwriting bytes with zero preserves valid UTF-8 and the String is exclusively owned.
                for byte in unsafe { field.as_bytes_mut() } {
                    // SAFETY: byte is an exclusive reference into that live String allocation.
                    unsafe { std::ptr::write_volatile(byte, 0) };
                }
            }
        }
        self.hosts.clear();
        self.active_label = "SSH session".into();
        self.refresh_list();
        self.reset_form();
        self.set(PORT, "");
        self.set(PASSWORD, "");
        self.set(CONFIRM, "");
        self.refresh_enabled();
        self.set(
            STATUS,
            "Vault locked. Terminal hidden and input paused. Unlock to return to your session.",
        );
    }

    fn select(&mut self) {
        // SAFETY: asks the live listbox for its current selection.
        let index = unsafe { SendMessageW(self.control(LIST), LB_GETCURSEL, 0, 0) };
        if index < 0 || index as usize >= self.hosts.len() {
            return;
        }
        self.selected = Some(index as usize);
        let host = &self.hosts[index as usize];
        for (id, value) in [
            (NAME, host.name.as_str()),
            (ADDRESS, host.address.as_str()),
            (USERNAME, host.username.as_str()),
            (IDENTITY, host.identity_path.as_str()),
        ] {
            self.set(id, value);
        }
        self.set(PORT, &host.port.to_string());
        self.set(SERVER_PASSWORD, "");
        // SAFETY: host mode maps to the two entries of this live combo.
        unsafe {
            SendMessageW(
                self.control(AUTHENTICATION),
                CB_SETCURSEL,
                usize::from(host.authentication == Authentication::Password),
                0,
            );
        }
        self.refresh_authentication();
        self.workspace_labels();
    }

    fn save(&mut self) -> Result<()> {
        let vault = self.vault.as_ref().ok_or("Unlock the vault first.")?;
        let authentication = self.authentication();
        let mut saved_password = self
            .selected
            .and_then(|index| self.hosts.get(index))
            .and_then(|host| host.password.clone());
        if authentication == Authentication::Password {
            let password = self.password(SERVER_PASSWORD)?;
            if !password.0.is_empty() {
                saved_password = Some(vault.encrypt_password(&password)?);
            }
        } else {
            saved_password = None;
            self.set(SERVER_PASSWORD, "");
        }
        let host = Host {
            name: self.text(NAME).trim().into(),
            address: self.text(ADDRESS).trim().into(),
            port: self
                .text(PORT)
                .trim()
                .parse()
                .map_err(|_| "SSH port must be between 1 and 65535.")?,
            username: self.text(USERNAME).trim().into(),
            identity_path: self.text(IDENTITY).trim().into(),
            authentication,
            password: saved_password,
        };
        host.validate()?;
        let mut next = self.hosts.clone();
        let selected = if let Some(index) = self.selected {
            next[index] = host;
            index
        } else {
            next.push(host);
            next.len() - 1
        };
        let sealed = vault.seal(&next)?;
        self.store.write(&sealed)?;
        self.hosts = next;
        self.envelope = Some(sealed);
        self.selected = Some(selected);
        self.refresh_list();
        self.refresh_authentication();
        self.workspace_labels();
        self.set(
            STATUS,
            "Server saved. Select Terminal and connect when ready.",
        );
        Ok(())
    }

    fn delete(&mut self) -> Result<()> {
        let index = self.selected.ok_or("Select a saved server first.")?;
        let vault = self.vault.as_ref().ok_or("Unlock the vault first.")?;
        let mut next = self.hosts.clone();
        next.remove(index);
        let sealed = vault.seal(&next)?;
        self.store.write(&sealed)?;
        self.envelope = Some(sealed);
        self.hosts = next;
        self.reset_form();
        self.refresh_list();
        self.set(
            STATUS,
            "Server removed from the inventory. Its OpenSSH trust entry is retained.",
        );
        Ok(())
    }

    fn connect(&mut self, action: Option<ReadOnlyAction>) -> Result<()> {
        let vault = self.vault.as_ref().ok_or("Unlock the vault first.")?;
        let host = self
            .hosts
            .get(
                self.selected
                    .ok_or("Select and save a server before connecting.")?,
            )
            .ok_or("Selected server no longer exists.")?
            .clone();
        let password = if host.authentication == Authentication::Password {
            Some(
                vault.decrypt_password(
                    host.password
                        .as_ref()
                        .ok_or("The saved password is missing.")?,
                )?,
            )
        } else {
            None
        };
        self.disconnect();
        self.details = false;
        self.layout();
        let terminal = self.control(TERMINAL);
        terminal_view::attach(terminal, None, true);
        let session = super::ssh::connect(
            &self.paths,
            &host,
            action,
            password,
            terminal_view::size(terminal),
        )?;
        terminal_view::attach(terminal, Some(session.input()), false);
        self.active_label = format!("{}@{}:{}", host.username, host.address, host.port);
        self.children.push(session);
        self.refresh_enabled();
        // SAFETY: the visible terminal child can receive keyboard focus on this UI thread.
        unsafe {
            SetFocus(terminal);
        }
        self.set(STATUS, "Connecting in the built-in terminal. Verify any new host fingerprint using a trusted source.");
        Ok(())
    }

    fn disconnect(&mut self) {
        let terminal = self.control(TERMINAL);
        terminal_view::attach(terminal, None, false);
        for child in &mut self.children {
            child.cancel_pending_credentials();
            for bytes in child.finish_output() {
                terminal_view::feed(terminal, &bytes);
            }
        }
        self.children.clear();
        self.active_label.clear();
        self.refresh_enabled();
        self.set(
            STATUS,
            "Session disconnected. Terminal output remains available until the next connection.",
        );
    }

    fn confirmation(&self, id: usize) -> Result<Option<String>> {
        if id == CONNECT && !self.children.is_empty() {
            return Ok(Some(
                "Disconnect the current SSH session and connect to the selected server?".into(),
            ));
        }
        if id == DELETE || matches!(id, SYSTEM | UPTIME | DISK | MEMORY) {
            let host = self
                .hosts
                .get(self.selected.ok_or("Select a saved server first.")?)
                .ok_or("Selected server no longer exists.")?;
            if id == DELETE {
                return Ok(Some(format!(
                    "Delete {} from the local inventory?",
                    host.name
                )));
            }
            let action = match id {
                SYSTEM => ReadOnlyAction::System,
                UPTIME => ReadOnlyAction::Uptime,
                DISK => ReadOnlyAction::Disk,
                _ => ReadOnlyAction::Memory,
            };
            return Ok(Some(format!(
                "Run this read-only check on {}@{}:{}?\n\n{}\n\nOutput appears in the built-in terminal.{}",
                host.username,
                host.address,
                host.port,
                action.command(),
                if self.children.is_empty() {
                    ""
                } else {
                    " The current SSH session will disconnect."
                }
            )));
        }
        Ok(None)
    }

    fn command(&mut self, id: usize, notification: usize) -> Result<()> {
        self.last_activity = Instant::now();
        if id == LIST && notification == LBN_SELCHANGE as usize && self.vault.is_some() {
            self.select();
            return Ok(());
        }
        if id == AUTHENTICATION && notification == CBN_SELCHANGE as usize {
            self.refresh_authentication();
            return Ok(());
        }
        if notification != BN_CLICKED as usize {
            return Ok(());
        }
        match id {
            SHOW_MASTER => {
                // SAFETY: queries the live checkbox's checked state.
                let show = unsafe { SendMessageW(self.control(SHOW_MASTER), BM_GETCHECK, 0, 0) }
                    == BST_CHECKED as isize;
                self.show_master(show);
                Ok(())
            }
            UNLOCK => self.unlock(),
            LOCK => {
                self.lock();
                Ok(())
            }
            NEW if self.vault.is_some() => {
                self.reset_form();
                self.details = true;
                self.layout();
                // SAFETY: visible edit is owned by this window.
                unsafe {
                    SetFocus(self.control(NAME));
                }
                Ok(())
            }
            TAB_TERMINAL | TAB_DETAILS if self.vault.is_some() => {
                self.details = id == TAB_DETAILS;
                self.layout();
                Ok(())
            }
            DISCONNECT if self.vault.is_some() => {
                self.disconnect();
                Ok(())
            }
            SAVE => self.save(),
            DELETE => self.delete(),
            CONNECT => self.connect(None),
            SYSTEM => self.connect(Some(ReadOnlyAction::System)),
            UPTIME => self.connect(Some(ReadOnlyAction::Uptime)),
            DISK => self.connect(Some(ReadOnlyAction::Disk)),
            MEMORY => self.connect(Some(ReadOnlyAction::Memory)),
            _ => Ok(()),
        }
    }

    fn show_master(&self, show: bool) {
        // SAFETY: edits and checkbox belong to the live window; repaint shows the new masking state.
        unsafe {
            SendMessageW(
                self.control(SHOW_MASTER),
                BM_SETCHECK,
                if show { BST_CHECKED } else { BST_UNCHECKED } as usize,
                0,
            );
            for id in [PASSWORD, CONFIRM] {
                SendMessageW(
                    self.control(id),
                    EM_SETPASSWORDCHAR,
                    if show { 0 } else { b'*' as usize },
                    0,
                );
                InvalidateRect(self.control(id), null(), 1);
            }
        }
    }

    fn tick(&mut self) {
        if self.vault.is_some() && self.last_activity.elapsed() >= Duration::from_secs(600) {
            self.lock();
        }
        let terminal = self.control(TERMINAL);
        let mut exit = None;
        self.children.retain_mut(|child| {
            let protocol_input = child.input();
            for bytes in child.output() {
                terminal_view::feed_session(terminal, &bytes, &protocol_input);
            }
            if let Ok(Some(status)) = child.try_wait() {
                for bytes in child.finish_output() {
                    terminal_view::feed(terminal, &bytes);
                }
                exit = Some(status);
                false
            } else {
                true
            }
        });
        if let Some(code) = exit {
            terminal_view::attach(terminal, None, false);
            self.active_label.clear();
            self.refresh_enabled();
            self.set(STATUS, &if code == 0 { "Session finished. Its output remains in the terminal.".into() } else { format!("OpenSSH exited with code {code}. Check the terminal output and your server's address and login details.") });
        }
    }
}

fn confirm(window: HWND, text: &str) -> bool {
    let text = wide(text);
    let title = wide("SentinelSSH");
    // SAFETY: owner handle is valid and strings are null terminated and alive during the modal call.
    unsafe {
        MessageBoxW(
            window,
            text.as_ptr(),
            title.as_ptr(),
            MB_YESNO | MB_ICONQUESTION | MB_DEFBUTTON2,
        ) == IDYES
    }
}

pub fn show_error(error: &str) {
    let text = wide(error);
    let title = wide("SentinelSSH");
    // SAFETY: null owner is allowed; UTF-16 string buffers remain valid for the call.
    unsafe {
        MessageBoxW(
            null_mut(),
            text.as_ptr(),
            title.as_ptr(),
            MB_OK | MB_ICONERROR,
        );
    }
}

unsafe extern "system" fn window_proc(
    window: HWND,
    message: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    // SAFETY: GWLP_USERDATA is either zero or our owned Box<RefCell<State>> pointer.
    let pointer = unsafe { GetWindowLongPtrW(window, GWLP_USERDATA) } as *mut RefCell<State>;
    if !pointer.is_null() {
        if message == WM_NCDESTROY {
            // SAFETY: clear ownership before dropping the box to prevent reentrant access.
            unsafe {
                SetWindowLongPtrW(window, GWLP_USERDATA, 0);
                drop(Box::from_raw(pointer));
            }
        } else {
            // SAFETY: the box remains owned by the live window until WM_NCDESTROY.
            let cell = unsafe { &*pointer };
            if message == WM_CLOSE {
                let active = match cell.try_borrow_mut() {
                    Ok(state) => !state.children.is_empty(),
                    Err(_) => {
                        // SAFETY: defer teardown until the current state operation has released its borrow.
                        unsafe {
                            PostMessageW(window, WM_CLOSE, 0, 0);
                        }
                        return 0;
                    }
                };
                if active
                    && !confirm(
                        window,
                        "Close SentinelSSH and disconnect the active SSH session?",
                    )
                {
                    return 0;
                }
                // SAFETY: modal close may dispatch nested destruction; only destroy if ownership is unchanged.
                unsafe {
                    if GetWindowLongPtrW(window, GWLP_USERDATA) == pointer as isize {
                        DestroyWindow(window);
                    }
                }
                return 0;
            }
            if matches!(
                message,
                WM_PAINT
                    | WM_PRINTCLIENT
                    | WM_DRAWITEM
                    | WM_CTLCOLORSTATIC
                    | WM_CTLCOLOREDIT
                    | WM_CTLCOLORLISTBOX
                    | WM_CTLCOLORBTN
            ) && let Ok(state) = cell.try_borrow()
            {
                match message {
                    WM_PAINT => {
                        state.paint();
                        return 0;
                    }
                    WM_PRINTCLIENT => {
                        state.render(wparam as HDC);
                        return 0;
                    }
                    WM_DRAWITEM if lparam != 0 => {
                        // SAFETY: Windows supplies a valid DRAWITEMSTRUCT for this synchronous owner-draw message.
                        state.draw_item(unsafe { &*(lparam as *const DRAWITEMSTRUCT) });
                        return 1;
                    }
                    WM_CTLCOLORSTATIC | WM_CTLCOLOREDIT | WM_CTLCOLORLISTBOX | WM_CTLCOLORBTN => {
                        // SAFETY: colour messages supply live DC/control handles, borrowed for this callback only.
                        unsafe {
                            let dc = wparam as HDC;
                            let id = GetDlgCtrlID(lparam as HWND) as usize;
                            let input = message == WM_CTLCOLOREDIT
                                || matches!(
                                    id,
                                    PASSWORD
                                        | CONFIRM
                                        | NAME
                                        | ADDRESS
                                        | PORT
                                        | USERNAME
                                        | IDENTITY
                                        | SERVER_PASSWORD
                                        | AUTHENTICATION
                                );
                            let panel = matches!(id, LIST | LIST_HINT | 205 | 220);
                            let colour = if input {
                                theme::INPUT
                            } else if panel {
                                theme::PANEL
                            } else {
                                theme::CANVAS
                            };
                            SetBkColor(dc, theme::color(colour));
                            SetTextColor(
                                dc,
                                theme::color(if matches!(id, 200 | 206 | 208) || input {
                                    theme::TEXT
                                } else if id == VAULT_BADGE && state.vault.is_some() {
                                    theme::GREEN
                                } else {
                                    theme::MUTED
                                }),
                            );
                            return if input {
                                state.theme.input.0
                            } else if panel {
                                state.theme.panel.0
                            } else {
                                state.theme.canvas.0
                            } as isize;
                        }
                    }
                    _ => {}
                }
            }
            // Release the state borrow before modal dialogs so workstation lock/suspend
            // messages can still lock the vault while a confirmation is visible.
            if message == WM_COMMAND && (wparam >> 16) & 0xffff == BN_CLICKED as usize {
                let preview = cell
                    .try_borrow()
                    .ok()
                    .map(|state| state.confirmation(wparam & 0xffff));
                if let Some(preview) = preview {
                    match preview {
                        Ok(Some(text)) if !confirm(window, &text) => return 0,
                        Err(error) => {
                            if let Ok(state) = cell.try_borrow() {
                                state.set(STATUS, &error);
                            }
                            return 0;
                        }
                        _ => {}
                    }
                }
            }
            // A modal dialog may dispatch a nested close/destroy message. Revalidate
            // the window's ownership before using its state again.
            // SAFETY: querying window user data is allowed even if the handle was destroyed.
            if unsafe { GetWindowLongPtrW(window, GWLP_USERDATA) } != pointer as isize {
                return 0;
            }
            // SAFETY: the ownership check above confirms the state is still attached to this window.
            let cell = unsafe { &*pointer };
            // Native controls send synchronous notifications. RefCell prevents mutable aliasing on reentry.
            if let Ok(mut state) = cell.try_borrow_mut() {
                match message {
                    WM_ERASEBKGND => return 1,
                    WM_SIZE => {
                        state.layout();
                        return 0;
                    }
                    WM_GETMINMAXINFO if lparam != 0 => {
                        // SAFETY: Windows supplies writable MINMAXINFO for this callback.
                        unsafe {
                            let info = &mut *(lparam as *mut MINMAXINFO);
                            info.ptMinTrackSize.x = theme::scale(960, state.theme.dpi);
                            info.ptMinTrackSize.y = theme::scale(660, state.theme.dpi);
                        }
                        return 0;
                    }
                    WM_DPICHANGED if lparam != 0 => {
                        if let Err(error) = state.dpi_changed((wparam & 0xffff) as u32) {
                            state.set(STATUS, &error);
                        }
                        // SAFETY: suggested bounds are supplied by Windows; changing the parent resizes its children.
                        unsafe {
                            let rect = &*(lparam as *const RECT);
                            SetWindowPos(
                                window,
                                null_mut(),
                                rect.left,
                                rect.top,
                                rect.right - rect.left,
                                rect.bottom - rect.top,
                                SWP_NOACTIVATE | SWP_NOZORDER,
                            );
                        }
                        state.layout();
                        return 0;
                    }
                    terminal_view::RESIZED => {
                        if let Some(child) = state.children.first() {
                            let (columns, rows) = terminal_view::size(state.control(TERMINAL));
                            if let Err(error) = child.resize(columns, rows) {
                                state.set(STATUS, &error);
                            }
                        }
                        return 0;
                    }
                    terminal_view::ACTIVITY => {
                        state.last_activity = Instant::now();
                        return 0;
                    }
                    WM_COMMAND => {
                        let result = state.command(wparam & 0xffff, (wparam >> 16) & 0xffff);
                        if let Err(error) = result {
                            state.set(STATUS, &error);
                        }
                        return 0;
                    }
                    WM_TIMER => {
                        state.tick();
                        return 0;
                    }
                    WM_WTSSESSION_CHANGE if wparam == WTS_SESSION_LOCK as usize => {
                        state.lock();
                        return 0;
                    }
                    WM_POWERBROADCAST if wparam == PBT_APMSUSPEND as usize => {
                        state.lock();
                        return 1;
                    }
                    _ => {}
                }
            } else if matches!(
                message,
                WM_COMMAND | WM_TIMER | WM_WTSSESSION_CHANGE | WM_POWERBROADCAST
            ) {
                return 0;
            }
        }
    }
    if message == WM_DESTROY {
        // SAFETY: window is being destroyed; notification and timer removal are valid at this point.
        unsafe {
            WTSUnRegisterSessionNotification(window);
            KillTimer(window, 1);
            PostQuitMessage(0);
        }
        return 0;
    }
    // SAFETY: forwards messages not handled by our procedure with their unchanged parameters.
    unsafe { DefWindowProcW(window, message, wparam, lparam) }
}

fn create_window(paths: AppPaths) -> Result<HWND> {
    let state = State::new(paths)?;
    let class = wide("SentinelSSH.NativeWindow.v1");
    let title = wide("SentinelSSH");
    // SAFETY: all Windows pointers refer to live buffers; null module name selects the current executable.
    let window = unsafe {
        let instance = GetModuleHandleW(null());
        let initial_dpi = GetDpiForSystem().max(96);
        let screen_width = GetSystemMetrics(SM_CXSCREEN);
        let screen_height = GetSystemMetrics(SM_CYSCREEN);
        let definition = WNDCLASSW {
            lpfnWndProc: Some(window_proc),
            hInstance: instance,
            lpszClassName: class.as_ptr(),
            hCursor: LoadCursorW(null_mut(), IDC_ARROW),
            ..Default::default()
        };
        // A prior test/window may have registered the same class; CreateWindow validates it below.
        RegisterClassW(&definition);
        CreateWindowExW(
            0,
            class.as_ptr(),
            title.as_ptr(),
            WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN,
            CW_USEDEFAULT,
            CW_USEDEFAULT,
            theme::scale(1260, initial_dpi)
                .min(screen_width - 40)
                .max(theme::scale(960, initial_dpi).min(screen_width)),
            theme::scale(850, initial_dpi)
                .min(screen_height - 60)
                .max(theme::scale(660, initial_dpi).min(screen_height - 40)),
            null_mut(),
            null_mut(),
            instance,
            null(),
        )
    };
    if window.is_null() {
        return Err(format!(
            "Cannot create desktop window: {}",
            std::io::Error::last_os_error()
        ));
    }
    let dark_caption = 1i32;
    // SAFETY: Windows copies this BOOL value synchronously; unsupported caption styling is harmless.
    unsafe {
        DwmSetWindowAttribute(
            window,
            DWMWA_USE_IMMERSIVE_DARK_MODE as u32,
            std::ptr::addr_of!(dark_caption).cast(),
            std::mem::size_of_val(&dark_caption) as u32,
        );
    }
    let pointer = Box::into_raw(Box::new(RefCell::new(state)));
    // SAFETY: attaches ownership to the live window, which releases it only in WM_NCDESTROY.
    unsafe {
        SetWindowLongPtrW(window, GWLP_USERDATA, pointer as isize);
    }
    // SAFETY: attached pointer remains valid until we destroy the window.
    let initialized = unsafe { &*pointer }.borrow_mut().initialize(window);
    if let Err(error) = initialized {
        // SAFETY: destroying the live window releases its attached state.
        unsafe {
            DestroyWindow(window);
        }
        return Err(error);
    }
    Ok(window)
}

pub fn run() -> Result<()> {
    // SAFETY: choose per-monitor DPI scaling before any application windows exist.
    unsafe {
        SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
    }
    let window = create_window(AppPaths::discover()?)?;
    // SAFETY: shows a live window; the message struct is initialized and reused by GetMessage.
    unsafe {
        ShowWindow(window, SW_SHOW);
        let mut message = MSG::default();
        loop {
            let result = GetMessageW(&mut message, null_mut(), 0, 0);
            if result == 0 {
                break;
            }
            if result == -1 {
                DestroyWindow(window);
                return Err("Windows message loop failed.".into());
            }
            let pointer = GetWindowLongPtrW(window, GWLP_USERDATA) as *const RefCell<State>;
            let terminal_focused = !pointer.is_null()
                && (*pointer)
                    .try_borrow()
                    .is_ok_and(|state| GetFocus() == state.control(TERMINAL));
            if terminal_focused || IsDialogMessageW(window, &message) == 0 {
                TranslateMessage(&message);
                DispatchMessageW(&message);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn preview(window: HWND, name: &str) {
        let Some(directory) = std::env::var_os("SENTINEL_UI_PREVIEW_DIR") else {
            return;
        };
        let directory = std::path::PathBuf::from(directory);
        std::fs::create_dir_all(&directory).unwrap();
        // SAFETY: screenshot renders only this test's disposable window, never other windows or the desktop.
        unsafe {
            ShowWindow(window, SW_SHOWNOACTIVATE);
            SetWindowPos(
                window,
                HWND_TOP,
                0,
                0,
                0,
                0,
                SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE,
            );
            RedrawWindow(
                window,
                null(),
                null_mut(),
                RDW_INVALIDATE | RDW_ERASE | RDW_ALLCHILDREN | RDW_UPDATENOW,
            );
            let mut bounds = RECT::default();
            GetClientRect(window, &mut bounds);
            let source = GetDC(window);
            let dc = CreateCompatibleDC(source);
            let bitmap = CreateCompatibleBitmap(source, bounds.right, bounds.bottom);
            assert!(!dc.is_null() && !bitmap.is_null());
            let old = SelectObject(dc, bitmap);
            BitBlt(dc, 0, 0, bounds.right, bounds.bottom, source, 0, 0, SRCCOPY);
            SelectObject(dc, old);
            let mut info = BITMAPINFO {
                bmiHeader: BITMAPINFOHEADER {
                    biSize: std::mem::size_of::<BITMAPINFOHEADER>() as u32,
                    biWidth: bounds.right,
                    biHeight: -bounds.bottom,
                    biPlanes: 1,
                    biBitCount: 32,
                    biCompression: BI_RGB,
                    ..Default::default()
                },
                ..Default::default()
            };
            let mut pixels = vec![0u8; bounds.right as usize * bounds.bottom as usize * 4];
            assert_ne!(
                GetDIBits(
                    dc,
                    bitmap,
                    0,
                    bounds.bottom as u32,
                    pixels.as_mut_ptr().cast(),
                    &mut info,
                    DIB_RGB_COLORS
                ),
                0
            );
            DeleteObject(bitmap);
            DeleteDC(dc);
            ReleaseDC(window, source);
            ShowWindow(window, SW_HIDE);
            let mut bytes = Vec::with_capacity(pixels.len() + 54);
            bytes.extend_from_slice(b"BM");
            bytes.extend_from_slice(&((pixels.len() + 54) as u32).to_le_bytes());
            bytes.extend_from_slice(&[0; 4]);
            bytes.extend_from_slice(&54u32.to_le_bytes());
            bytes.extend_from_slice(&40u32.to_le_bytes());
            bytes.extend_from_slice(&bounds.right.to_le_bytes());
            bytes.extend_from_slice(&(-bounds.bottom).to_le_bytes());
            bytes.extend_from_slice(&1u16.to_le_bytes());
            bytes.extend_from_slice(&32u16.to_le_bytes());
            bytes.extend_from_slice(&[0; 24]);
            bytes.extend_from_slice(&pixels);
            std::fs::write(directory.join(format!("{name}.bmp")), bytes).unwrap();
        }
    }

    #[test]
    fn native_controls_save_lock_and_reopen_encrypted_inventory() {
        const MASTER: &str = "  test passphrase ঢাকা e\u{301} with spaces  ";
        let root = std::env::temp_dir().join(format!(
            "sentinel-ui-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        super::super::paths::secure_directory(&root).unwrap();
        let make_paths = || AppPaths {
            root: root.clone(),
            database_dir: root.join("database"),
            known_hosts: root.join("known_hosts"),
            ssh: root.join("no-ssh.exe"),
        };
        let window = create_window(make_paths()).unwrap();
        preview(window, "vault-setup");
        // SAFETY: test owns the window and its attached state throughout each scoped borrow.
        unsafe {
            let cell = &*(GetWindowLongPtrW(window, GWLP_USERDATA) as *const RefCell<State>);
            {
                let mut state = cell.borrow_mut();
                state.set(PASSWORD, MASTER);
                state.set(CONFIRM, MASTER);
                state.show_master(true);
                assert_eq!(
                    SendMessageW(state.control(PASSWORD), EM_GETPASSWORDCHAR, 0, 0),
                    0
                );
                assert_eq!(state.password(CONFIRM).unwrap().0, MASTER.as_bytes());
                state.set(CONFIRM, MASTER);
                state.unlock().unwrap();
                assert_ne!(
                    SendMessageW(state.control(PASSWORD), EM_GETPASSWORDCHAR, 0, 0),
                    0
                );
                assert_eq!(
                    SendMessageW(state.control(SHOW_MASTER), BM_GETCHECK, 0, 0),
                    BST_UNCHECKED as isize
                );
                assert!(state.text(PASSWORD).is_empty());
                assert!(state.text(CONFIRM).is_empty());
                state.set(NAME, "confidential-test-name");
                state.set(ADDRESS, "test.example.com");
                state.set(USERNAME, "deploy");
                state.save().unwrap();
                assert_eq!(state.hosts.len(), 1);
                assert_eq!(state.hosts[0].authentication, Authentication::Key);
                state.details = true;
                state.layout();
            }
            preview(window, "server-details");
            {
                let mut state = cell.borrow_mut();
                state.details = false;
                state.layout();
                terminal_view::feed(state.control(TERMINAL), b"\x1b[38;2;126;231;135mdeploy@demo:~$\x1b[0m uname -a\r\nLinux demo 6.8.0 x86_64 GNU/Linux\r\n\r\n\x1b[38;2;126;231;135mdeploy@demo:~$\x1b[0m df -h /\r\nFilesystem      Size  Used Avail Use% Mounted on\r\n/dev/vda1        80G   12G   68G  15% /\r\n\r\n\x1b[38;2;126;231;135mdeploy@demo:~$\x1b[0m ");
            }
            preview(window, "terminal-workspace");
            {
                let mut state = cell.borrow_mut();
                SendMessageW(state.control(AUTHENTICATION), CB_SETCURSEL, 1, 0);
                state
                    .command(AUTHENTICATION, CBN_SELCHANGE as usize)
                    .unwrap();
                assert_eq!(
                    windows_sys::Win32::UI::Input::KeyboardAndMouse::IsWindowEnabled(
                        state.control(IDENTITY)
                    ),
                    0
                );
                assert_ne!(
                    windows_sys::Win32::UI::Input::KeyboardAndMouse::IsWindowEnabled(
                        state.control(SERVER_PASSWORD)
                    ),
                    0
                );
                state.set(SERVER_PASSWORD, "disposable saved SSH password");
                state.save().unwrap();
                assert_eq!(state.hosts[0].authentication, Authentication::Password);
                assert!(state.text(SERVER_PASSWORD).is_empty());
                let original = state.hosts[0].password.clone();
                state.select();
                assert!(state.text(SERVER_PASSWORD).is_empty());
                state.save().unwrap();
                assert_eq!(state.hosts[0].password, original);
                state.set(SERVER_PASSWORD, "replacement disposable SSH password");
                state.save().unwrap();
                assert_ne!(state.hosts[0].password, original);
                assert_eq!(SendMessageW(state.control(LIST), LB_GETCOUNT, 0, 0), 1);
                assert!(
                    !String::from_utf8_lossy(state.envelope.as_ref().unwrap())
                        .contains("confidential-test-name")
                );
                state.last_activity = Instant::now() - Duration::from_secs(601);
                state.set(SERVER_PASSWORD, "unsaved password draft");
                state.tick();
                assert!(state.hosts.is_empty());
                assert!(state.vault.is_none());
                assert!(state.text(SERVER_PASSWORD).is_empty());
                assert_eq!(SendMessageW(state.control(LIST), LB_GETCOUNT, 0, 0), 0);
                assert_eq!(
                    windows_sys::Win32::UI::WindowsAndMessaging::IsWindowVisible(
                        state.control(TERMINAL)
                    ),
                    0
                );
            }
            {
                let mut state = cell.borrow_mut();
                state.set(PASSWORD, MASTER);
                state.unlock().unwrap();
            }
            SendMessageW(window, WM_WTSSESSION_CHANGE, WTS_SESSION_LOCK as usize, 0);
            assert!(cell.borrow().vault.is_none());
            {
                let mut state = cell.borrow_mut();
                state.set(PASSWORD, MASTER);
                state.unlock().unwrap();
            }
            SendMessageW(window, WM_POWERBROADCAST, PBT_APMSUSPEND as usize, 0);
            assert!(cell.borrow().vault.is_none());
            DestroyWindow(window);
            let reopened = create_window(make_paths()).unwrap();
            let reopened_cell =
                &*(GetWindowLongPtrW(reopened, GWLP_USERDATA) as *const RefCell<State>);
            {
                let mut state = reopened_cell.borrow_mut();
                state.set(PASSWORD, MASTER);
                state.unlock().unwrap();
                assert_eq!(state.hosts[0].name, "confidential-test-name");
                assert_eq!(state.hosts[0].authentication, Authentication::Password);
                state.selected = Some(0);
                SendMessageW(state.control(LIST), LB_SETCURSEL, 0, 0);
                state.select();
                assert!(state.text(SERVER_PASSWORD).is_empty());
                assert_eq!(
                    state
                        .vault
                        .as_ref()
                        .unwrap()
                        .decrypt_password(state.hosts[0].password.as_ref().unwrap())
                        .unwrap()
                        .0,
                    b"replacement disposable SSH password"
                );
            }
            DestroyWindow(reopened);
        }
        for entry in std::fs::read_dir(root.join("database")).unwrap() {
            let path = entry.unwrap().path();
            if path.is_file() {
                let bytes = std::fs::read(path).unwrap();
                assert!(
                    !bytes
                        .windows(b"confidential-test-name".len())
                        .any(|slice| slice == b"confidential-test-name")
                );
                for fixture in [
                    "disposable saved SSH password",
                    "replacement disposable SSH password",
                    "unsaved password draft",
                ] {
                    let utf16: Vec<_> = fixture.encode_utf16().flat_map(u16::to_le_bytes).collect();
                    for secret in [fixture.as_bytes(), utf16.as_slice()] {
                        assert!(!bytes.windows(secret.len()).any(|slice| slice == secret));
                    }
                }
            }
        }
    }
}
