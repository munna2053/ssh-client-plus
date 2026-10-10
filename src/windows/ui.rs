use super::{
    crypto::Secret, paths::AppPaths, ssh::SshSession, storage::RecordStore, vault::UnlockedVault,
    wide,
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
    Foundation::{HWND, LPARAM, LRESULT, WPARAM},
    Graphics::Gdi::{COLOR_WINDOW, DEFAULT_GUI_FONT, GetStockObject},
    System::{LibraryLoader::GetModuleHandleW, RemoteDesktop::*},
    UI::{Controls::*, Input::KeyboardAndMouse::EnableWindow, WindowsAndMessaging::*},
};

const PASSWORD: usize = 101;
const CONFIRM: usize = 102;
const UNLOCK: usize = 103;
const LOCK: usize = 104;
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
            SendMessageW(
                handle,
                WM_SETFONT,
                GetStockObject(DEFAULT_GUI_FONT) as usize,
                1,
            );
        }
        self.controls.push((id, handle));
        Ok(())
    }

    fn initialize(&mut self, window: HWND) -> Result<()> {
        let edit = WS_BORDER | WS_TABSTOP | ES_AUTOHSCROLL as u32;
        let button = WS_TABSTOP | BS_PUSHBUTTON as u32;
        self.add(window, "STATIC", "SentinelSSH", 201, 0, [24, 18, 550, 26])?;
        self.add(
            window,
            "STATIC",
            "Local encrypted inventory  |  Windows OpenSSH",
            202,
            0,
            [24, 50, 850, 24],
        )?;
        self.add(
            window,
            "STATIC",
            "Master passphrase",
            203,
            0,
            [24, 90, 170, 22],
        )?;
        self.add(
            window,
            "EDIT",
            "",
            PASSWORD,
            edit | ES_PASSWORD as u32,
            [200, 86, 340, 28],
        )?;
        self.add(
            window,
            "STATIC",
            "Confirm on first setup",
            204,
            0,
            [24, 128, 170, 22],
        )?;
        self.add(
            window,
            "EDIT",
            "",
            CONFIRM,
            edit | ES_PASSWORD as u32,
            [200, 124, 340, 28],
        )?;
        self.add(window, "BUTTON", "", UNLOCK, button, [558, 86, 164, 30])?;
        self.add(
            window,
            "BUTTON",
            "Lock vault",
            LOCK,
            button,
            [740, 86, 128, 30],
        )?;
        self.add(
            window,
            "STATIC",
            "Saved servers",
            205,
            0,
            [24, 185, 300, 22],
        )?;
        self.add(
            window,
            "LISTBOX",
            "",
            LIST,
            WS_BORDER | WS_VSCROLL | WS_TABSTOP | LBS_NOTIFY as u32,
            [24, 215, 310, 341],
        )?;
        self.add(
            window,
            "BUTTON",
            "New server",
            NEW,
            button,
            [24, 576, 144, 30],
        )?;
        self.add(
            window,
            "BUTTON",
            "Delete",
            DELETE,
            button,
            [184, 576, 150, 30],
        )?;
        for (index, (id, label)) in [
            (NAME, "Display name"),
            (ADDRESS, "Hostname / IP"),
            (PORT, "SSH port"),
            (USERNAME, "Linux username"),
        ]
        .into_iter()
        .enumerate()
        {
            let y = 218 + index as i32 * 44;
            self.add(
                window,
                "STATIC",
                label,
                210 + index,
                0,
                [360, y + 4, 142, 22],
            )?;
            self.add(window, "EDIT", "", id, edit, [508, y, 360, 28])?;
        }
        self.add(
            window,
            "STATIC",
            "Login method",
            215,
            0,
            [360, 398, 142, 22],
        )?;
        self.add(
            window,
            "COMBOBOX",
            "",
            AUTHENTICATION,
            WS_TABSTOP | WS_VSCROLL | CBS_DROPDOWNLIST as u32,
            [508, 394, 360, 150],
        )?;
        // SAFETY: live combo copies each string; zero selects the key login default.
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
        }
        self.add(
            window,
            "STATIC",
            "Identity file path",
            216,
            0,
            [360, 442, 142, 22],
        )?;
        self.add(window, "EDIT", "", IDENTITY, edit, [508, 438, 360, 28])?;
        self.add(
            window,
            "STATIC",
            "Server password",
            217,
            0,
            [360, 486, 142, 22],
        )?;
        self.add(
            window,
            "EDIT",
            "",
            SERVER_PASSWORD,
            edit | ES_PASSWORD as u32,
            [508, 482, 360, 28],
        )?;
        self.add(
            window,
            "STATIC",
            "Use a passphrase-protected OpenSSH key. Blank path uses your Windows SSH agent.",
            IDENTITY_NOTE,
            0,
            [360, 520, 508, 44],
        )?;
        self.add(
            window,
            "BUTTON",
            "Save server",
            SAVE,
            button,
            [508, 576, 162, 30],
        )?;
        self.add(
            window,
            "BUTTON",
            "Open SSH terminal",
            CONNECT,
            button,
            [690, 576, 178, 30],
        )?;
        self.add(
            window,
            "STATIC",
            "Read-only checks (select a saved server)",
            220,
            0,
            [24, 626, 800, 22],
        )?;
        for (index, (id, text)) in [
            (SYSTEM, "System info"),
            (UPTIME, "Uptime"),
            (DISK, "Disk usage"),
            (MEMORY, "Memory"),
        ]
        .into_iter()
        .enumerate()
        {
            self.add(
                window,
                "BUTTON",
                text,
                id,
                button,
                [24 + index as i32 * 213, 660, 194, 30],
            )?;
        }
        self.add(window, "STATIC", "", STATUS, 0, [24, 710, 844, 65])?;
        // SAFETY: each edit control exists and supports EM_SETLIMITTEXT.
        unsafe {
            SendMessageW(self.control(PASSWORD), EM_SETLIMITTEXT, 1024, 0);
            SendMessageW(self.control(CONFIRM), EM_SETLIMITTEXT, 1024, 0);
            SendMessageW(self.control(SERVER_PASSWORD), EM_SETLIMITTEXT, 1022, 0);
            for id in [NAME, ADDRESS, PORT, USERNAME, IDENTITY] {
                SendMessageW(self.control(id), EM_SETLIMITTEXT, 2048, 0);
            }
            if SetTimer(window, 1, 1000, None) == 0 {
                return Err("Cannot start the vault idle-lock timer.".into());
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
        self.refresh_enabled();
        self.set(STATUS, if self.paths.ssh.is_file() { "Windows OpenSSH detected. Unlock your vault to manage servers. First connections ask you to verify the host fingerprint in the SSH console." } else { "Windows OpenSSH Client was not found. Enable it in Windows Settings > Optional features. You can still set up the host vault." });
        Ok(())
    }

    fn set(&self, id: usize, value: &str) {
        let value = wide(value);
        // SAFETY: handle belongs to this window and UTF-16 text lives until the synchronous call returns.
        unsafe {
            SetWindowTextW(self.control(id), value.as_ptr());
        }
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
            ] {
                EnableWindow(self.control(id), i32::from(unlocked));
            }
            EnableWindow(self.control(PASSWORD), i32::from(!unlocked));
            EnableWindow(
                self.control(CONFIRM),
                i32::from(!unlocked && self.envelope.is_none()),
            );
            EnableWindow(self.control(UNLOCK), i32::from(!unlocked));
        }
        self.refresh_authentication();
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
    }

    fn unlock(&mut self) -> Result<()> {
        if Instant::now() < self.retry_after {
            return Err("Please wait a few seconds before trying the passphrase again.".into());
        }
        let password = self.password(PASSWORD)?;
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
            self.envelope = Some(sealed);
            Ok((vault, vec![]))
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
                self.set(STATUS, "Vault unlocked. Add a server or select a saved server. Changes are encrypted and committed to the local database.");
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
        self.refresh_list();
        self.reset_form();
        self.set(PORT, "");
        self.set(PASSWORD, "");
        self.set(CONFIRM, "");
        self.refresh_enabled();
        self.set(STATUS, "Vault locked. Existing SSH consoles and identities in your Windows SSH agent remain available independently.");
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
        self.set(STATUS, "Server saved. The database and transaction logs receive an encrypted inventory envelope.");
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
            .ok_or("Selected server no longer exists.")?;
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
        self.children
            .push(super::ssh::connect(&self.paths, host, action, password)?);
        self.set(STATUS, "OpenSSH launched in its own console. Verify any new host fingerprint using a trusted source. A changed fingerprint blocks the connection.");
        Ok(())
    }

    fn confirmation(&self, id: usize) -> Result<Option<String>> {
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
                "Run this read-only check on {}@{}:{}?\n\n{}\n\nOutput appears in a Windows SSH console.",
                host.username,
                host.address,
                host.port,
                action.command()
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
            UNLOCK => self.unlock(),
            LOCK => {
                self.lock();
                Ok(())
            }
            NEW if self.vault.is_some() => {
                self.reset_form();
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

    fn tick(&mut self) {
        if self.vault.is_some() && self.last_activity.elapsed() >= Duration::from_secs(600) {
            self.lock();
        }
        let mut failed_exit = None;
        self.children.retain_mut(|child| {
            if let Ok(Some(status)) = child.try_wait() {
                if status != 0 {
                    failed_exit = Some(status);
                }
                false
            } else {
                true
            }
        });
        if let Some(code) = failed_exit {
            self.set(STATUS, &format!("OpenSSH exited with code {code}. Check the host address, trust decision, and login credentials; retry from the server list."));
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
    let title = wide("SentinelSSH — Rust native preview");
    // SAFETY: all Windows pointers refer to live buffers; null module name selects the current executable.
    let window = unsafe {
        let instance = GetModuleHandleW(null());
        let definition = WNDCLASSW {
            lpfnWndProc: Some(window_proc),
            hInstance: instance,
            lpszClassName: class.as_ptr(),
            hCursor: LoadCursorW(null_mut(), IDC_ARROW),
            hbrBackground: (COLOR_WINDOW + 1) as *mut _,
            ..Default::default()
        };
        // A prior test/window may have registered the same class; CreateWindow validates it below.
        RegisterClassW(&definition);
        CreateWindowExW(
            0,
            class.as_ptr(),
            title.as_ptr(),
            WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
            CW_USEDEFAULT,
            CW_USEDEFAULT,
            916,
            840,
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
            if IsDialogMessageW(window, &message) == 0 {
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

    #[test]
    fn native_controls_save_lock_and_reopen_encrypted_inventory() {
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
        // SAFETY: test owns the window and its attached state throughout each scoped borrow.
        unsafe {
            let cell = &*(GetWindowLongPtrW(window, GWLP_USERDATA) as *const RefCell<State>);
            {
                let mut state = cell.borrow_mut();
                state.set(PASSWORD, "test passphrase with many words");
                state.set(CONFIRM, "test passphrase with many words");
                state.unlock().unwrap();
                assert!(state.text(PASSWORD).is_empty());
                assert!(state.text(CONFIRM).is_empty());
                state.set(NAME, "confidential-test-name");
                state.set(ADDRESS, "test.example.com");
                state.set(USERNAME, "deploy");
                state.save().unwrap();
                assert_eq!(state.hosts.len(), 1);
                assert_eq!(state.hosts[0].authentication, Authentication::Key);
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
            }
            {
                let mut state = cell.borrow_mut();
                state.set(PASSWORD, "test passphrase with many words");
                state.unlock().unwrap();
            }
            SendMessageW(window, WM_WTSSESSION_CHANGE, WTS_SESSION_LOCK as usize, 0);
            assert!(cell.borrow().vault.is_none());
            {
                let mut state = cell.borrow_mut();
                state.set(PASSWORD, "test passphrase with many words");
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
                state.set(PASSWORD, "test passphrase with many words");
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
