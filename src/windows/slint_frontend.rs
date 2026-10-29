use super::{
    crypto::Secret,
    keygen::{self, KeyGeneration},
    paths::AppPaths,
    ssh::SshSession,
    storage::RecordStore,
    terminal_view,
    vault::UnlockedVault,
    wide,
};
use crate::{
    Result,
    core::{Authentication, BUILTIN_SHORTCUTS, CommandShortcut, Host, MAX_SHORTCUTS},
};
use raw_window_handle::{HasWindowHandle, RawWindowHandle};
use slint::{ComponentHandle, ModelRc, VecModel};
use std::{
    cell::{Cell, RefCell},
    rc::{Rc, Weak},
    time::{Duration, Instant},
};
use windows_sys::Win32::{
    Foundation::*,
    Graphics::Gdi::*,
    System::RemoteDesktop::*,
    UI::{
        HiDpi::GetDpiForWindow,
        Input::KeyboardAndMouse::SetFocus,
        Shell::{DefSubclassProc, RemoveWindowSubclass, SetWindowSubclass},
        WindowsAndMessaging::*,
    },
};

slint::slint! {
    export { Workspace, ServerRow, SessionRow, ShortcutRow } from "ui/workspace.slint";
}

const MAX_TABS: usize = 16;
const TERMINAL_ID: usize = 20000;
const SESSION_CLOSE_PREFERENCE: &str = "skip-session-close-confirmation";

fn session_close_confirmation_disabled(root: &std::path::Path) -> bool {
    let path = root.join(SESSION_CLOSE_PREFERENCE);
    super::paths::reject_reparse_point(&path).is_ok()
        && std::fs::read(path).is_ok_and(|bytes| bytes == b"skip\n")
}

fn remember_session_close_preference(root: &std::path::Path) -> Result<()> {
    let path = root.join(SESSION_CLOSE_PREFERENCE);
    super::paths::reject_reparse_point(&path)?;
    std::fs::write(path, b"skip\n")
        .map_err(|error| format!("Could not save the session-close preference: {error}"))
}

struct Tab {
    name: String,
    terminal: HWND,
    session: Option<SshSession>,
    input_attached: bool,
    bounds: Option<[i32; 4]>,
    shown: bool,
}

struct Controller {
    ui: slint::Weak<Workspace>,
    window: HWND,
    paths: AppPaths,
    store: RecordStore,
    envelope: Option<Vec<u8>>,
    vault: Option<UnlockedVault>,
    hosts: Vec<Host>,
    selected: Option<usize>,
    tabs: Vec<Tab>,
    active: Option<usize>,
    empty_terminal: HWND,
    empty_bounds: Option<[i32; 4]>,
    empty_shown: bool,
    last_activity: Instant,
    retry_after: Instant,
    failures: u32,
    preview: bool,
    skip_session_close_confirmation: bool,
    pending_close: Option<usize>,
    key_generation: Option<KeyGeneration>,
}

fn clear_string(value: &mut String) {
    // SAFETY: writing zeros preserves UTF-8 and this String is exclusively owned.
    for byte in unsafe { value.as_bytes_mut() } {
        // SAFETY: each byte is a valid exclusive reference into the owned buffer.
        unsafe {
            std::ptr::write_volatile(byte, 0);
        }
    }
    value.clear();
}

impl Controller {
    fn new(ui: &Workspace, window: HWND, paths: AppPaths, preview: bool) -> Result<Self> {
        let store = RecordStore::open(&paths.database_dir)?;
        let envelope = store.read()?;
        let skip_session_close_confirmation = session_close_confirmation_disabled(&paths.root);
        let empty_terminal = terminal_view::create(window, TERMINAL_ID)?;
        // SAFETY: hide the newly created child until the controller lays it out.
        unsafe {
            ShowWindow(empty_terminal, SW_HIDE);
        }
        Ok(Self {
            ui: ui.as_weak(),
            window,
            paths,
            store,
            envelope,
            vault: None,
            hosts: vec![],
            selected: None,
            tabs: vec![],
            active: None,
            empty_terminal,
            empty_bounds: None,
            empty_shown: false,
            last_activity: Instant::now(),
            retry_after: Instant::now(),
            failures: 0,
            preview,
            skip_session_close_confirmation,
            pending_close: None,
            key_generation: None,
        })
    }

    fn status(&self, text: &str) {
        if let Some(ui) = self.ui.upgrade() {
            ui.set_status(text.into());
            if ui.get_settings_open() {
                ui.set_settings_message(text.into());
            }
        }
    }

    fn sync(&self) {
        let Some(ui) = self.ui.upgrade() else {
            return;
        };
        let unlocked = self.vault.is_some();
        ui.set_unlocked(unlocked);
        ui.set_creating(self.envelope.is_none());
        ui.set_selected_server(self.selected.map_or(-1, |value| value as i32));
        ui.set_active_session(self.active.map_or(-1, |value| value as i32));
        ui.set_active_running(
            unlocked
                && self
                    .active
                    .and_then(|i| self.tabs.get(i))
                    .is_some_and(|tab| tab.session.is_some()),
        );
        let servers = if unlocked {
            self.hosts
                .iter()
                .map(|host| ServerRow {
                    name: host.name.as_str().into(),
                    destination: format!("{}@{}:{}", host.username, host.address, host.port).into(),
                    password_login: host.authentication == Authentication::Password,
                })
                .collect()
        } else {
            vec![]
        };
        ui.set_servers(ModelRc::new(VecModel::from(servers)));
        let sessions = if unlocked {
            self.tabs
                .iter()
                .map(|tab| SessionRow {
                    name: tab.name.as_str().into(),
                    running: tab.session.is_some(),
                })
                .collect()
        } else {
            vec![]
        };
        ui.set_sessions(ModelRc::new(VecModel::from(sessions)));
        ui.set_database_location(
            self.paths
                .database_dir
                .join("vault.edb")
                .to_string_lossy()
                .as_ref()
                .into(),
        );
        let mut shortcuts = vec![];
        if let Some(vault) = &self.vault {
            shortcuts.extend(BUILTIN_SHORTCUTS.iter().map(|(name, command)| ShortcutRow {
                name: (*name).into(),
                command: (*command).into(),
            }));
            shortcuts.extend(vault.shortcuts.iter().map(|shortcut| ShortcutRow {
                name: shortcut.name.as_str().into(),
                command: shortcut.command.as_str().into(),
            }));
        }
        ui.set_custom_shortcuts(ModelRc::new(VecModel::from(
            shortcuts
                .iter()
                .skip(BUILTIN_SHORTCUTS.len())
                .cloned()
                .collect::<Vec<_>>(),
        )));
        ui.set_shortcuts(ModelRc::new(VecModel::from(shortcuts)));
        ui.set_builtin_shortcut_count(BUILTIN_SHORTCUTS.len() as i32);
    }

    fn close_settings(&self) {
        if let Some(ui) = self.ui.upgrade() {
            ui.set_settings_open(false);
            ui.set_current_passphrase("".into());
            ui.set_new_passphrase("".into());
            ui.set_new_passphrase_confirmation("".into());
            ui.set_delete_data_open(false);
            ui.set_delete_data_confirmation("".into());
            ui.set_shortcut_editor_open(false);
            ui.set_shortcut_name("".into());
            ui.set_shortcut_command("".into());
            ui.set_settings_message("".into());
            ui.set_settings_scroll_y(0.);
        }
    }

    fn open_settings(&mut self) -> Result<()> {
        if self.vault.is_none() {
            return Err("Unlock the vault first.".into());
        }
        self.dismiss_popups();
        self.dismiss_close_confirmation();
        self.reset_editor();
        let ui = self.ui.upgrade().ok_or("Workspace closed.")?;
        if !ui.get_settings_open() {
            self.close_settings();
        }
        ui.set_editor_open(false);
        ui.set_about_open(false);
        ui.set_drawer_open(false);
        ui.set_settings_open(true);
        self.sync();
        self.position_terminals();
        Ok(())
    }

    fn change_vault_key(&mut self) -> Result<()> {
        let ui = self.ui.upgrade().ok_or("Workspace closed.")?;
        let current = Secret(ui.get_current_passphrase().as_bytes().to_vec());
        let password = Secret(ui.get_new_passphrase().as_bytes().to_vec());
        let confirmation = Secret(ui.get_new_passphrase_confirmation().as_bytes().to_vec());
        ui.set_current_passphrase("".into());
        ui.set_new_passphrase("".into());
        ui.set_new_passphrase_confirmation("".into());
        let vault = self.vault.as_ref().ok_or("Unlock the vault first.")?;
        if Instant::now() < self.retry_after {
            return Err("Please wait a few seconds before trying the passphrase again.".into());
        }
        if current.0.len() > 4096 || password.0.len() > 4096 {
            return Err("Master passphrase is too long.".into());
        }
        if password.0 != confirmation.0 {
            return Err("The new master passphrases do not match.".into());
        }
        let envelope = self.envelope.as_ref().ok_or("No saved vault found.")?;
        if let Err(error) = UnlockedVault::unlock(&current, envelope) {
            self.failures = self.failures.saturating_add(1);
            self.retry_after =
                Instant::now() + Duration::from_secs(u64::from(self.failures).min(10));
            return Err(error);
        }
        let next = vault.change_passphrase(&password)?;
        let sealed = next.seal(&self.hosts)?;
        // Verify the replacement before the single durable ESE transaction.
        UnlockedVault::unlock(&password, &sealed)?;
        self.store.write(&sealed)?;
        self.envelope = Some(sealed);
        self.vault = Some(next);
        self.failures = 0;
        self.retry_after = Instant::now();
        self.status("Vault key changed. Use your new master passphrase next time you unlock.");
        Ok(())
    }

    fn save_shortcut(&mut self) -> Result<()> {
        let vault = self.vault.as_ref().ok_or("Unlock the vault first.")?;
        let ui = self.ui.upgrade().ok_or("Workspace closed.")?;
        let shortcut = CommandShortcut {
            name: ui.get_shortcut_name().trim().into(),
            command: ui.get_shortcut_command().to_string(),
        };
        shortcut.validate()?;
        if vault.shortcuts.len() >= MAX_SHORTCUTS {
            return Err("You can save up to 100 custom shortcuts.".into());
        }
        if BUILTIN_SHORTCUTS
            .iter()
            .any(|(name, _)| name.eq_ignore_ascii_case(&shortcut.name))
            || vault
                .shortcuts
                .iter()
                .any(|saved| saved.name.eq_ignore_ascii_case(&shortcut.name))
        {
            return Err("A shortcut with that name already exists.".into());
        }
        let mut next = vault.shortcuts.clone();
        next.push(shortcut);
        let sealed = vault.seal_with_shortcuts(&self.hosts, &next)?;
        self.store.write(&sealed)?;
        self.envelope = Some(sealed);
        self.vault.as_mut().unwrap().shortcuts = next;
        ui.set_shortcut_name("".into());
        ui.set_shortcut_command("".into());
        ui.set_shortcut_editor_open(false);
        self.sync();
        self.status("Shortcut saved. Choose it from the Shortcuts menu.");
        Ok(())
    }

    fn delete_shortcut(&mut self, index: usize) -> Result<()> {
        let vault = self.vault.as_ref().ok_or("Unlock the vault first.")?;
        let index = index
            .checked_sub(BUILTIN_SHORTCUTS.len())
            .ok_or("Built-in shortcuts cannot be removed.")?;
        let mut next = vault.shortcuts.clone();
        if index >= next.len() {
            return Err("Shortcut no longer exists.".into());
        }
        next.remove(index);
        let sealed = vault.seal_with_shortcuts(&self.hosts, &next)?;
        self.store.write(&sealed)?;
        self.envelope = Some(sealed);
        self.vault.as_mut().unwrap().shortcuts = next;
        self.sync();
        self.status("Shortcut removed.");
        Ok(())
    }

    fn delete_all_server_data(&mut self) -> Result<()> {
        let vault = self.vault.as_ref().ok_or("Unlock the vault first.")?;
        let ui = self.ui.upgrade().ok_or("Workspace closed.")?;
        if !ui.get_settings_open()
            || !ui.get_delete_data_open()
            || ui.get_delete_data_confirmation() != "DELETE"
        {
            return Err("Type DELETE in Settings to confirm removing all saved servers.".into());
        }
        let sealed = vault.seal(&[])?;
        self.store.write(&sealed)?;
        self.envelope = Some(sealed);
        self.hosts.clear();
        self.dismiss_close_confirmation();
        while !self.tabs.is_empty() {
            self.close_tab(self.tabs.len() - 1)?;
        }
        self.reset_editor();
        ui.set_delete_data_open(false);
        ui.set_delete_data_confirmation("".into());
        self.sync();
        self.position_terminals();
        self.status("All saved servers and passwords deleted. All sessions closed.");
        Ok(())
    }

    fn position_terminals(&mut self) {
        let Some(ui) = self.ui.upgrade() else {
            return;
        };
        // SAFETY: queries the live Slint parent; child coordinates use the same physical DPI.
        let scale = unsafe { GetDpiForWindow(self.window) }.max(96) as f32 / 96.0;
        // SAFETY: the parent is live. Keep terminal grids intact through minimized/zero-size layouts.
        let minimized = unsafe { IsIconic(self.window) } != 0;
        let bounds = [
            (ui.get_terminal_x() * scale).round() as i32,
            (ui.get_terminal_y() * scale).round() as i32,
            (ui.get_terminal_width() * scale).round().max(1.) as i32,
            (ui.get_terminal_height() * scale).round().max(1.) as i32,
        ];
        let visible = self.vault.is_some() && ui.get_terminal_visible();
        let mut visibility_changed = false;
        for (index, tab) in self.tabs.iter_mut().enumerate() {
            let shown = visible && self.active == Some(index);
            // SAFETY: each terminal belongs to this controller and parent; layout is performed on the UI thread.
            unsafe {
                if !minimized && tab.bounds != Some(bounds) {
                    MoveWindow(tab.terminal, bounds[0], bounds[1], bounds[2], bounds[3], 1);
                    tab.bounds = Some(bounds);
                }
                if shown != tab.shown {
                    ShowWindow(tab.terminal, if shown { SW_SHOWNA } else { SW_HIDE });
                    tab.shown = shown;
                    visibility_changed = true;
                }
            }
            let attach = shown && tab.session.is_some();
            if attach != tab.input_attached {
                terminal_view::attach(
                    tab.terminal,
                    if attach {
                        tab.session.as_ref().map(SshSession::input)
                    } else {
                        None
                    },
                    false,
                );
                tab.input_attached = attach;
            }
        }
        // SAFETY: this empty-state terminal is owned by the same live parent.
        unsafe {
            if !minimized && self.empty_bounds != Some(bounds) {
                MoveWindow(
                    self.empty_terminal,
                    bounds[0],
                    bounds[1],
                    bounds[2],
                    bounds[3],
                    1,
                );
                self.empty_bounds = Some(bounds);
            }
            let shown = visible && self.active.is_none();
            if shown != self.empty_shown {
                ShowWindow(self.empty_terminal, if shown { SW_SHOWNA } else { SW_HIDE });
                self.empty_shown = shown;
                visibility_changed = true;
            }
        }
        if visibility_changed {
            ui.window().request_redraw();
        }
    }

    fn reset_editor(&mut self) {
        self.cancel_key_generation();
        self.selected = None;
        if let Some(ui) = self.ui.upgrade() {
            ui.set_server_name("".into());
            ui.set_address("".into());
            ui.set_port("22".into());
            ui.set_username("".into());
            ui.set_identity("".into());
            ui.set_public_key("".into());
            ui.set_server_password("".into());
            ui.set_password_login(false);
            ui.set_saved_password(false);
        }
    }

    fn unlock(&mut self) -> Result<()> {
        if Instant::now() < self.retry_after {
            return Err("Please wait a few seconds before trying the passphrase again.".into());
        }
        let ui = self.ui.upgrade().ok_or("Workspace closed.")?;
        let password = Secret(ui.get_master().as_bytes().to_vec());
        let confirmation = Secret(ui.get_confirmation().as_bytes().to_vec());
        ui.set_master("".into());
        ui.set_confirmation("".into());
        ui.set_show_master(false);
        if password.0.len() > 4096 {
            return Err("Master passphrase is too long.".into());
        }
        let result = (|| {
            if let Some(envelope) = &self.envelope {
                UnlockedVault::unlock(&password, envelope)
            } else {
                if password.0 != confirmation.0 {
                    return Err("The master passphrases do not match.".into());
                }
                let vault = UnlockedVault::create(&password)?;
                self.store.write(&vault.seal(&[])?)?;
                self.envelope = Some(
                    self.store
                        .read()?
                        .ok_or("Cannot read the newly created vault.")?,
                );
                UnlockedVault::unlock(&password, self.envelope.as_ref().unwrap())
            }
        })();
        match result {
            Ok((vault, hosts)) => {
                self.vault = Some(vault);
                self.hosts = hosts;
                self.failures = 0;
                self.reset_editor();
                ui.set_editor_open(false);
                self.sync();
                self.position_terminals();
                self.status("Vault unlocked. Your workspace is ready.");
                Ok(())
            }
            Err(error) => {
                self.failures = self.failures.saturating_add(1);
                self.retry_after =
                    Instant::now() + Duration::from_secs(u64::from(self.failures).min(10));
                self.sync();
                Err(error)
            }
        }
    }

    fn lock(&mut self) {
        self.close_settings();
        self.dismiss_popups();
        self.dismiss_close_confirmation();
        for tab in &mut self.tabs {
            if let Some(session) = &mut tab.session {
                session.cancel_pending_credentials();
            }
            terminal_view::attach(tab.terminal, None, false);
            tab.input_attached = false;
            // SAFETY: hides only this controller's terminal view before releasing the vault.
            unsafe {
                ShowWindow(tab.terminal, SW_HIDE);
            }
            tab.shown = false;
        }
        self.vault = None;
        for host in &mut self.hosts {
            for field in [
                &mut host.name,
                &mut host.address,
                &mut host.username,
                &mut host.identity_path,
            ] {
                clear_string(field);
            }
        }
        self.hosts.clear();
        self.reset_editor();
        if let Some(ui) = self.ui.upgrade() {
            ui.set_master("".into());
            ui.set_confirmation("".into());
            ui.set_show_master(false);
            ui.set_editor_open(false);
            ui.set_drawer_open(false);
            ui.set_about_open(false);
            ui.set_shortcuts_open(false);
            ui.set_terminal_image(slint::Image::default());
        }
        self.sync();
        self.position_terminals();
        self.status("Vault locked. Unlock to return to your sessions.");
    }

    fn edit(&mut self, index: Option<usize>) -> Result<()> {
        if self.vault.is_none() {
            return Err("Unlock the vault first.".into());
        }
        self.reset_editor();
        self.close_settings();
        self.dismiss_popups();
        let ui = self.ui.upgrade().ok_or("Workspace closed.")?;
        ui.set_drawer_open(false);
        ui.set_about_open(false);
        if let Some(index) = index {
            let host = self.hosts.get(index).ok_or("Server no longer exists.")?;
            self.selected = Some(index);
            ui.set_server_name(host.name.as_str().into());
            ui.set_address(host.address.as_str().into());
            ui.set_port(host.port.to_string().into());
            ui.set_username(host.username.as_str().into());
            ui.set_identity(host.identity_path.as_str().into());
            if !host.identity_path.is_empty()
                && let Ok(public_key) =
                    keygen::read_public_key(std::path::Path::new(&host.identity_path))
            {
                ui.set_public_key(public_key.into());
            }
            ui.set_password_login(host.authentication == Authentication::Password);
            ui.set_saved_password(host.password.is_some());
        }
        ui.set_editor_open(true);
        self.sync();
        self.position_terminals();
        Ok(())
    }

    fn save(&mut self) -> Result<()> {
        if self.key_generation.is_some() {
            return Err("Wait for the SSH key pair to finish generating before saving.".into());
        }
        let vault = self.vault.as_ref().ok_or("Unlock the vault first.")?;
        let ui = self.ui.upgrade().ok_or("Workspace closed.")?;
        let authentication = if ui.get_password_login() {
            Authentication::Password
        } else {
            Authentication::Key
        };
        let password = Secret(ui.get_server_password().as_bytes().to_vec());
        ui.set_server_password("".into());
        let saved_password = match authentication {
            Authentication::Password if !password.0.is_empty() => {
                Some(vault.encrypt_password(&password)?)
            }
            Authentication::Password => self
                .selected
                .and_then(|i| self.hosts.get(i))
                .and_then(|host| host.password.clone()),
            Authentication::Key => None,
        };
        let host = Host {
            name: ui.get_server_name().trim().into(),
            address: ui.get_address().trim().into(),
            port: ui
                .get_port()
                .trim()
                .parse()
                .map_err(|_| "SSH port must be between 1 and 65535.")?,
            username: ui.get_username().trim().into(),
            identity_path: ui.get_identity().trim().into(),
            authentication,
            password: saved_password,
        };
        host.validate()?;
        let mut next = self.hosts.clone();
        let selected = if let Some(index) = self.selected {
            *next.get_mut(index).ok_or("Server no longer exists.")? = host;
            index
        } else {
            next.push(host);
            next.len() - 1
        };
        let sealed = vault.seal(&next)?;
        self.store.write(&sealed)?;
        self.envelope = Some(sealed);
        self.hosts = next;
        self.selected = Some(selected);
        ui.set_editor_open(false);
        self.sync();
        self.position_terminals();
        self.status("Server saved. Connect from its card to start a session.");
        Ok(())
    }

    fn cancel_key_generation(&mut self) {
        self.key_generation.take();
        if let Some(ui) = self.ui.upgrade() {
            ui.set_generating_key(false);
            ui.set_keygen_open(false);
            ui.set_key_passphrase("".into());
            ui.set_key_confirmation("".into());
        }
    }

    fn generate_key(&mut self) -> Result<()> {
        if self.vault.is_none() {
            return Err("Unlock the vault first.".into());
        }
        if self.key_generation.is_some() {
            return Ok(());
        }
        let ui = self.ui.upgrade().ok_or("Workspace closed.")?;
        let passphrase = Secret(ui.get_key_passphrase().as_bytes().to_vec());
        let confirmation = Secret(ui.get_key_confirmation().as_bytes().to_vec());
        ui.set_key_passphrase("".into());
        ui.set_key_confirmation("".into());
        if passphrase.0 != confirmation.0 {
            return Err("Key passphrases do not match. Please enter them again.".into());
        }
        self.key_generation = Some(KeyGeneration::start(self.paths.root.clone(), passphrase)?);
        ui.set_generating_key(true);
        self.status("Creating your SSH key pair…");
        Ok(())
    }

    fn poll_key_generation(&mut self) {
        let Some(result) = self.key_generation.as_ref().and_then(KeyGeneration::poll) else {
            return;
        };
        self.key_generation.take();
        let Some(ui) = self.ui.upgrade() else {
            return;
        };
        ui.set_generating_key(false);
        match result {
            Ok(mut key) if self.vault.is_some() && ui.get_editor_open() => {
                ui.set_password_login(false);
                ui.set_identity(key.private_path.to_string_lossy().as_ref().into());
                ui.set_public_key(key.public_key.as_str().into());
                ui.set_keygen_open(false);
                key.retain();
                self.status("SSH key pair saved. Copy the public key to your server, then save this server.");
            }
            Ok(_) => {}
            Err(error) => self.status(&error),
        }
    }

    fn copy_public_key(&self) -> Result<()> {
        if self.vault.is_none() {
            return Err("Unlock the vault first.".into());
        }
        let ui = self.ui.upgrade().ok_or("Workspace closed.")?;
        let public_key = keygen::read_public_key(std::path::Path::new(ui.get_identity().as_str()))?;
        terminal_view::set_clipboard_text(self.window, &public_key)?;
        self.status("Public key copied to the clipboard.");
        Ok(())
    }

    fn delete(&mut self) -> Result<()> {
        let vault = self.vault.as_ref().ok_or("Unlock the vault first.")?;
        let index = self.selected.ok_or("Choose a server to delete.")?;
        if index >= self.hosts.len() {
            return Err("Server no longer exists.".into());
        }
        let mut next = self.hosts.clone();
        next.remove(index);
        let sealed = vault.seal(&next)?;
        self.store.write(&sealed)?;
        self.hosts = next;
        self.envelope = Some(sealed);
        self.reset_editor();
        if let Some(ui) = self.ui.upgrade() {
            ui.set_editor_open(false);
        }
        self.sync();
        self.position_terminals();
        self.status("Server removed. Its OpenSSH trust entry is retained.");
        Ok(())
    }

    fn open_tab(&mut self, name: String, session: Option<SshSession>) -> Result<usize> {
        if self.tabs.len() >= MAX_TABS {
            return Err(
                "Close a session tab before opening another; up to 16 tabs are supported.".into(),
            );
        }
        let terminal = terminal_view::create(self.window, TERMINAL_ID + 1 + self.tabs.len())?;
        // SAFETY: defer display until the new terminal is positioned inside the Slint layout.
        unsafe {
            ShowWindow(terminal, SW_HIDE);
        }
        self.tabs.push(Tab {
            name,
            terminal,
            session,
            input_attached: false,
            bounds: None,
            shown: false,
        });
        let index = self.tabs.len() - 1;
        self.active = Some(index);
        self.close_settings();
        self.dismiss_popups();
        if let Some(ui) = self.ui.upgrade() {
            ui.set_editor_open(false);
            ui.set_drawer_open(false);
            ui.set_about_open(false);
        }
        self.sync();
        self.position_terminals();
        // SAFETY: the selected terminal is a visible child owned by this controller.
        unsafe {
            SetFocus(terminal);
        }
        Ok(index)
    }

    fn connect(&mut self, index: usize) -> Result<()> {
        if self.preview {
            return Err("This is a preview workspace with sample servers.".into());
        }
        if self.tabs.len() >= MAX_TABS {
            return Err(
                "Close a session tab before opening another; up to 16 tabs are supported.".into(),
            );
        }
        let vault = self.vault.as_ref().ok_or("Unlock the vault first.")?;
        let host = self
            .hosts
            .get(index)
            .ok_or("Server no longer exists.")?
            .clone();
        let password =
            if host.authentication == Authentication::Password {
                Some(vault.decrypt_password(
                    host.password.as_ref().ok_or("Saved password is missing.")?,
                )?)
            } else {
                None
            };
        let session = super::ssh::connect(
            &self.paths,
            &host,
            None,
            password,
            terminal_view::size(self.empty_terminal),
        )?;
        self.selected = Some(index);
        self.open_tab(host.name, Some(session))?;
        if let Err(error) = self.remember_server_use(index) {
            self.status(&format!(
                "Session opened, but the recent server order could not be saved: {error}"
            ));
            return Ok(());
        }
        self.status("Connecting. Verify any new host fingerprint using a trusted source.");
        Ok(())
    }

    // The encrypted inventory order is the MRU order, avoiding a separate usage-history file.
    fn remember_server_use(&mut self, index: usize) -> Result<()> {
        let vault = self.vault.as_ref().ok_or("Unlock the vault first.")?;
        if index >= self.hosts.len() {
            return Err("Server no longer exists.".into());
        }
        if index != 0 {
            let mut next = self.hosts.clone();
            let host = next.remove(index);
            next.insert(0, host);
            let sealed = vault.seal(&next)?;
            self.store.write(&sealed)?;
            self.envelope = Some(sealed);
            self.hosts = next;
        }
        self.selected = Some(0);
        if let Some(ui) = self.ui.upgrade() {
            ui.set_server_scroll_y(0.);
        }
        self.sync();
        Ok(())
    }

    fn select_tab(&mut self, index: usize) -> Result<()> {
        if self.vault.is_none() {
            return Err("Unlock the vault first.".into());
        }
        let terminal = self
            .tabs
            .get(index)
            .ok_or("Session no longer exists.")?
            .terminal;
        self.active = Some(index);
        self.close_settings();
        self.dismiss_popups();
        if let Some(ui) = self.ui.upgrade() {
            ui.set_editor_open(false);
            ui.set_drawer_open(false);
            ui.set_about_open(false);
        }
        self.sync();
        self.position_terminals();
        // SAFETY: this terminal is visible after layout and belongs to the current UI thread.
        unsafe {
            SetFocus(terminal);
        }
        Ok(())
    }

    fn request_close_tab(&mut self, index: usize) -> Result<()> {
        if self.vault.is_none() {
            return Err("Unlock the vault first.".into());
        }
        if self.pending_close.is_some() {
            return Ok(());
        }
        let tab = self.tabs.get(index).ok_or("Session no longer exists.")?;
        if tab.session.is_none() || self.skip_session_close_confirmation {
            return self.close_tab(index);
        }
        self.show_close_confirmation(index)
    }

    fn show_close_confirmation(&mut self, index: usize) -> Result<()> {
        let ui = self.ui.upgrade().ok_or("Workspace closed.")?;
        let tab = self.tabs.get(index).ok_or("Session no longer exists.")?;
        ui.set_closing_session_name(tab.name.as_str().into());
        ui.set_skip_close_confirmation(false);
        self.dismiss_popups();
        self.pending_close = Some(index);
        ui.set_close_confirmation_open(true);
        self.position_terminals();
        // The native terminal must be hidden before the Slint popup takes focus.
        ui.invoke_show_close_confirmation();
        Ok(())
    }

    fn dismiss_close_confirmation(&mut self) {
        self.pending_close = None;
        if let Some(ui) = self.ui.upgrade() {
            ui.invoke_hide_close_confirmation();
            ui.set_closing_session_name("".into());
            ui.set_skip_close_confirmation(false);
        }
    }

    fn finish_close_tab(&mut self, confirmed: bool) -> Result<()> {
        let pending = self.pending_close;
        let remember = confirmed
            && self
                .ui
                .upgrade()
                .is_some_and(|ui| ui.get_skip_close_confirmation());
        self.dismiss_close_confirmation();
        self.position_terminals();
        let Some(index) = pending else {
            return Ok(());
        };
        if !confirmed || self.vault.is_none() {
            if let Some(tab) = self.active.and_then(|index| self.tabs.get(index))
                && tab.shown
            {
                // SAFETY: restores focus only to this controller's visible terminal after cancellation.
                unsafe { SetFocus(tab.terminal) };
            }
            return Ok(());
        }
        self.close_tab(index)?;
        if remember {
            match remember_session_close_preference(&self.paths.root) {
                Ok(()) => self.skip_session_close_confirmation = true,
                Err(error) => self.status(&format!("Session tab closed. {error}")),
            }
        }
        Ok(())
    }

    fn close_tab(&mut self, index: usize) -> Result<()> {
        if self.vault.is_none() {
            return Err("Unlock the vault first.".into());
        }
        if index >= self.tabs.len() {
            return Err("Session no longer exists.".into());
        }
        let mut tab = self.tabs.remove(index);
        terminal_view::attach(tab.terminal, None, false);
        if let Some(mut session) = tab.session.take() {
            session.cancel_pending_credentials();
            session.finish_output();
        }
        // SAFETY: the removed tab owns this terminal; its input is detached and process has finished teardown.
        unsafe {
            DestroyWindow(tab.terminal);
        }
        self.active = match self.active {
            Some(active) if active > index => Some(active - 1),
            Some(active) if active == index => {
                if self.tabs.is_empty() {
                    None
                } else {
                    Some(index.min(self.tabs.len() - 1))
                }
            }
            other => other,
        };
        self.sync();
        self.position_terminals();
        self.status("Session tab closed.");
        Ok(())
    }

    fn dismiss_popups(&self) {
        if let Some(ui) = self.ui.upgrade() {
            ui.invoke_hide_app_menu();
            ui.set_shortcuts_open(false);
            ui.set_terminal_image(slint::Image::default());
        }
    }

    fn open_app_menu(&mut self) -> Result<()> {
        let ui = self.ui.upgrade().ok_or("Workspace closed.")?;
        if ui.get_app_menu_open() || ui.get_close_confirmation_open() {
            return Ok(());
        }
        self.dismiss_popups();
        if self.vault.is_some()
            && !ui.get_editor_open()
            && !ui.get_about_open()
            && !ui.get_settings_open()
        {
            let terminal = self
                .active
                .and_then(|index| self.tabs.get(index))
                .map_or(self.empty_terminal, |tab| tab.terminal);
            ui.set_terminal_image(slint::Image::from_rgba8(terminal_pixels(terminal)?));
        }
        ui.set_app_menu_open(true);
        self.position_terminals();
        ui.invoke_show_app_menu();
        Ok(())
    }

    fn close_app_menu(&mut self) {
        self.dismiss_popups();
        self.position_terminals();
        self.focus_terminal();
    }

    fn focus_terminal(&self) {
        if let Some(tab) = self.active.and_then(|index| self.tabs.get(index))
            && tab.shown
        {
            // SAFETY: the selected terminal is a visible native child owned by this controller.
            unsafe {
                SetFocus(tab.terminal);
            }
        }
    }

    fn shortcut(&mut self, index: usize) -> Result<()> {
        if self.vault.is_none() {
            return Err("Unlock the vault first.".into());
        }
        let vault = self.vault.as_ref().unwrap();
        let command = if let Some((_, command)) = BUILTIN_SHORTCUTS.get(index) {
            (*command).to_string()
        } else {
            vault
                .shortcuts
                .get(index - BUILTIN_SHORTCUTS.len())
                .ok_or("Unknown command shortcut.")?
                .command
                .clone()
        };
        let tab = self
            .active
            .and_then(|i| self.tabs.get(i))
            .filter(|tab| tab.session.is_some())
            .ok_or("Choose a running session first.")?;
        let terminal = tab.terminal;
        self.close_settings();
        if let Some(ui) = self.ui.upgrade() {
            ui.set_editor_open(false);
            ui.set_about_open(false);
        }
        self.position_terminals();
        terminal_view::insert_command(terminal, &command)?;
        // SAFETY: the selected terminal is visible and attached to its own running session.
        unsafe {
            SetFocus(terminal);
        }
        self.status("Command inserted. Edit it or press Enter to run it.");
        Ok(())
    }

    fn tick(&mut self) {
        if self.vault.is_some() && self.last_activity.elapsed() >= Duration::from_secs(600) {
            self.lock();
        }
        self.poll_key_generation();
        let mut changed = false;
        let mut exit = None;
        for (index, tab) in self.tabs.iter_mut().enumerate() {
            let Some(session) = &mut tab.session else {
                continue;
            };
            let input = session.input();
            for bytes in session.output() {
                terminal_view::feed_session(tab.terminal, &bytes, &input);
            }
            if let Ok(Some(code)) = session.try_wait() {
                for bytes in session.finish_output() {
                    terminal_view::feed(tab.terminal, &bytes);
                }
                tab.session = None;
                terminal_view::attach(tab.terminal, None, false);
                tab.input_attached = false;
                changed = true;
                if self.active == Some(index) {
                    exit = Some(code);
                }
            }
        }
        if changed {
            self.sync();
            if let Some(ui) = self.ui.upgrade()
                && !ui.get_active_running()
            {
                ui.set_shortcuts_open(false);
                if !ui.get_app_menu_open() {
                    ui.set_terminal_image(slint::Image::default());
                }
            }
        }
        if let Some(code) = exit {
            self.status(&format!(
                "Session finished with exit code {code}. Output remains in its tab."
            ));
        }
        self.position_terminals();
    }
}

impl Drop for Controller {
    fn drop(&mut self) {
        self.key_generation.take();
        for tab in &mut self.tabs {
            if let Some(mut session) = tab.session.take() {
                session.cancel_pending_credentials();
                session.finish_output();
            }
            // SAFETY: only this controller's child windows are destroyed, and Win32 tolerates an already-destroyed child.
            unsafe {
                DestroyWindow(tab.terminal);
            }
        }
        // SAFETY: this empty-state child was created by this controller.
        unsafe {
            DestroyWindow(self.empty_terminal);
        }
    }
}

fn confirm(window: HWND, message: &str) -> bool {
    // SAFETY: buffers remain alive during the modal call; refusal is the default action.
    unsafe {
        MessageBoxW(
            window,
            wide(message).as_ptr(),
            wide("SentinelSSH").as_ptr(),
            MB_YESNO | MB_ICONQUESTION | MB_DEFBUTTON2,
        ) == IDYES
    }
}

struct NativeEvents {
    controller: Weak<RefCell<Controller>>,
    ui: slint::Weak<Workspace>,
}

fn mark_windows_damage(ui: &Workspace, window: HWND) {
    let mut damage = RECT::default();
    // SAFETY: inspect the live parent's update region before Winit/softbuffer validates it.
    // Internal Slint redraws have no update rectangle, so normal partial rendering stays enabled.
    if unsafe { IsIconic(window) != 0 || GetUpdateRect(window, &mut damage, 0) == 0 } {
        return;
    }
    // Slint 1.13.1 does not propagate Windows damage to its software renderer. Keep
    // this compatibility shim isolated until upgrading to a version with upstream
    // fix https://github.com/slint-ui/slint/pull/13568. request_redraw() alone only
    // schedules a frame; it does not invalidate the renderer's retained contents.
    use slint::private_unstable_api::re_exports::{WindowInner, euclid};
    let scale = ui.window().scale_factor();
    let region = euclid::Rect::new(
        euclid::point2(damage.left as f32 / scale, damage.top as f32 / scale),
        euclid::size2(
            (damage.right - damage.left) as f32 / scale,
            (damage.bottom - damage.top) as f32 / scale,
        ),
    );
    WindowInner::from_pub(ui.window())
        .window_adapter()
        .renderer()
        .mark_dirty_region(region.into());
}

unsafe extern "system" fn native_events(
    window: HWND,
    message: u32,
    wparam: WPARAM,
    lparam: LPARAM,
    _id: usize,
    data: usize,
) -> LRESULT {
    // SAFETY: the runtime owns this boxed reference for the lifetime of the installed subclass.
    let events = unsafe { &*(data as *const NativeEvents) };
    if message == WM_PAINT
        && let Some(ui) = events.ui.upgrade()
    {
        // Repaint handling must also work during nested native events while the
        // controller is borrowed (for example, when moving its child terminals).
        mark_windows_damage(&ui, window);
    }
    let controller = events.controller.upgrade();
    if let Some(controller) = controller {
        if let Ok(mut state) = controller.try_borrow_mut() {
            match message {
                WM_WTSSESSION_CHANGE if wparam == WTS_SESSION_LOCK as usize => state.lock(),
                WM_POWERBROADCAST if wparam == PBT_APMSUSPEND as usize => state.lock(),
                terminal_view::RESIZED => {
                    if let Some(tab) = state.tabs.iter().find(|tab| tab.terminal == wparam as HWND)
                        && let Some(session) = &tab.session
                    {
                        let (columns, rows) = terminal_view::size(tab.terminal);
                        if let Err(error) = session.resize(columns, rows) {
                            state.status(&error);
                        }
                    }
                }
                terminal_view::ACTIVITY | WM_KEYDOWN | WM_CHAR | WM_LBUTTONDOWN | WM_MOUSEWHEEL => {
                    state.last_activity = Instant::now()
                }
                _ => {}
            }
        } else if (message == WM_WTSSESSION_CHANGE && wparam == WTS_SESSION_LOCK as usize)
            || (message == WM_POWERBROADCAST && wparam == PBT_APMSUSPEND as usize)
        {
            // SAFETY: defer security events until the current short operation releases its mutable borrow.
            unsafe {
                PostMessageW(window, message, wparam, lparam);
            }
        }
    }
    // SAFETY: forwards the unchanged event to Slint/Winit after our native terminal/security handling.
    unsafe { DefSubclassProc(window, message, wparam, lparam) }
}

fn perform(
    controller: &Rc<RefCell<Controller>>,
    action: impl FnOnce(&mut Controller) -> Result<()>,
) {
    let mut state = controller.borrow_mut();
    state.last_activity = Instant::now();
    if let Err(error) = action(&mut state) {
        state.status(&error);
    }
}

fn terminal_pixels(window: HWND) -> Result<slint::SharedPixelBuffer<slint::Rgba8Pixel>> {
    let mut bounds = RECT::default();
    // SAFETY: capture renders only this owned terminal, never the desktop or another application's window.
    unsafe {
        if GetClientRect(window, &mut bounds) == 0 || bounds.right <= 0 || bounds.bottom <= 0 {
            return Err("Terminal image is unavailable.".into());
        }
        let source = GetDC(window);
        let dc = CreateCompatibleDC(source);
        let bitmap = CreateCompatibleBitmap(source, bounds.right, bounds.bottom);
        if source.is_null() || dc.is_null() || bitmap.is_null() {
            if !bitmap.is_null() {
                DeleteObject(bitmap);
            }
            if !dc.is_null() {
                DeleteDC(dc);
            }
            if !source.is_null() {
                ReleaseDC(window, source);
            }
            return Err("Cannot capture the terminal view.".into());
        }
        let old = SelectObject(dc, bitmap);
        SendMessageW(window, WM_PRINTCLIENT, dc as WPARAM, 0);
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
        let mut bytes = vec![0u8; bounds.right as usize * bounds.bottom as usize * 4];
        let copied = GetDIBits(
            dc,
            bitmap,
            0,
            bounds.bottom as u32,
            bytes.as_mut_ptr().cast(),
            &mut info,
            DIB_RGB_COLORS,
        );
        DeleteObject(bitmap);
        DeleteDC(dc);
        ReleaseDC(window, source);
        if copied == 0 {
            return Err("Cannot read the terminal view.".into());
        }
        let mut pixels = slint::SharedPixelBuffer::<slint::Rgba8Pixel>::new(
            bounds.right as u32,
            bounds.bottom as u32,
        );
        for (pixel, source) in pixels
            .make_mut_slice()
            .iter_mut()
            .zip(bytes.chunks_exact(4))
        {
            *pixel = slint::Rgba8Pixel {
                r: source[2],
                g: source[1],
                b: source[0],
                a: 255,
            };
        }
        Ok(pixels)
    }
}

fn wire(ui: &Workspace, controller: &Rc<RefCell<Controller>>) {
    let state = controller.clone();
    ui.on_unlock(move || perform(&state, Controller::unlock));
    let state = controller.clone();
    ui.on_lock(move || {
        perform(&state, |state| {
            state.lock();
            Ok(())
        })
    });
    let state = controller.clone();
    ui.on_toggle_servers(move || {
        perform(&state, |state| {
            let ui = state.ui.upgrade().ok_or("Workspace closed.")?;
            if state.vault.is_some() {
                ui.set_drawer_open(!ui.get_drawer_open());
                state.position_terminals();
            }
            Ok(())
        })
    });
    let state = controller.clone();
    ui.on_open_app_menu(move || perform(&state, Controller::open_app_menu));
    let state = controller.clone();
    ui.on_close_app_menu(move || {
        perform(&state, |state| {
            state.close_app_menu();
            Ok(())
        })
    });
    let state = controller.clone();
    ui.on_open_about(move || {
        perform(&state, |state| {
            state.dismiss_popups();
            state.close_settings();
            state.reset_editor();
            let ui = state.ui.upgrade().ok_or("Workspace closed.")?;
            ui.set_editor_open(false);
            ui.set_about_open(true);
            state.position_terminals();
            Ok(())
        })
    });
    let state = controller.clone();
    ui.on_open_settings(move || perform(&state, Controller::open_settings));
    let state = controller.clone();
    ui.on_close_settings(move || {
        perform(&state, |state| {
            state.close_settings();
            state.position_terminals();
            state.focus_terminal();
            Ok(())
        })
    });
    let state = controller.clone();
    ui.on_copy_database_location(move || {
        perform(&state, |state| {
            if state.vault.is_none() {
                return Err("Unlock the vault first.".into());
            }
            terminal_view::set_clipboard_text(
                state.window,
                &state.paths.database_dir.join("vault.edb").to_string_lossy(),
            )?;
            state.status("Database location copied to the clipboard.");
            Ok(())
        })
    });
    let state = controller.clone();
    ui.on_change_vault_key(move || perform(&state, Controller::change_vault_key));
    let state = controller.clone();
    ui.on_delete_all_server_data(move || perform(&state, Controller::delete_all_server_data));
    let state = controller.clone();
    ui.on_new_shortcut(move || {
        perform(&state, |state| {
            state.open_settings()?;
            let ui = state.ui.upgrade().ok_or("Workspace closed.")?;
            ui.set_shortcut_editor_open(true);
            ui.invoke_reset_settings_scroll();
            Ok(())
        })
    });
    let state = controller.clone();
    ui.on_save_shortcut(move || perform(&state, Controller::save_shortcut));
    let state = controller.clone();
    ui.on_delete_shortcut(move |index| {
        perform(&state, |state| state.delete_shortcut(index as usize))
    });
    let state = controller.clone();
    ui.on_close_about(move || {
        perform(&state, |state| {
            let ui = state.ui.upgrade().ok_or("Workspace closed.")?;
            ui.set_about_open(false);
            state.position_terminals();
            state.focus_terminal();
            Ok(())
        })
    });
    let state = controller.clone();
    ui.on_new_server(move || perform(&state, |state| state.edit(None)));
    let state = controller.clone();
    ui.on_edit_server(move |index| perform(&state, |state| state.edit(Some(index as usize))));
    let state = controller.clone();
    ui.on_connect_server(move |index| perform(&state, |state| state.connect(index as usize)));
    let state = controller.clone();
    ui.on_save_server(move || perform(&state, Controller::save));
    let state = controller.clone();
    ui.on_generate_key(move || perform(&state, Controller::generate_key));
    let state = controller.clone();
    ui.on_copy_public_key(move || perform(&state, |state| state.copy_public_key()));
    let state = controller.clone();
    ui.on_close_editor(move || {
        perform(&state, |state| {
            state.cancel_key_generation();
            if let Some(ui) = state.ui.upgrade() {
                ui.set_editor_open(false);
                ui.set_server_password("".into());
            }
            state.position_terminals();
            Ok(())
        })
    });
    let state = controller.clone();
    ui.on_select_session(move |index| perform(&state, |state| state.select_tab(index as usize)));
    let state = controller.clone();
    ui.on_insert_shortcut(move |index| perform(&state, |state| state.shortcut(index as usize)));
    let state = controller.clone();
    ui.on_open_shortcuts(move || {
        perform(&state, |state| {
            if state.vault.is_none() {
                return Err("Unlock the vault first.".into());
            }
            state.dismiss_popups();
            if let Some(ui) = state.ui.upgrade() {
                if ui.get_terminal_visible() {
                    let terminal = state
                        .active
                        .and_then(|index| state.tabs.get(index))
                        .map_or(state.empty_terminal, |tab| tab.terminal);
                    ui.set_terminal_image(slint::Image::from_rgba8(terminal_pixels(terminal)?));
                }
                ui.set_shortcuts_open(true);
            }
            state.position_terminals();
            Ok(())
        })
    });
    let state = controller.clone();
    ui.on_close_shortcuts(move || {
        perform(&state, |state| {
            if let Some(ui) = state.ui.upgrade() {
                ui.set_shortcuts_open(false);
                ui.set_terminal_image(slint::Image::default());
            }
            state.position_terminals();
            if let Some(tab) = state.active.and_then(|index| state.tabs.get(index))
                && tab.shown
            {
                // SAFETY: restores keyboard focus to the visible terminal after dismissing the dropdown.
                unsafe {
                    SetFocus(tab.terminal);
                }
            }
            Ok(())
        })
    });
    let state = controller.clone();
    ui.on_activity(move || {
        state.borrow_mut().last_activity = Instant::now();
    });
    let state = controller.clone();
    ui.on_delete_server(move || {
        let preview = {
            let state = state.borrow();
            state.selected.and_then(|i| state.hosts.get(i)).map(|host| {
                (
                    state.window,
                    format!("Delete {} from the local inventory?", host.name),
                )
            })
        };
        if let Some((window, message)) = preview
            && confirm(window, &message)
        {
            perform(&state, Controller::delete);
        }
    });
    let state = controller.clone();
    ui.on_close_session(move |index| {
        perform(&state, |state| state.request_close_tab(index as usize));
    });
    let state = controller.clone();
    ui.on_finish_close_session(move |confirmed| {
        perform(&state, |state| state.finish_close_tab(confirmed));
    });
    let state = controller.clone();
    ui.window().on_close_requested(move || {
        let (window, running) = {
            let state = state.borrow();
            (
                state.window,
                state.tabs.iter().any(|tab| tab.session.is_some()),
            )
        };
        if !running
            || confirm(
                window,
                "Close SentinelSSH and disconnect all running SSH sessions?",
            )
        {
            slint::CloseRequestResponse::HideWindow
        } else {
            slint::CloseRequestResponse::KeepWindowShown
        }
    });
}

fn preview_paths() -> Result<AppPaths> {
    // A new random directory under the user's temporary folder keeps disposable preview data away
    // from the real vault and from the build machine's source path compiled into the executable.
    let nonce = super::crypto::random::<16>()?;
    let name: String = nonce.iter().map(|byte| format!("{byte:02x}")).collect();
    let root = std::env::temp_dir().join(format!("SentinelSSH-preview-{name}"));
    std::fs::create_dir(&root)
        .map_err(|error| format!("Cannot create the preview workspace: {error}"))?;
    super::paths::secure_directory(&root)?;
    let database_dir = root.join("database");
    super::paths::secure_directory(&database_dir)?;
    Ok(AppPaths {
        known_hosts: root.join("known_hosts"),
        ssh: root.join("no-ssh.exe"),
        root,
        database_dir,
    })
}

fn preview_snapshot(ui: &Workspace, state: &Controller, name: &str) -> Result<()> {
    let mut pixels = ui
        .window()
        .take_snapshot()
        .map_err(|error| error.to_string())?;
    if ui.get_terminal_visible()
        && let Some(tab) = state.active.and_then(|index| state.tabs.get(index))
    {
        let terminal = terminal_pixels(tab.terminal)?;
        let [x, y, _, _] = tab
            .bounds
            .ok_or("Preview terminal has not been positioned.")?;
        let width = pixels.width() as usize;
        let height = pixels.height() as usize;
        let target = pixels.make_mut_slice();
        for row in 0..terminal.height() as usize {
            for column in 0..terminal.width() as usize {
                let (dx, dy) = (x as usize + column, y as usize + row);
                if dx < width && dy < height {
                    target[dy * width + dx] =
                        terminal.as_slice()[row * terminal.width() as usize + column];
                }
            }
        }
    }
    let mut bytes = Vec::with_capacity(pixels.as_bytes().len() + 54);
    bytes.extend_from_slice(b"BM");
    bytes.extend_from_slice(&((pixels.as_bytes().len() + 54) as u32).to_le_bytes());
    bytes.extend_from_slice(&[0; 4]);
    bytes.extend_from_slice(&54u32.to_le_bytes());
    bytes.extend_from_slice(&40u32.to_le_bytes());
    bytes.extend_from_slice(&(pixels.width() as i32).to_le_bytes());
    bytes.extend_from_slice(&(-(pixels.height() as i32)).to_le_bytes());
    bytes.extend_from_slice(&1u16.to_le_bytes());
    bytes.extend_from_slice(&32u16.to_le_bytes());
    bytes.extend_from_slice(&[0; 24]);
    for pixel in pixels.as_slice() {
        bytes.extend_from_slice(&[pixel.b, pixel.g, pixel.r, 255]);
    }
    std::fs::write(state.paths.root.join(format!("{name}.bmp")), bytes)
        .map_err(|error| error.to_string())
}

#[derive(Default)]
struct NavigationSmokeState {
    step: u8,
    full_width: f32,
    full_height: f32,
}

fn verify_terminal_layout(ui: &Workspace, state: &Controller) -> Result<()> {
    let terminal = state
        .active
        .and_then(|index| state.tabs.get(index))
        .map_or(state.empty_terminal, |tab| tab.terminal);
    let mut rect = RECT::default();
    let mut origin = POINT::default();
    // SAFETY: these are owned preview windows; queries compare the native child against Slint's layout.
    unsafe {
        if IsWindowVisible(terminal) == 0 || GetWindowRect(terminal, &mut rect) == 0 {
            return Err("The selected terminal was not restored after navigation.".into());
        }
        origin.x = rect.left;
        origin.y = rect.top;
        ScreenToClient(state.window, &mut origin);
        let scale = GetDpiForWindow(state.window).max(96) as f32 / 96.;
        let actual = [
            origin.x,
            origin.y,
            rect.right - rect.left,
            rect.bottom - rect.top,
        ];
        let expected = [
            ui.get_terminal_x(),
            ui.get_terminal_y(),
            ui.get_terminal_width(),
            ui.get_terminal_height(),
        ]
        .map(|value| (value * scale).round() as i32);
        if actual
            .iter()
            .zip(expected)
            .any(|(actual, expected)| (actual - expected).abs() > 1)
        {
            return Err(
                "Native terminal bounds did not follow the compact workspace layout.".into(),
            );
        }
    }
    Ok(())
}

fn navigation_smoke_test(
    ui: &Workspace,
    controller: &Rc<RefCell<Controller>>,
    phase: &mut NavigationSmokeState,
) -> Result<bool> {
    // Separate timer turns let Winit animate and repaint normally before we inspect native bounds.
    if phase.step == 0 {
        phase.full_width = ui.get_terminal_width();
        phase.full_height = ui.get_terminal_height();
        if ui.get_drawer_open()
            || phase.full_width
                < ui.window().size().width as f32 / ui.window().scale_factor() * 0.95
            || ui.get_terminal_y() > 60.
            || phase.full_height < 500.
        {
            return Err(
                "The default workspace did not give the terminal the available window space."
                    .into(),
            );
        }
        verify_terminal_layout(ui, &controller.borrow())?;
        preview_snapshot(ui, &controller.borrow(), "slint-compact-workspace")?;
        ui.invoke_toggle_servers();
        phase.step = 1;
        return Ok(false);
    }
    if phase.step == 1 {
        if !ui.get_drawer_open()
            || phase.full_width - ui.get_terminal_width() < 280.
            || ui.get_terminal_height() != phase.full_height
            || controller.borrow().tabs.len() != 2
        {
            return Err(
                "The server drawer did not open alongside the existing session tabs.".into(),
            );
        }
        verify_terminal_layout(ui, &controller.borrow())?;
        preview_snapshot(ui, &controller.borrow(), "slint-server-drawer")?;
        server_list_smoke_test(ui, controller)?;
        // Editing during the overflow check closes the drawer; let its restored layout settle.
        phase.step = 2;
        return Ok(false);
    }
    if phase.step == 2 {
        if !ui.get_drawer_open() {
            return Err("The overflow check did not restore the server drawer.".into());
        }
        ui.invoke_toggle_servers();
        phase.step = 3;
        return Ok(false);
    }
    if ui.get_drawer_open() || (ui.get_terminal_width() - phase.full_width).abs() > 1. {
        return Err("Closing the server drawer did not restore the terminal width.".into());
    }
    verify_terminal_layout(ui, &controller.borrow())?;
    ui.invoke_open_app_menu();
    if !ui.get_app_menu_open()
        || ui.get_terminal_visible()
        || ui.get_terminal_image().size().width == 0
        || controller
            .borrow()
            .tabs
            .iter()
            .any(|tab| tab.shown || tab.input_attached)
    {
        return Err(
            "The application menu did not cover and detach the native terminals safely.".into(),
        );
    }
    preview_snapshot(ui, &controller.borrow(), "slint-app-menu")?;
    ui.window()
        .dispatch_event(slint::platform::WindowEvent::KeyPressed {
            text: slint::platform::Key::Escape.into(),
        });
    ui.window()
        .dispatch_event(slint::platform::WindowEvent::KeyReleased {
            text: slint::platform::Key::Escape.into(),
        });
    if ui.get_app_menu_open() || ui.get_terminal_image().size().width != 0 {
        return Err(
            "Escape did not dismiss the application menu and clear its terminal image.".into(),
        );
    }
    verify_terminal_layout(ui, &controller.borrow())?;
    ui.invoke_open_app_menu();
    for event in [
        slint::platform::WindowEvent::PointerPressed {
            position: slint::LogicalPosition::new(100., 100.),
            button: slint::platform::PointerEventButton::Left,
        },
        slint::platform::WindowEvent::PointerReleased {
            position: slint::LogicalPosition::new(100., 100.),
            button: slint::platform::PointerEventButton::Left,
        },
    ] {
        ui.window().dispatch_event(event);
    }
    if ui.get_app_menu_open() {
        return Err("Clicking outside the application menu did not dismiss it.".into());
    }
    ui.invoke_open_about();
    if !ui.get_about_open() || ui.get_terminal_visible() {
        return Err("About did not replace the terminal view.".into());
    }
    ui.invoke_close_about();
    verify_terminal_layout(ui, &controller.borrow())?;
    ui.invoke_open_app_menu();
    ui.invoke_lock();
    if ui.get_app_menu_open()
        || ui.get_drawer_open()
        || ui.get_about_open()
        || ui.get_terminal_image().size().width != 0
        || ui.get_unlocked()
    {
        return Err("Locking did not dismiss navigation and clear its terminal image.".into());
    }
    ui.set_master("disposable Slint preview vault passphrase".into());
    ui.invoke_unlock();
    if !ui.get_unlocked() {
        return Err("The navigation lock check could not restore the preview vault.".into());
    }
    verify_terminal_layout(ui, &controller.borrow())?;
    Ok(true)
}

fn server_list_smoke_test(ui: &Workspace, controller: &Rc<RefCell<Controller>>) -> Result<()> {
    let (original_hosts, original_envelope, original_selected) = {
        let state = controller.borrow();
        (state.hosts.clone(), state.envelope.clone(), state.selected)
    };
    {
        let mut state = controller.borrow_mut();
        for index in 1..=27 {
            state.hosts.push(Host {
                name: format!("Overflow server {index}"),
                address: format!("overflow-{index}.example.test"),
                port: 22,
                username: "deploy".into(),
                identity_path: String::new(),
                authentication: Authentication::Key,
                password: None,
            });
        }
        state.sync();
    }
    ui.set_server_scroll_y(0.);
    preview_snapshot(ui, &controller.borrow(), "slint-server-overflow-top")?;
    ui.window()
        .dispatch_event(slint::platform::WindowEvent::PointerScrolled {
            position: slint::LogicalPosition::new(150., ui.get_terminal_y() + 150.),
            delta_x: 0.,
            delta_y: -400.,
        });
    if ui.get_server_scroll_y() >= 0. {
        return Err("The overflowing server list did not respond to the mouse wheel.".into());
    }
    let list_height = ui.get_terminal_height() - 117.;
    ui.set_server_scroll_y(-(30. * 116. - list_height));
    preview_snapshot(ui, &controller.borrow(), "slint-server-overflow-bottom")?;
    let position = slint::LogicalPosition::new(220., ui.get_terminal_y() + 49. + list_height - 36.);
    for event in [
        slint::platform::WindowEvent::PointerPressed {
            position,
            button: slint::platform::PointerEventButton::Left,
        },
        slint::platform::WindowEvent::PointerReleased {
            position,
            button: slint::platform::PointerEventButton::Left,
        },
    ] {
        ui.window().dispatch_event(event);
    }
    if !ui.get_editor_open()
        || ui.get_server_name() != "Overflow server 27"
        || controller.borrow().selected != Some(29)
    {
        return Err(
            "The last server's Edit button did not work after scrolling to the bottom.".into(),
        );
    }
    ui.invoke_close_editor();
    {
        let mut state = controller.borrow_mut();
        state.remember_server_use(2)?;
        state.remember_server_use(2)?;
        if state
            .hosts
            .iter()
            .take(3)
            .map(|host| host.name.as_str())
            .collect::<Vec<_>>()
            != ["Production", "Staging", "Home server"]
            || state.selected != Some(0)
            || ui.get_server_scroll_y() != 0.
        {
            return Err(
                "Recently used servers did not move to the top in connection order.".into(),
            );
        }
        let sealed = state
            .store
            .read()?
            .ok_or("Recent server order was not saved.")?;
        let (_, reopened) = UnlockedVault::unlock(
            &Secret(b"disposable Slint preview vault passphrase".to_vec()),
            &sealed,
        )?;
        if reopened != state.hosts {
            return Err("Recent server order did not survive reading the saved vault.".into());
        }
        if state.remember_server_use(usize::MAX).is_ok()
            || state.store.read()?.as_ref() != Some(&sealed)
        {
            return Err("An invalid server index changed the recent server order.".into());
        }
    }
    ui.invoke_edit_server(0);
    if ui.get_server_name() != "Production" {
        return Err("Server editing no longer matches the reordered list.".into());
    }
    ui.invoke_close_editor();
    {
        let mut state = controller.borrow_mut();
        state.hosts = original_hosts;
        state.store.write(
            original_envelope
                .as_ref()
                .ok_or("Preview inventory missing.")?,
        )?;
        state.envelope = original_envelope;
        state.selected = original_selected;
        state.reset_editor();
        state.sync();
    }
    ui.set_drawer_open(true);
    ui.set_server_scroll_y(0.);
    Ok(())
}

fn smoke_test(ui: &Workspace, controller: &Rc<RefCell<Controller>>) -> Result<()> {
    ui.invoke_edit_server(0);
    if ui.get_server_name() != "Home server" || !ui.get_editor_open() {
        return Err("Edit callback did not open the selected server.".into());
    }
    preview_snapshot(ui, &controller.borrow(), "slint-editor")?;
    ui.set_password_login(true);
    ui.set_server_password("disposable smoke-test SSH password".into());
    ui.invoke_save_server();
    if !ui.get_server_password().is_empty() || ui.get_editor_open() {
        return Err("Save did not clear the password field and return to sessions.".into());
    }
    {
        let state = controller.borrow();
        let vault = state
            .vault
            .as_ref()
            .ok_or("Preview vault locked unexpectedly.")?;
        if vault
            .decrypt_password(
                state.hosts[0]
                    .password
                    .as_ref()
                    .ok_or("Saved password missing.")?,
            )?
            .0
            != b"disposable smoke-test SSH password"
        {
            return Err("Saved password did not round trip.".into());
        }
        if String::from_utf8_lossy(state.envelope.as_ref().unwrap())
            .contains("disposable smoke-test SSH password")
        {
            return Err("Password appears in the vault envelope.".into());
        }
    }
    ui.invoke_edit_server(0);
    ui.invoke_save_server();
    let mut expected_hosts = 3;
    if super::paths::system_openssh_directory()?
        .join("ssh-keygen.exe")
        .is_file()
    {
        ui.invoke_new_server();
        ui.set_server_name("Generated key server".into());
        ui.set_address("192.0.2.10".into());
        ui.set_username("deploy".into());
        ui.set_keygen_open(true);
        ui.set_key_passphrase("mismatch".into());
        ui.set_key_confirmation("different".into());
        ui.invoke_generate_key();
        if ui.get_generating_key()
            || !ui.get_key_passphrase().is_empty()
            || !ui.get_key_confirmation().is_empty()
        {
            return Err("Mismatched key passphrases were not rejected and cleared.".into());
        }
        preview_snapshot(ui, &controller.borrow(), "slint-keygen")?;
        ui.set_key_passphrase("disposable smoke-test key passphrase".into());
        ui.set_key_confirmation("disposable smoke-test key passphrase".into());
        ui.invoke_generate_key();
        if !ui.get_generating_key()
            || !ui.get_key_passphrase().is_empty()
            || !ui.get_key_confirmation().is_empty()
        {
            return Err(
                "Key generation did not start asynchronously and clear the passphrase fields."
                    .into(),
            );
        }
        let deadline = Instant::now() + Duration::from_secs(20);
        while ui.get_generating_key() && Instant::now() < deadline {
            controller.borrow_mut().poll_key_generation();
            std::thread::sleep(Duration::from_millis(20));
        }
        let identity = ui.get_identity();
        let public_key = ui.get_public_key();
        if ui.get_generating_key()
            || identity.is_empty()
            || public_key.is_empty()
            || !std::path::Path::new(identity.as_str()).is_file()
            || keygen::read_public_key(std::path::Path::new(identity.as_str()))?
                != public_key.as_str()
        {
            return Err(format!(
                "Key generation did not save a usable pair: {}",
                ui.get_status()
            ));
        }
        preview_snapshot(ui, &controller.borrow(), "slint-public-key")?;
        ui.invoke_save_server();
        ui.invoke_edit_server(3);
        if ui.get_identity() != identity || ui.get_public_key() != public_key {
            return Err(
                "Reopening the server did not restore its generated key and public-key display."
                    .into(),
            );
        }
        ui.invoke_close_editor();
        expected_hosts = 4;
    }
    ui.invoke_select_session(0);
    if ui.get_active_session() != 0 || ui.get_editor_open() {
        return Err("Session callback did not select the requested tab.".into());
    }
    // Preview tabs do not connect to SSH; open their confirmation explicitly to exercise its UI.
    controller.borrow_mut().show_close_confirmation(0)?;
    ui.set_key_passphrase("must clear on lock".into());
    ui.set_key_confirmation("must clear on lock".into());
    if !ui.get_close_confirmation_open()
        || ui.get_skip_close_confirmation()
        || ui.get_terminal_visible()
        || controller.borrow().tabs.iter().any(|tab| tab.shown)
    {
        return Err(
            "Session-close confirmation did not start unchecked and hide the terminals.".into(),
        );
    }
    preview_snapshot(ui, &controller.borrow(), "slint-close-session")?;
    ui.set_skip_close_confirmation(true);
    ui.invoke_finish_close_session(false);
    if controller.borrow().tabs.len() != 2
        || ui.get_close_confirmation_open()
        || session_close_confirmation_disabled(&controller.borrow().paths.root)
        || !ui.get_terminal_visible()
        || !controller.borrow().tabs[0].shown
    {
        return Err("Cancelling session close changed a tab or saved the checkbox.".into());
    }
    controller.borrow_mut().show_close_confirmation(0)?;
    if ui.get_skip_close_confirmation() {
        return Err("Session-close checkbox was not reset after cancellation.".into());
    }
    ui.invoke_finish_close_session(true);
    if controller.borrow().tabs.len() != 1 || controller.borrow().active != Some(0) {
        return Err("Closing one tab affected the other session.".into());
    }
    if session_close_confirmation_disabled(&controller.borrow().paths.root) {
        return Err("Unchecked session-close checkbox disabled future confirmations.".into());
    }
    {
        let mut state = controller.borrow_mut();
        let index = state.open_tab("Preference check".into(), None)?;
        state.show_close_confirmation(index)?;
    }
    ui.set_skip_close_confirmation(true);
    ui.invoke_finish_close_session(true);
    if !controller.borrow().skip_session_close_confirmation
        || !session_close_confirmation_disabled(&controller.borrow().paths.root)
        || controller.borrow().tabs.len() != 1
    {
        return Err("Confirmed session-close preference did not persist.".into());
    }
    controller.borrow_mut().show_close_confirmation(0)?;
    let window = controller.borrow().window;
    // SAFETY: sends a workstation-lock notification to this disposable preview window only.
    unsafe {
        SendMessageW(window, WM_WTSSESSION_CHANGE, WTS_SESSION_LOCK as usize, 0);
    }
    if ui.get_unlocked()
        || !ui.get_server_password().is_empty()
        || !controller.borrow().hosts.is_empty()
        || ui.get_close_confirmation_open()
        || controller.borrow().pending_close.is_some()
        || !ui.get_key_passphrase().is_empty()
        || !ui.get_key_confirmation().is_empty()
        || !ui.get_public_key().is_empty()
    {
        return Err("Workstation lock did not clear the workspace.".into());
    }
    preview_snapshot(ui, &controller.borrow(), "slint-locked")?;
    ui.set_master("disposable Slint preview vault passphrase".into());
    ui.invoke_unlock();
    if !ui.get_unlocked()
        || !ui.get_master().is_empty()
        || controller.borrow().hosts.len() != expected_hosts
    {
        return Err("Unlock did not restore the encrypted inventory.".into());
    }
    ui.invoke_select_session(0);
    if !ui.get_terminal_visible() || !controller.borrow().tabs[0].shown {
        return Err("Unlock did not restore the visible terminal.".into());
    }
    preview_snapshot(ui, &controller.borrow(), "slint-preview")?;
    settings_smoke_test(ui, controller)?;
    Ok(())
}

fn settings_smoke_test(ui: &Workspace, controller: &Rc<RefCell<Controller>>) -> Result<()> {
    ui.invoke_open_settings();
    if !ui.get_settings_open()
        || ui.get_terminal_visible()
        || controller
            .borrow()
            .tabs
            .iter()
            .any(|tab| tab.shown || tab.input_attached)
        || ui.get_database_location().as_str()
            != controller
                .borrow()
                .paths
                .database_dir
                .join("vault.edb")
                .to_string_lossy()
    {
        return Err(
            "Settings did not show the database location and hide the native terminal.".into(),
        );
    }
    preview_snapshot(ui, &controller.borrow(), "slint-settings")?;
    // Shortcut management remains available without a running SSH connection.
    ui.invoke_open_shortcuts();
    if !ui.get_shortcuts_open() {
        return Err("Shortcuts cannot be managed without a running session.".into());
    }
    ui.invoke_new_shortcut();
    if !ui.get_shortcut_editor_open() || ui.get_shortcuts_open() {
        return Err("New shortcut did not open its settings form.".into());
    }
    ui.set_shortcut_name("Container logs".into());
    ui.set_shortcut_command("docker logs --tail 30 app\nreboot".into());
    let original = controller.borrow().envelope.clone();
    ui.invoke_save_shortcut();
    if controller.borrow().envelope != original || !ui.get_shortcut_editor_open() {
        return Err("An unsafe multiline shortcut changed the vault.".into());
    }
    ui.set_shortcut_command("docker logs --tail 30 app".into());
    preview_snapshot(ui, &controller.borrow(), "slint-new-shortcut")?;
    ui.invoke_save_shortcut();
    if ui.get_shortcut_editor_open()
        || !ui.get_shortcut_command().is_empty()
        || controller.borrow().vault.as_ref().unwrap().shortcuts.len() != 1
    {
        return Err("Custom shortcut was not saved and cleared from the form.".into());
    }
    ui.invoke_new_shortcut();
    ui.set_shortcut_name("container logs".into());
    ui.set_shortcut_command("uptime".into());
    let original = controller.borrow().envelope.clone();
    ui.invoke_save_shortcut();
    if controller.borrow().envelope != original {
        return Err("A duplicate shortcut overwrote the saved inventory.".into());
    }
    ui.set_current_passphrase("incorrect current passphrase".into());
    ui.set_new_passphrase("replacement smoke-test master passphrase".into());
    ui.set_new_passphrase_confirmation("replacement smoke-test master passphrase".into());
    ui.invoke_change_vault_key();
    if controller.borrow().envelope != original
        || !ui.get_current_passphrase().is_empty()
        || !ui.get_new_passphrase().is_empty()
        || !ui.get_new_passphrase_confirmation().is_empty()
    {
        return Err(
            "A wrong current passphrase changed the vault or left secret inputs populated.".into(),
        );
    }
    // Reset only the disposable fixture's retry deadline to exercise further validation immediately.
    controller.borrow_mut().retry_after = Instant::now();
    ui.set_current_passphrase("disposable Slint preview vault passphrase".into());
    ui.set_new_passphrase("replacement smoke-test master passphrase".into());
    ui.set_new_passphrase_confirmation("mismatched confirmation".into());
    ui.invoke_change_vault_key();
    if controller.borrow().envelope != original {
        return Err("Mismatched replacement passphrases changed the saved vault.".into());
    }
    ui.set_current_passphrase("disposable Slint preview vault passphrase".into());
    ui.set_new_passphrase("replacement smoke-test master passphrase".into());
    ui.set_new_passphrase_confirmation("replacement smoke-test master passphrase".into());
    ui.invoke_change_vault_key();
    {
        let state = controller.borrow();
        let sealed = state
            .store
            .read()?
            .ok_or("Settings did not persist the vault.")?;
        if UnlockedVault::unlock(
            &Secret(b"disposable Slint preview vault passphrase".to_vec()),
            &sealed,
        )
        .is_ok()
        {
            return Err("The old passphrase still unlocks the updated vault.".into());
        }
        let (vault, hosts) = UnlockedVault::unlock(
            &Secret(b"replacement smoke-test master passphrase".to_vec()),
            &sealed,
        )?;
        if vault.shortcuts.len() != 1
            || hosts != state.hosts
            || vault
                .decrypt_password(
                    hosts[0]
                        .password
                        .as_ref()
                        .ok_or("Password lost during key change.")?,
                )?
                .0
                != b"disposable smoke-test SSH password"
        {
            return Err("Changing the vault key lost a server, password, or shortcut.".into());
        }
    }
    ui.set_current_passphrase("clear this on lock".into());
    ui.set_new_passphrase("clear this on lock too".into());
    ui.set_delete_data_open(true);
    ui.set_delete_data_confirmation("DELETE".into());
    ui.invoke_lock();
    if ui.get_settings_open()
        || ui.get_shortcut_editor_open()
        || ui.get_delete_data_open()
        || !ui.get_current_passphrase().is_empty()
        || !ui.get_new_passphrase().is_empty()
        || !ui.get_delete_data_confirmation().is_empty()
        || !ui.get_shortcut_command().is_empty()
    {
        return Err("Locking did not clear settings and pending destructive actions.".into());
    }
    let original = controller.borrow().envelope.clone();
    ui.invoke_delete_all_server_data();
    if controller.borrow().envelope != original {
        return Err("A stale delete callback changed the locked vault.".into());
    }
    ui.set_master("replacement smoke-test master passphrase".into());
    ui.invoke_unlock();
    if !ui.get_unlocked() || controller.borrow().vault.as_ref().unwrap().shortcuts.len() != 1 {
        return Err("Unlocking did not restore the updated vault and its shortcut.".into());
    }
    ui.invoke_open_settings();
    let original = controller.borrow().envelope.clone();
    ui.invoke_delete_all_server_data();
    if controller.borrow().envelope != original {
        return Err("Unconfirmed bulk deletion changed the saved servers.".into());
    }
    ui.set_delete_data_open(true);
    ui.set_delete_data_confirmation("DELETE".into());
    ui.invoke_delete_all_server_data();
    {
        let state = controller.borrow();
        let sealed = state
            .store
            .read()?
            .ok_or("Deleted inventory was not saved.")?;
        let (vault, hosts) = UnlockedVault::unlock(
            &Secret(b"replacement smoke-test master passphrase".to_vec()),
            &sealed,
        )?;
        if !hosts.is_empty()
            || !state.hosts.is_empty()
            || !state.tabs.is_empty()
            || state.active.is_some()
            || ui.get_delete_data_open()
            || vault.shortcuts.len() != 1
        {
            return Err(
                "Bulk deletion left servers or session tabs, or removed custom shortcuts.".into(),
            );
        }
    }
    ui.invoke_delete_shortcut(0);
    if controller.borrow().vault.as_ref().unwrap().shortcuts.len() != 1 {
        return Err("Built-in shortcut removal changed custom shortcuts.".into());
    }
    ui.invoke_delete_shortcut(BUILTIN_SHORTCUTS.len() as i32);
    if !controller
        .borrow()
        .vault
        .as_ref()
        .unwrap()
        .shortcuts
        .is_empty()
    {
        return Err("Removing a custom shortcut did not persist.".into());
    }
    ui.invoke_close_settings();
    verify_terminal_layout(ui, &controller.borrow())?;
    Ok(())
}

struct FrontendRuntime {
    controller: Rc<RefCell<Controller>>,
    _native_reference: Box<NativeEvents>,
    timer: slint::Timer,
    smoke_timer: slint::Timer,
}

impl Drop for FrontendRuntime {
    fn drop(&mut self) {
        self.timer.stop();
        self.smoke_timer.stop();
        let window = self.controller.borrow().window;
        // SAFETY: unregister before the boxed Weak is dropped; the live parent belongs to this runtime.
        unsafe {
            WTSUnRegisterSessionNotification(window);
            RemoveWindowSubclass(window, Some(native_events), 71);
        }
    }
}

fn start_runtime(
    ui: &Workspace,
    smoke: bool,
    smoke_result: Rc<RefCell<Result<()>>>,
) -> Result<FrontendRuntime> {
    let handle = ui.window().window_handle();
    let RawWindowHandle::Win32(handle) = handle
        .window_handle()
        .map_err(|error| error.to_string())?
        .as_raw()
    else {
        return Err("The frontend requires a Windows window.".into());
    };
    let window = handle.hwnd.get() as HWND;
    // SAFETY: the Slint window is live; monitor bounds and caption styling use OS-owned handles.
    unsafe {
        let monitor = MonitorFromWindow(window, MONITOR_DEFAULTTONEAREST);
        let mut info = MONITORINFO {
            cbSize: std::mem::size_of::<MONITORINFO>() as u32,
            ..Default::default()
        };
        if GetMonitorInfoW(monitor, &mut info) != 0 {
            let scale = GetDpiForWindow(window).max(96) as f32 / 96.0;
            ui.window().set_size(slint::LogicalSize::new(
                1260f32.min((info.rcWork.right - info.rcWork.left - 48) as f32 / scale),
                850f32.min((info.rcWork.bottom - info.rcWork.top - 70) as f32 / scale),
            ));
        }
        let dark = 1i32;
        windows_sys::Win32::Graphics::Dwm::DwmSetWindowAttribute(
            window,
            windows_sys::Win32::Graphics::Dwm::DWMWA_USE_IMMERSIVE_DARK_MODE as u32,
            std::ptr::from_ref(&dark).cast(),
            std::mem::size_of_val(&dark) as u32,
        );
    }
    let preview = smoke || std::env::args().any(|argument| argument == "--ui-preview");
    let paths = if preview {
        preview_paths()?
    } else {
        AppPaths::discover()?
    };
    if smoke {
        // Tells developers where to review the smoke test's BMP snapshots.
        eprintln!("Preview workspace: {}", paths.root.display());
    }
    let controller = Rc::new(RefCell::new(Controller::new(ui, window, paths, preview)?));
    wire(ui, &controller);
    {
        let mut state = controller.borrow_mut();
        if preview {
            ui.set_master("disposable Slint preview vault passphrase".into());
            ui.set_confirmation("disposable Slint preview vault passphrase".into());
            state.unlock()?;
            state.hosts = ["Home server", "Production", "Staging"]
                .into_iter()
                .enumerate()
                .map(|(index, name)| Host {
                    name: name.into(),
                    address: format!("server-{}.example.test", index + 1),
                    port: 22,
                    username: "deploy".into(),
                    identity_path: String::new(),
                    authentication: Authentication::Key,
                    password: None,
                })
                .collect();
            let sealed = state.vault.as_ref().unwrap().seal(&state.hosts)?;
            state.store.write(&sealed)?;
            state.envelope = Some(sealed);
            state.open_tab("Home server".into(), None)?;
            state.open_tab("Production".into(), None)?;
            terminal_view::feed(state.tabs[1].terminal, b"\x1b[38;2;114;219;177mdeploy@production:~$\x1b[0m uname -a\r\nLinux production 6.8.0 x86_64 GNU/Linux\r\n\r\n\x1b[38;2;114;219;177mdeploy@production:~$\x1b[0m df -h /\r\nFilesystem      Size  Used Avail Use% Mounted on\r\n/dev/vda1        80G   12G   68G  15% /\r\n\r\n\x1b[38;2;114;219;177mdeploy@production:~$\x1b[0m ");
            state.status("Preview workspace · sample servers and terminal output");
        } else {
            state.status("Unlock your vault to open your private workspace.");
        }
        state.sync();
        state.position_terminals();
    }
    let native_reference = Box::new(NativeEvents {
        controller: Rc::downgrade(&controller),
        ui: ui.as_weak(),
    });
    // SAFETY: Slint owns the parent; our subclass only supplements it and its boxed data outlives registration.
    unsafe {
        let style = GetWindowLongPtrW(window, GWL_STYLE);
        SetWindowLongPtrW(window, GWL_STYLE, style | WS_CLIPCHILDREN as isize);
        if SetWindowSubclass(
            window,
            Some(native_events),
            71,
            std::ptr::from_ref(&*native_reference) as usize,
        ) == 0
        {
            return Err("Cannot attach terminal event handling.".into());
        }
        if WTSRegisterSessionNotification(window, NOTIFY_FOR_THIS_SESSION) == 0 {
            RemoveWindowSubclass(window, Some(native_events), 71);
            return Err("Cannot register workstation lock handling.".into());
        }
    }
    let timer = slint::Timer::default();
    let state = controller.clone();
    timer.start(
        slint::TimerMode::Repeated,
        Duration::from_millis(25),
        move || state.borrow_mut().tick(),
    );
    let smoke_timer = slint::Timer::default();
    if smoke {
        let state = controller.clone();
        let weak_ui = ui.as_weak();
        let result = smoke_result.clone();
        let navigation = Rc::new(RefCell::new(NavigationSmokeState::default()));
        let finished = Cell::new(false);
        smoke_timer.start(
            slint::TimerMode::Repeated,
            Duration::from_millis(250),
            move || {
                if finished.get() {
                    return;
                }
                if let Some(ui) = weak_ui.upgrade() {
                    let check =
                        match navigation_smoke_test(&ui, &state, &mut navigation.borrow_mut()) {
                            Ok(false) => return,
                            Ok(true) => smoke_test(&ui, &state),
                            Err(error) => Err(error),
                        };
                    *result.borrow_mut() = check;
                }
                finished.set(true);
                let _ = slint::quit_event_loop();
            },
        );
    }
    Ok(FrontendRuntime {
        controller,
        _native_reference: native_reference,
        timer,
        smoke_timer,
    })
}

pub fn run() -> Result<()> {
    slint::BackendSelector::new()
        .backend_name("winit".into())
        .renderer_name("software".into())
        // GDI child painting clears alpha; an opaque host keeps the terminal from exposing the desktop.
        .with_winit_window_attributes_hook(|attributes| attributes.with_transparent(false))
        .select()
        .map_err(|error| error.to_string())?;
    let ui = Workspace::new().map_err(|error| error.to_string())?;
    ui.show().map_err(|error| error.to_string())?;
    let smoke = std::env::args().any(|argument| argument == "--ui-smoke-test");
    let runtime = Rc::new(RefCell::new(None));
    let outcome = Rc::new(RefCell::new(Ok(())));
    let initialize = slint::Timer::default();
    let runtime_slot = runtime.clone();
    let result = outcome.clone();
    let weak_ui = ui.as_weak();
    // Winit creates the native window when its event loop starts; attach native children after that point.
    initialize.start(
        slint::TimerMode::SingleShot,
        Duration::from_millis(25),
        move || {
            if let Some(ui) = weak_ui.upgrade() {
                match start_runtime(&ui, smoke, result.clone()) {
                    Ok(ready) => *runtime_slot.borrow_mut() = Some(ready),
                    Err(error) => {
                        *result.borrow_mut() = Err(error);
                        let _ = slint::quit_event_loop();
                    }
                }
            }
        },
    );
    slint::run_event_loop().map_err(|error| error.to_string())?;
    initialize.stop();
    drop(runtime.borrow_mut().take());
    outcome.borrow().clone()
}
