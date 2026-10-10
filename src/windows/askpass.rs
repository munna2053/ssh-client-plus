//! Single-use, per-user credential pipe for the system OpenSSH askpass helper.
use super::{
    crypto::{self, Secret},
    paths::private_security,
    wide,
};
use crate::{Result, core::MAX_SSH_PASSWORD_BYTES};
use std::{
    ffi::OsString,
    fs::File,
    io::{Read, Write},
    os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
    path::{Path, PathBuf},
    ptr::{null, null_mut},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU32, Ordering},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};
use windows_sys::Win32::{
    Foundation::{ERROR_NO_DATA, ERROR_PIPE_CONNECTED, ERROR_PIPE_LISTENING, INVALID_HANDLE_VALUE},
    Storage::FileSystem::{
        CreateFileW, FILE_FLAG_FIRST_PIPE_INSTANCE, OPEN_EXISTING, PIPE_ACCESS_DUPLEX,
    },
    System::{
        Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW,
            TH32CS_SNAPPROCESS,
        },
        Pipes::{
            ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, GetNamedPipeClientProcessId,
            GetNamedPipeServerProcessId, PIPE_NOWAIT, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE,
            PeekNamedPipe,
        },
        Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW},
    },
    UI::WindowsAndMessaging::{
        IDYES, MB_DEFBUTTON2, MB_ICONWARNING, MB_SETFOREGROUND, MB_YESNO, MessageBoxW,
    },
};

const PIPE_ENV: &str = "SENTINEL_ASKPASS_PIPE";
const OWNER_ENV: &str = "SENTINEL_ASKPASS_OWNER";
const LIFETIME: Duration = Duration::from_secs(120);

pub struct CredentialBroker {
    pipe: String,
    helper: PathBuf,
    parent: Arc<AtomicU32>,
    cancel: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}

impl CredentialBroker {
    pub fn new(password: Secret, helper: &Path) -> Result<Self> {
        if password.0.is_empty()
            || password.0.len() > MAX_SSH_PASSWORD_BYTES
            || password
                .0
                .iter()
                .any(|byte| matches!(byte, 0 | b'\r' | b'\n'))
            || std::str::from_utf8(&password.0).is_err()
        {
            return Err("Invalid SSH credential.".into());
        }
        if !helper.is_absolute() {
            return Err("The credential helper must have an absolute path.".into());
        }
        let expected_helper = helper
            .canonicalize()
            .map_err(|_| "Cannot locate the credential helper.")?;
        let nonce = crypto::random::<32>()?;
        let token: String = nonce.iter().map(|byte| format!("{byte:02x}")).collect();
        let pipe = format!(r"\\.\pipe\SentinelSSH-{token}");
        let name = wide(&pipe);
        let security = private_security()?;
        let attributes = security.attributes();
        // SAFETY: name/security remain alive; pipe is local, private, non-inheritable and single-instance.
        let raw = unsafe {
            CreateNamedPipeW(
                name.as_ptr(),
                PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
                PIPE_TYPE_BYTE | PIPE_NOWAIT | PIPE_REJECT_REMOTE_CLIENTS,
                1,
                2048,
                64,
                0,
                &attributes,
            )
        };
        if raw == INVALID_HANDLE_VALUE {
            return Err("Cannot create the private credential pipe.".into());
        }
        // SAFETY: CreateNamedPipeW returned an exclusively owned real handle.
        let handle = unsafe { OwnedHandle::from_raw_handle(raw) };
        let cancel = Arc::new(AtomicBool::new(false));
        let parent = Arc::new(AtomicU32::new(0));
        let worker_cancel = Arc::clone(&cancel);
        let worker_parent = Arc::clone(&parent);
        let helper = helper.to_path_buf();
        let worker = thread::Builder::new()
            .name("ssh-credential".into())
            .spawn(move || {
                serve(
                    handle,
                    password,
                    &expected_helper,
                    &worker_parent,
                    &worker_cancel,
                );
            })
            .map_err(|_| "Cannot start the credential handoff.")?;
        Ok(Self {
            pipe,
            helper,
            parent,
            cancel,
            worker: Some(worker),
        })
    }

    pub fn environment(&self) -> Vec<(OsString, OsString)> {
        vec![
            ("SSH_ASKPASS".into(), self.helper.as_os_str().to_owned()),
            ("SSH_ASKPASS_REQUIRE".into(), "force".into()),
            (PIPE_ENV.into(), self.pipe.clone().into()),
            (OWNER_ENV.into(), std::process::id().to_string().into()),
        ]
    }

    pub fn authorize_parent(&self, process: u32) {
        self.parent.store(process, Ordering::Release);
    }

    pub fn cancel(&mut self) {
        self.cancel.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

impl Drop for CredentialBroker {
    fn drop(&mut self) {
        self.cancel();
    }
}

fn pending(cancel: &AtomicBool, deadline: Instant) -> bool {
    !cancel.load(Ordering::Acquire) && Instant::now() < deadline
}

fn read_signal(pipe: &mut File, cancel: &AtomicBool, deadline: Instant) -> Option<u8> {
    while pending(cancel, deadline) {
        let mut available = 0;
        // SAFETY: pipe is owned and connected; only the available-byte count is requested.
        if unsafe {
            PeekNamedPipe(
                pipe.as_raw_handle(),
                null_mut(),
                0,
                null_mut(),
                &mut available,
                null_mut(),
            )
        } == 0
        {
            return None;
        }
        if available == 0 {
            thread::sleep(Duration::from_millis(20));
            continue;
        }
        let mut byte = [0];
        match pipe.read(&mut byte) {
            Ok(1) => return Some(byte[0]),
            Ok(_) => return None,
            Err(error) if error.raw_os_error() == Some(ERROR_NO_DATA as i32) => {}
            Err(_) => return None,
        }
        thread::sleep(Duration::from_millis(20));
    }
    None
}

fn serve(
    handle: OwnedHandle,
    password: Secret,
    helper: &Path,
    parent: &AtomicU32,
    cancel: &AtomicBool,
) {
    let mut pipe = File::from(handle);
    let deadline = Instant::now() + LIFETIME;
    while pending(cancel, deadline) {
        // SAFETY: pipe is owned here, opened in nonblocking mode; no overlapped structure is required.
        let connected = unsafe { ConnectNamedPipe(pipe.as_raw_handle(), null_mut()) };
        let error = std::io::Error::last_os_error().raw_os_error();
        if connected == 0 && error != Some(ERROR_PIPE_CONNECTED as i32) {
            if matches!(error, Some(code) if code == ERROR_PIPE_LISTENING as i32 || code == ERROR_NO_DATA as i32)
            {
                if error == Some(ERROR_NO_DATA as i32) {
                    // SAFETY: reset a pipe whose previous client closed without requesting a credential.
                    unsafe {
                        DisconnectNamedPipe(pipe.as_raw_handle());
                    }
                }
                thread::sleep(Duration::from_millis(20));
                continue;
            }
            return;
        }
        // The helper may start before CreateProcessW has returned its parent's PID to us.
        while parent.load(Ordering::Acquire) == 0 && pending(cancel, deadline) {
            thread::sleep(Duration::from_millis(20));
        }
        let mut client = 0;
        // SAFETY: pipe is connected and the PID out parameter is valid.
        let identified =
            unsafe { GetNamedPipeClientProcessId(pipe.as_raw_handle(), &mut client) } != 0;
        if !identified || !trusted_client(client, parent.load(Ordering::Acquire), helper) {
            // SAFETY: disconnects only this untrusted connection; no credential was sent.
            unsafe {
                DisconnectNamedPipe(pipe.as_raw_handle());
            }
            continue;
        }
        if read_signal(&mut pipe, cancel, deadline) != Some(1) || !pending(cancel, deadline) {
            return;
        }
        if pipe
            .write_all(&(password.0.len() as u32).to_le_bytes())
            .is_err()
            || pipe.write_all(&password.0).is_err()
        {
            return;
        }
        drop(password);
        // Keep the pipe alive until the helper has read the bounded payload, or cancellation.
        let _ = read_signal(&mut pipe, cancel, deadline);
        return;
    }
}

fn trusted_client(client: u32, parent: u32, helper: &Path) -> bool {
    if parent == 0 {
        return false;
    }
    // SAFETY: opens a process only for image-name inspection; no mutation rights requested.
    let raw = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, client) };
    if raw.is_null() {
        return false;
    }
    // SAFETY: successful OpenProcess returns an owned real handle.
    let process = unsafe { OwnedHandle::from_raw_handle(raw) };
    let mut name = vec![0_u16; 32768];
    let mut size = name.len() as u32;
    // SAFETY: process is live and buffer has the specified UTF-16 capacity.
    if unsafe {
        QueryFullProcessImageNameW(process.as_raw_handle(), 0, name.as_mut_ptr(), &mut size)
    } == 0
    {
        return false;
    }
    let image = PathBuf::from(String::from_utf16_lossy(&name[..size as usize]));
    let Ok(image) = image.canonicalize() else {
        return false;
    };
    if image != helper {
        return false;
    }
    // SAFETY: takes a read-only process snapshot and returns an owned handle.
    let raw = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if raw == INVALID_HANDLE_VALUE {
        return false;
    }
    // SAFETY: successful snapshot creation returned an owned real handle.
    let snapshot = unsafe { OwnedHandle::from_raw_handle(raw) };
    let mut entry = PROCESSENTRY32W {
        dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
        ..Default::default()
    };
    // SAFETY: entry is correctly sized and snapshot remains owned for enumeration.
    let mut present = unsafe { Process32FirstW(snapshot.as_raw_handle(), &mut entry) };
    while present != 0 {
        if entry.th32ProcessID == client {
            return entry.th32ParentProcessID == parent;
        }
        // SAFETY: entry size and snapshot are unchanged during enumeration.
        present = unsafe { Process32NextW(snapshot.as_raw_handle(), &mut entry) };
    }
    false
}

pub fn is_helper() -> bool {
    std::env::var_os(PIPE_ENV).is_some()
}

pub fn run_helper() -> Result<()> {
    let prompt = std::env::args().nth(1).ok_or("Missing OpenSSH prompt.")?;
    if prompt.contains("Are you sure you want to continue connecting") {
        let message = wide(&format!(
            "Verify this fingerprint through a trusted source before accepting.\n\n{prompt}"
        ));
        let title = wide("SentinelSSH — verify server identity");
        // SAFETY: helper owns no GUI window; message/title are null-terminated and live throughout the dialog.
        let choice = unsafe {
            MessageBoxW(
                null_mut(),
                message.as_ptr(),
                title.as_ptr(),
                MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2 | MB_SETFOREGROUND,
            )
        };
        std::io::stdout()
            .write_all(if choice == IDYES { b"yes\n" } else { b"no\n" })
            .map_err(|_| "Cannot answer host verification.")?;
        return Ok(());
    }
    if !prompt.trim_end().ends_with("'s password:") {
        return Err("Unsupported OpenSSH prompt.".into());
    }
    let pipe = std::env::var(PIPE_ENV).map_err(|_| "Missing credential pipe.")?;
    if !pipe.starts_with(r"\\.\pipe\SentinelSSH-")
        || pipe.len() != r"\\.\pipe\SentinelSSH-".len() + 64
        || !pipe.as_bytes()[pipe.len() - 64..]
            .iter()
            .all(u8::is_ascii_hexdigit)
    {
        return Err("Invalid credential pipe.".into());
    }
    let owner: u32 = std::env::var(OWNER_ENV)
        .ok()
        .and_then(|text| text.parse().ok())
        .ok_or("Missing credential owner.")?;
    let name = wide(&pipe);
    // SAFETY: connects to an existing local pipe; no inherited handles or filesystem creation.
    let raw = unsafe {
        CreateFileW(
            name.as_ptr(),
            0x80000000 | 0x40000000,
            0,
            null(),
            OPEN_EXISTING,
            0,
            null_mut(),
        )
    };
    if raw == INVALID_HANDLE_VALUE {
        return Err("Credential handoff unavailable.".into());
    }
    // SAFETY: CreateFileW returned an owned real handle.
    let handle = unsafe { OwnedHandle::from_raw_handle(raw) };
    let mut server = 0;
    // SAFETY: the connected handle and PID out parameter are valid.
    if unsafe { GetNamedPipeServerProcessId(handle.as_raw_handle(), &mut server) } == 0
        || server != owner
    {
        return Err("Credential owner mismatch.".into());
    }
    let mut pipe = File::from(handle);
    pipe.write_all(&[1])
        .map_err(|_| "Credential request failed.")?;
    let mut length = [0_u8; 4];
    pipe.read_exact(&mut length)
        .map_err(|_| "Credential handoff ended.")?;
    let length = u32::from_le_bytes(length) as usize;
    if !(1..=MAX_SSH_PASSWORD_BYTES).contains(&length) {
        return Err("Invalid credential size.".into());
    }
    // Allocate the newline up front so appending it never reallocates plaintext.
    let mut password = Secret(vec![0; length + 1]);
    pipe.read_exact(&mut password.0[..length])
        .map_err(|_| "Credential handoff ended.")?;
    if password.0[..length]
        .iter()
        .any(|byte| matches!(byte, 0 | b'\r' | b'\n'))
    {
        return Err("Invalid credential payload.".into());
    }
    pipe.write_all(&[2])
        .map_err(|_| "Credential acknowledgement failed.")?;
    password.0[length] = b'\n';
    std::io::stdout()
        .write_all(&password.0)
        .map_err(|_| "Cannot deliver credential to OpenSSH.")?;
    Ok(())
}
