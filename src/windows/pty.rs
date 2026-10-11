//! Windows ConPTY ownership with separate, bounded input/output workers.
use super::{
    crypto::Secret,
    process::{self, ChildProcess},
};
use crate::Result;
use std::{
    ffi::OsString,
    fs::File,
    io::{Read, Write},
    os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
    path::Path,
    ptr::{null, null_mut},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver, SyncSender, TrySendError},
    },
    thread::{self, JoinHandle},
    time::Duration,
};
use windows_sys::Win32::System::{
    Console::{COORD, ClosePseudoConsole, CreatePseudoConsole, HPCON, ResizePseudoConsole},
    IO::CancelSynchronousIo,
    Pipes::CreatePipe,
    Threading::{
        CREATE_UNICODE_ENVIRONMENT, CreateProcessW, DeleteProcThreadAttributeList,
        EXTENDED_STARTUPINFO_PRESENT, InitializeProcThreadAttributeList,
        PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE, PROCESS_INFORMATION, STARTF_USESTDHANDLES,
        STARTUPINFOEXW, UpdateProcThreadAttribute,
    },
};

fn pipe() -> Result<(OwnedHandle, OwnedHandle)> {
    let mut read = null_mut();
    let mut write = null_mut();
    // SAFETY: writable handle outputs; null security attributes make both handles non-inheritable.
    if unsafe { CreatePipe(&mut read, &mut write, null(), 65536) } == 0 {
        return Err("Cannot create the terminal communication pipe.".into());
    }
    // SAFETY: successful CreatePipe returned two owned real handles.
    Ok(unsafe {
        (
            OwnedHandle::from_raw_handle(read),
            OwnedHandle::from_raw_handle(write),
        )
    })
}

struct PseudoConsole(HPCON);
impl Drop for PseudoConsole {
    fn drop(&mut self) {
        // SAFETY: owns a valid pseudo console; output is serviced independently during closure.
        unsafe {
            ClosePseudoConsole(self.0);
        }
    }
}

struct Attributes {
    memory: Vec<usize>,
}
impl Attributes {
    fn new(console: HPCON) -> Result<Self> {
        let mut length = 0;
        // SAFETY: size-only query, no attribute memory is provided.
        unsafe {
            InitializeProcThreadAttributeList(null_mut(), 1, 0, &mut length);
        }
        if length == 0 {
            return Err("Cannot size the terminal process attributes.".into());
        }
        let mut memory = vec![0usize; length.div_ceil(std::mem::size_of::<usize>())];
        // SAFETY: buffer has the required size and alignment and stays alive throughout child creation.
        if unsafe {
            InitializeProcThreadAttributeList(memory.as_mut_ptr().cast(), 1, 0, &mut length)
        } == 0
        {
            return Err("Cannot initialize terminal process attributes.".into());
        }
        let mut attributes = Self { memory };
        // SAFETY: pseudo console is valid; the attribute expects the handle value as its pointer argument.
        if unsafe {
            UpdateProcThreadAttribute(
                attributes.memory.as_mut_ptr().cast(),
                0,
                PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE as usize,
                console as *const _,
                std::mem::size_of::<HPCON>(),
                null_mut(),
                null(),
            )
        } == 0
        {
            return Err("Cannot attach OpenSSH to the embedded terminal.".into());
        }
        Ok(attributes)
    }
}
impl Drop for Attributes {
    fn drop(&mut self) {
        // SAFETY: memory holds an initialized attribute list and is freed after deletion.
        unsafe {
            DeleteProcThreadAttributeList(self.memory.as_mut_ptr().cast());
        }
    }
}

pub struct PtyProcess {
    process: ChildProcess,
    console: Option<PseudoConsole>,
    input: Option<SyncSender<Secret>>,
    output: Receiver<Vec<u8>>,
    cancelled: Arc<AtomicBool>,
    reader: Option<JoinHandle<()>>,
    writer: Option<JoinHandle<()>>,
    final_output: Arc<Mutex<Vec<u8>>>,
}

impl PtyProcess {
    pub fn id(&self) -> u32 {
        self.process.id()
    }
    pub fn input(&self) -> SyncSender<Secret> {
        self.input.as_ref().expect("live terminal input").clone()
    }
    pub fn try_wait(&self) -> Result<Option<u32>> {
        self.process.try_wait()
    }
    pub fn resize(&self, columns: usize, rows: usize) -> Result<()> {
        let size = dimensions(columns, rows);
        let console = self.console.as_ref().ok_or("Terminal has disconnected.")?;
        // SAFETY: owned pseudo console remains live; dimensions fit COORD.
        let status = unsafe { ResizePseudoConsole(console.0, size) };
        if status < 0 {
            return Err(format!(
                "Cannot resize terminal (Windows status 0x{:08X}).",
                status as u32
            ));
        }
        Ok(())
    }
    pub fn output(&self) -> Vec<Vec<u8>> {
        (0..16)
            .filter_map(|_| self.output.try_recv().ok())
            .collect()
    }
    pub fn finish_output(&mut self) -> Vec<Vec<u8>> {
        self.cancelled.store(true, Ordering::Release);
        self.input.take();
        self.process.terminate();
        if let Some(writer) = &self.writer {
            // SAFETY: worker owns a live thread handle; only its blocking write is cancelled.
            unsafe {
                CancelSynchronousIo(writer.as_raw_handle());
            }
        }
        self.console.take();
        if let Some(writer) = self.writer.take() {
            let _ = writer.join();
        }
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
        let mut output: Vec<_> = self.output.try_iter().collect();
        if let Ok(mut final_output) = self.final_output.lock()
            && !final_output.is_empty()
        {
            output.push(std::mem::take(&mut *final_output));
        }
        output
    }
}

fn dimensions(columns: usize, rows: usize) -> COORD {
    COORD {
        X: columns.clamp(2, crate::terminal::MAX_COLUMNS) as i16,
        Y: rows.clamp(2, crate::terminal::MAX_ROWS) as i16,
    }
}

pub fn spawn(
    executable: &Path,
    arguments: &[String],
    directory: &Path,
    overrides: &[(OsString, OsString)],
    columns: usize,
    rows: usize,
) -> Result<PtyProcess> {
    if !executable.is_absolute() {
        return Err("Use an absolute system executable path for the terminal.".into());
    }
    let (input_read, input_write) = pipe()?;
    let (output_read, output_write) = pipe()?;
    let mut console = 0;
    // SAFETY: pipe endpoints remain alive and refer to synchronous, non-inheritable channels.
    let status = unsafe {
        CreatePseudoConsole(
            dimensions(columns, rows),
            input_read.as_raw_handle(),
            output_write.as_raw_handle(),
            0,
            &mut console,
        )
    };
    if status < 0 {
        return Err(format!(
            "Windows could not create the embedded terminal (status 0x{:08X}).",
            status as u32
        ));
    }
    let console = PseudoConsole(console);
    // Start draining before launching the child or tearing down after any launch failure.
    let cancelled = Arc::new(AtomicBool::new(false));
    let drain_cancelled = Arc::clone(&cancelled);
    let final_output = Arc::new(Mutex::new(Vec::new()));
    let reader_final_output = Arc::clone(&final_output);
    let (output_sender, output) = mpsc::sync_channel(128);
    let reader = thread::Builder::new()
        .name("terminal-output".into())
        .spawn(move || {
            let mut output_pipe = File::from(output_read);
            let mut buffer = [0; 8192];
            loop {
                let Ok(length) = output_pipe.read(&mut buffer) else {
                    break;
                };
                if length == 0 {
                    break;
                }
                let mut packet = buffer[..length].to_vec();
                loop {
                    if drain_cancelled.load(Ordering::Acquire) {
                        if let Ok(mut final_output) = reader_final_output.lock() {
                            let count = packet
                                .len()
                                .min((1024 * 1024usize).saturating_sub(final_output.len()));
                            final_output.extend_from_slice(&packet[..count]);
                        }
                        break;
                    }
                    match output_sender.try_send(packet) {
                        Ok(()) => break,
                        Err(TrySendError::Full(returned)) => {
                            packet = returned;
                            thread::sleep(Duration::from_millis(10));
                        }
                        Err(TrySendError::Disconnected(_)) => return,
                    }
                }
            }
        })
        .map_err(|_| "Cannot start the terminal output reader.")?;
    let launch = (|| {
        let mut attributes = Attributes::new(console.0)?;
        let startup = STARTUPINFOEXW {
            StartupInfo: windows_sys::Win32::System::Threading::STARTUPINFOW {
                cb: std::mem::size_of::<STARTUPINFOEXW>() as u32,
                // Prevent redirected parent output from overriding ConPTY's console handles.
                dwFlags: STARTF_USESTDHANDLES,
                hStdInput: windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE,
                hStdOutput: windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE,
                hStdError: windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE,
                ..Default::default()
            },
            lpAttributeList: attributes.memory.as_mut_ptr().cast(),
        };
        let program = super::paths::path_wide(executable);
        let cwd = super::paths::path_wide(directory);
        let mut command = process::command_line(executable, arguments)?;
        let environment = process::environment(overrides)?;
        let mut information = PROCESS_INFORMATION::default();
        // SAFETY: extended startup attributes and all buffers are alive; no application handles are inherited.
        if unsafe {
            CreateProcessW(
                program.as_ptr(),
                command.as_mut_ptr(),
                null(),
                null(),
                0,
                EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT,
                environment.as_ptr().cast(),
                cwd.as_ptr(),
                std::ptr::addr_of!(startup).cast(),
                &mut information,
            )
        } == 0
        {
            return Err(format!(
                "Cannot launch OpenSSH in the terminal: {}",
                std::io::Error::last_os_error()
            ));
        }
        Ok(ChildProcess::take(information))
    })();
    drop(input_read);
    drop(output_write);
    let process = match launch {
        Ok(process) => process,
        Err(error) => {
            cancelled.store(true, Ordering::Release);
            drop(console);
            let _ = reader.join();
            return Err(error);
        }
    };
    let (input, input_receiver) = mpsc::sync_channel::<Secret>(128);
    let write_cancelled = Arc::clone(&cancelled);
    let writer = thread::Builder::new()
        .name("terminal-input".into())
        .spawn(move || {
            let mut input_pipe = File::from(input_write);
            while !write_cancelled.load(Ordering::Acquire) {
                match input_receiver.recv_timeout(Duration::from_millis(50)) {
                    Ok(packet) => {
                        if input_pipe.write_all(&packet.0).is_err() {
                            break;
                        }
                    }
                    Err(mpsc::RecvTimeoutError::Timeout) => {}
                    Err(_) => break,
                }
            }
        });
    let writer = match writer {
        Ok(writer) => writer,
        Err(_) => {
            cancelled.store(true, Ordering::Release);
            process.terminate();
            drop(console);
            let _ = reader.join();
            return Err("Cannot start terminal keyboard input.".into());
        }
    };
    Ok(PtyProcess {
        process,
        console: Some(console),
        input: Some(input),
        output,
        cancelled,
        reader: Some(reader),
        writer: Some(writer),
        final_output,
    })
}

impl Drop for PtyProcess {
    fn drop(&mut self) {
        // The reader keeps draining (discarding queued output) during ClosePseudoConsole, avoiding a full-pipe deadlock.
        self.finish_output();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::terminal::Terminal;
    use std::time::Instant;

    fn fixture(mode: &str) -> PtyProcess {
        spawn(
            &std::env::current_exe().unwrap(),
            &[
                "--exact".into(),
                "windows::pty::tests::pseudoconsole_child_fixture".into(),
                "--nocapture".into(),
            ],
            &std::env::temp_dir(),
            &[("SENTINEL_PTY_FIXTURE".into(), mode.into())],
            100,
            30,
        )
        .unwrap()
    }

    #[test]
    fn pseudoconsole_child_fixture() {
        let Some(mode) = std::env::var_os("SENTINEL_PTY_FIXTURE") else {
            return;
        };
        use windows_sys::Win32::System::Console::{
            GetConsoleMode, GetStdHandle, STD_OUTPUT_HANDLE,
        };
        let mut console_mode = 0;
        // SAFETY: queries this child's OS-owned output handle, without transferring ownership.
        let attached =
            unsafe { GetConsoleMode(GetStdHandle(STD_OUTPUT_HANDLE), &mut console_mode) };
        assert_ne!(attached, 0, "{}", std::io::Error::last_os_error());
        let mut output = std::io::stdout().lock();
        if mode == "flood" {
            let chunk = [b'x'; 8192];
            loop {
                if output.write_all(&chunk).is_err() {
                    break;
                }
            }
        } else {
            output.write_all(b"PTY_READY\r\n").unwrap();
            output.flush().unwrap();
            let mut input = String::new();
            std::io::stdin().read_line(&mut input).unwrap();
            writeln!(output, "RESULT:{}", input.trim_end()).unwrap();
            output.flush().unwrap();
        }
    }

    fn receive(process: &PtyProcess, model: &mut Terminal, wanted: &str) {
        let start = Instant::now();
        loop {
            for packet in process.output() {
                let reply = model.feed(&packet);
                if !reply.is_empty() {
                    process.input().send(Secret(reply)).unwrap();
                }
            }
            if model
                .selection((0, 0), (model.rows - 1, model.columns - 1), 0)
                .contains(wanted)
            {
                return;
            }
            assert!(
                start.elapsed() < Duration::from_secs(10),
                "Missing terminal output {wanted:?}: {:?}",
                model.selection((0, 0), (model.rows - 1, model.columns - 1), 0)
            );
            thread::sleep(Duration::from_millis(10));
        }
    }

    #[test]
    fn pseudoconsole_receives_input_resizes_and_preserves_final_output() {
        let mut process = fixture("echo");
        let mut model = Terminal::new(100, 30);
        receive(&process, &mut model, "PTY_READY");
        process.resize(110, 32).unwrap();
        model.resize(110, 32);
        process
            .input()
            .send(Secret(b"input-fixture\r".to_vec()))
            .unwrap();
        let start = Instant::now();
        while process.try_wait().unwrap().is_none() {
            for packet in process.output() {
                let reply = model.feed(&packet);
                if !reply.is_empty() {
                    let _ = process.input().send(Secret(reply));
                }
            }
            assert!(start.elapsed() < Duration::from_secs(10));
            thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(process.try_wait().unwrap(), Some(0));
        for packet in process.finish_output() {
            model.feed(&packet);
        }
        assert!(
            model
                .selection((0, 0), (model.rows - 1, model.columns - 1), 0)
                .contains("RESULT:input-fixture")
        );
    }

    #[test]
    fn disconnect_terminates_child_even_when_output_queue_is_full() {
        let mut process = fixture("flood");
        thread::sleep(Duration::from_millis(350));
        assert!(
            process.try_wait().unwrap().is_none(),
            "Flood fixture must still be alive before disconnect."
        );
        let start = Instant::now();
        process.finish_output();
        assert!(start.elapsed() < Duration::from_secs(5));
        assert!(process.try_wait().unwrap().is_some());
    }

    #[test]
    fn failed_launch_closes_pseudoconsole_without_hanging() {
        let missing = std::env::temp_dir().join("sentinel-missing-executable-test.exe");
        let start = Instant::now();
        assert!(spawn(&missing, &[], &std::env::temp_dir(), &[], 80, 24).is_err());
        assert!(start.elapsed() < Duration::from_secs(5));
    }
}
