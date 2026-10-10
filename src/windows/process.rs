use crate::Result;
use std::{os::windows::ffi::OsStrExt, path::Path, ptr::null};
use windows_sys::Win32::{
    Foundation::{CloseHandle, HANDLE, WAIT_OBJECT_0, WAIT_TIMEOUT},
    System::Threading::{
        CREATE_NEW_CONSOLE, CreateProcessW, GetExitCodeProcess, PROCESS_INFORMATION, STARTUPINFOW,
        WaitForSingleObject,
    },
};

pub struct ConsoleProcess(HANDLE);

impl ConsoleProcess {
    pub fn try_wait(&self) -> Result<Option<u32>> {
        // SAFETY: the process handle remains owned by this wrapper; zero timeout never blocks.
        let wait = unsafe { WaitForSingleObject(self.0, 0) };
        if wait == WAIT_TIMEOUT {
            return Ok(None);
        }
        if wait != WAIT_OBJECT_0 {
            return Err("Cannot query the SSH process state.".into());
        }
        let mut code = 0;
        // SAFETY: the process is signaled as terminated and the exit-code out parameter is valid.
        if unsafe { GetExitCodeProcess(self.0, &mut code) } == 0 {
            return Err("Cannot read the SSH exit code.".into());
        }
        Ok(Some(code))
    }
}

impl Drop for ConsoleProcess {
    fn drop(&mut self) {
        // SAFETY: this wrapper owns the real process handle; closing it does not end the SSH session.
        unsafe {
            CloseHandle(self.0);
        }
    }
}

// Quote for the Windows argv parsing convention, without introducing a shell.
fn quote_argument(units: impl IntoIterator<Item = u16>) -> Result<Vec<u16>> {
    let mut quoted = vec![b'"' as u16];
    let mut slashes = 0;
    for unit in units {
        if unit == 0 {
            return Err("Process argument contains a null character.".into());
        }
        if unit == b'\\' as u16 {
            slashes += 1;
        } else {
            let count = if unit == b'"' as u16 {
                slashes * 2 + 1
            } else {
                slashes
            };
            quoted.extend(std::iter::repeat_n(b'\\' as u16, count));
            quoted.push(unit);
            slashes = 0;
        }
    }
    quoted.extend(std::iter::repeat_n(b'\\' as u16, slashes * 2));
    quoted.push(b'"' as u16);
    Ok(quoted)
}

fn command_line(executable: &Path, arguments: &[String]) -> Result<Vec<u16>> {
    let mut line = quote_argument(executable.as_os_str().encode_wide())?;
    for argument in arguments {
        line.push(b' ' as u16);
        line.extend(quote_argument(argument.encode_utf16())?);
    }
    line.push(0);
    if line.len() > 32767 {
        return Err("SSH command line is too long.".into());
    }
    Ok(line)
}

pub fn spawn_console(
    executable: &Path,
    arguments: &[String],
    directory: &Path,
) -> Result<ConsoleProcess> {
    if !executable.is_absolute() {
        return Err("The SSH executable must have an absolute system path.".into());
    }
    let executable_wide = super::paths::path_wide(executable);
    let directory_wide = super::paths::path_wide(directory);
    let mut command = command_line(executable, arguments)?;
    let startup = STARTUPINFOW {
        cb: std::mem::size_of::<STARTUPINFOW>() as u32,
        ..Default::default()
    };
    let mut information = PROCESS_INFORMATION::default();
    // SAFETY: buffers and structures remain alive. No handles are inherited and
    // STARTF_USESTDHANDLES is absent, so the new console receives its own stdin/output.
    if unsafe {
        CreateProcessW(
            executable_wide.as_ptr(),
            command.as_mut_ptr(),
            null(),
            null(),
            0,
            CREATE_NEW_CONSOLE,
            null(),
            directory_wide.as_ptr(),
            &startup,
            &mut information,
        )
    } == 0
    {
        return Err(format!(
            "Cannot launch Windows OpenSSH: {}",
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: CreateProcessW returned an owned thread handle; only the process handle is retained.
    unsafe {
        CloseHandle(information.hThread);
    }
    Ok(ConsoleProcess(information.hProcess))
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows_sys::Win32::{Foundation::LocalFree, UI::Shell::CommandLineToArgvW};

    #[test]
    fn windows_argument_parser_preserves_spaces_quotes_unicode_and_trailing_slashes() {
        let program = Path::new("C:\\Program Files\\OpenSSH\\ssh.exe");
        let args: Vec<String> = [
            "",
            "plain",
            "C:\\Keys with spaces\\id_ed25519",
            "C:\\directory with spaces\\",
            "a\\\"b",
            "$(id); reboot",
            "UserKnownHostsFile=\"C:/Data with spaces/known_hosts\"",
            "server \u{2014} \u{09a2}\u{09be}\u{0995}\u{09be}",
            "printf '\\n' \"$status\"",
        ]
        .into_iter()
        .map(String::from)
        .collect();
        let line = command_line(program, &args).unwrap();
        let mut count = 0;
        // SAFETY: command is null terminated; Windows returns a LocalAlloc-owned argv array.
        unsafe {
            let argv = CommandLineToArgvW(line.as_ptr(), &mut count);
            assert!(!argv.is_null());
            let mut parsed = Vec::new();
            for pointer in std::slice::from_raw_parts(argv, count as usize) {
                let mut length = 0;
                while *pointer.add(length) != 0 {
                    length += 1;
                }
                parsed.push(
                    String::from_utf16(std::slice::from_raw_parts(*pointer, length)).unwrap(),
                );
            }
            LocalFree(argv.cast());
            assert_eq!(parsed[0], program.to_str().unwrap());
            assert_eq!(&parsed[1..], &args);
        }
        assert!(command_line(program, &["invalid\0argument".into()]).is_err());
        assert!(command_line(program, &["x".repeat(32768)]).is_err());
    }
}
