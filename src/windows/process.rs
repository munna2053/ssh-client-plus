use crate::Result;
use std::{ffi::OsString, os::windows::ffi::OsStrExt, path::Path};
use windows_sys::Win32::{
    Foundation::{CloseHandle, HANDLE, WAIT_OBJECT_0, WAIT_TIMEOUT},
    System::Threading::{GetExitCodeProcess, PROCESS_INFORMATION, WaitForSingleObject},
};

pub struct ChildProcess {
    handle: HANDLE,
    id: u32,
}

impl ChildProcess {
    pub(crate) fn take(information: PROCESS_INFORMATION) -> Self {
        // SAFETY: successful CreateProcessW returned owned process/thread handles.
        unsafe {
            CloseHandle(information.hThread);
        }
        Self {
            handle: information.hProcess,
            id: information.dwProcessId,
        }
    }
    pub fn terminate(&self) {
        // SAFETY: wrapper owns the process; termination is used only for an explicit session teardown.
        unsafe {
            windows_sys::Win32::System::Threading::TerminateProcess(self.handle, 1);
        }
    }
    pub fn id(&self) -> u32 {
        self.id
    }
    pub fn try_wait(&self) -> Result<Option<u32>> {
        // SAFETY: the process handle remains owned by this wrapper; zero timeout never blocks.
        let wait = unsafe { WaitForSingleObject(self.handle, 0) };
        if wait == WAIT_TIMEOUT {
            return Ok(None);
        }
        if wait != WAIT_OBJECT_0 {
            return Err("Cannot query the SSH process state.".into());
        }
        let mut code = 0;
        // SAFETY: the process is signaled as terminated and the exit-code out parameter is valid.
        if unsafe { GetExitCodeProcess(self.handle, &mut code) } == 0 {
            return Err("Cannot read the SSH exit code.".into());
        }
        Ok(Some(code))
    }
}

impl Drop for ChildProcess {
    fn drop(&mut self) {
        // SAFETY: this wrapper owns the real process handle; closing it does not end the SSH session.
        unsafe {
            CloseHandle(self.handle);
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

pub(crate) fn command_line(executable: &Path, arguments: &[String]) -> Result<Vec<u16>> {
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

pub(crate) fn environment(overrides: &[(OsString, OsString)]) -> Result<Vec<u16>> {
    let mut values: Vec<_> = std::env::vars_os()
        .filter(|(key, _)| {
            !overrides.iter().any(|(name, _)| {
                key.to_string_lossy()
                    .eq_ignore_ascii_case(&name.to_string_lossy())
            })
        })
        .collect();
    values.extend_from_slice(overrides);
    values.sort_by_cached_key(|(key, _)| key.to_string_lossy().to_uppercase());
    let mut block = Vec::new();
    for (key, value) in values {
        let key: Vec<_> = key.encode_wide().collect();
        let value: Vec<_> = value.encode_wide().collect();
        if key.is_empty()
            || key.contains(&0)
            || value.contains(&0)
            || key[1..].contains(&(b'=' as u16))
        {
            return Err("Invalid process environment entry.".into());
        }
        block.extend(key);
        block.push(b'=' as u16);
        block.extend(value);
        block.push(0);
    }
    if block.is_empty() {
        block.push(0);
    }
    block.push(0);
    Ok(block)
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows_sys::Win32::{Foundation::LocalFree, UI::Shell::CommandLineToArgvW};

    #[test]
    fn child_environment_overrides_case_insensitively_without_changing_the_parent() {
        let original_path = std::env::var_os("PATH");
        let overrides = vec![
            ("pAtH".into(), "C:\\test only".into()),
            ("SENTINEL_ENV_TEST".into(), "Unicode ঢাকা".into()),
        ];
        let block = environment(&overrides).unwrap();
        assert!(block.ends_with(&[0, 0]));
        let entries: Vec<_> = block
            .split(|unit| *unit == 0)
            .filter(|entry| !entry.is_empty())
            .map(|entry| String::from_utf16(entry).unwrap())
            .collect();
        assert_eq!(
            entries
                .iter()
                .filter(|entry| entry
                    .split_once('=')
                    .is_some_and(|(key, _)| key.eq_ignore_ascii_case("PATH")))
                .count(),
            1
        );
        assert!(entries.iter().any(|entry| entry == "pAtH=C:\\test only"));
        assert!(
            entries
                .iter()
                .any(|entry| entry == "SENTINEL_ENV_TEST=Unicode ঢাকা")
        );
        assert!(std::env::var_os("PATH") == original_path);
        assert!(environment(&[("invalid=key".into(), "value".into())]).is_err());
        assert!(environment(&[("NAME".into(), "bad\0value".into())]).is_err());
    }

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
