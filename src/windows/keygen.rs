//! Generate standard OpenSSH keys without exposing a passphrase in process arguments or files.
use super::{
    crypto::{self, Secret},
    paths, pty,
};
use crate::Result;
use std::{
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver, TryRecvError},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

pub(crate) struct GeneratedKey {
    pub private_path: PathBuf,
    pub public_key: String,
    retained: bool,
}

impl GeneratedKey {
    pub fn retain(&mut self) {
        self.retained = true;
    }
}

impl Drop for GeneratedKey {
    fn drop(&mut self) {
        if !self.retained {
            // Only these two files in our exclusively created directory can be removed.
            let _ = std::fs::remove_file(&self.private_path);
            let _ = std::fs::remove_file(public_path(&self.private_path));
            if let Some(directory) = self.private_path.parent() {
                let _ = std::fs::remove_dir(directory);
            }
        }
    }
}

pub(crate) struct KeyGeneration {
    result: Receiver<Result<GeneratedKey>>,
    cancelled: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}

impl KeyGeneration {
    pub fn start(root: PathBuf, passphrase: Secret) -> Result<Self> {
        validate_passphrase(&passphrase)?;
        let (sender, result) = mpsc::sync_channel(1);
        let cancelled = Arc::new(AtomicBool::new(false));
        let worker_cancelled = cancelled.clone();
        let worker = thread::Builder::new()
            .name("ssh-keygen".into())
            .spawn(move || {
                let _ = sender.send(generate(&root, &passphrase, &worker_cancelled));
            })
            .map_err(|_| "Cannot start SSH key generation.")?;
        Ok(Self {
            result,
            cancelled,
            worker: Some(worker),
        })
    }

    pub fn poll(&self) -> Option<Result<GeneratedKey>> {
        match self.result.try_recv() {
            Ok(result) => Some(result),
            Err(TryRecvError::Empty) => None,
            Err(TryRecvError::Disconnected) => {
                Some(Err("SSH key generation stopped unexpectedly.".into()))
            }
        }
    }
}

impl Drop for KeyGeneration {
    fn drop(&mut self) {
        self.cancelled.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn validate_passphrase(passphrase: &Secret) -> Result<()> {
    if passphrase.0.len() > crate::core::MAX_SSH_PASSWORD_BYTES
        || std::str::from_utf8(&passphrase.0).is_err()
        || passphrase
            .0
            .iter()
            .any(|byte| matches!(byte, 0 | b'\r' | b'\n'))
    {
        return Err(
            "Use a key passphrase of up to 1022 UTF-8 bytes without nulls or line breaks.".into(),
        );
    }
    Ok(())
}

fn public_path(private_path: &Path) -> PathBuf {
    let mut name = private_path.as_os_str().to_owned();
    name.push(".pub");
    name.into()
}

pub(crate) fn read_public_key(private_path: &Path) -> Result<String> {
    let path = public_path(private_path);
    paths::reject_reparse_point(&path)?;
    let metadata = std::fs::metadata(&path)
        .map_err(|_| "No public key file was found beside this identity.")?;
    if !metadata.is_file() || metadata.len() > 4096 {
        return Err("Invalid public key file.".into());
    }
    let text = std::fs::read_to_string(path).map_err(|_| "Cannot read the public key file.")?;
    let text = text.trim();
    let mut fields = text.split_whitespace();
    if text.chars().any(char::is_control)
        || fields.next() != Some("ssh-ed25519")
        || !fields.next().is_some_and(|key| {
            key.len() == 68
                && key
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"+/=".contains(&byte))
        })
    {
        return Err("Expected an Ed25519 public key in OpenSSH format.".into());
    }
    Ok(text.into())
}

fn generate(root: &Path, passphrase: &Secret, cancelled: &AtomicBool) -> Result<GeneratedKey> {
    validate_passphrase(passphrase)?;
    let executable = paths::system_openssh_directory()?.join("ssh-keygen.exe");
    if !executable.is_file() {
        return Err("Install the Windows OpenSSH Client to create an SSH key pair.".into());
    }
    if cancelled.load(Ordering::Acquire) {
        return Err("SSH key generation cancelled.".into());
    }
    let keys = root.join("keys");
    paths::secure_directory(&keys)?;
    let directory = (0..8)
        .find_map(|_| {
            let nonce = match crypto::random::<16>() {
                Ok(nonce) => nonce,
                Err(error) => return Some(Err(error)),
            };
            let name: String = nonce.iter().map(|byte| format!("{byte:02x}")).collect();
            let directory = keys.join(name);
            match std::fs::create_dir(&directory) {
                Ok(()) => Some(Ok(directory)),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => None,
                Err(error) => Some(Err(format!(
                    "Cannot create the private key directory: {error}"
                ))),
            }
        })
        .ok_or("Cannot allocate a unique SSH key directory.")??;
    let mut key = GeneratedKey {
        private_path: directory.join("id_ed25519"),
        public_key: String::new(),
        retained: false,
    };
    paths::secure_directory(&directory)?;
    let filename = key
        .private_path
        .to_str()
        .ok_or("The SSH key path is not Unicode.")?;
    let arguments = [
        "-q",
        "-t",
        "ed25519",
        "-a",
        "64",
        "-f",
        filename,
        "-C",
        "SentinelSSH",
    ]
    .map(String::from);
    run_keygen(&executable, &arguments, &directory, passphrase, cancelled)?;
    if cancelled.load(Ordering::Acquire) {
        return Err("SSH key generation cancelled.".into());
    }
    paths::secure_file(&key.private_path)?;
    paths::secure_file(&public_path(&key.private_path))?;
    key.public_key = read_public_key(&key.private_path)?;
    Ok(key)
}

// The hidden ConPTY gives Windows OpenSSH a real console for its two masked passphrase prompts.
// Its output is never displayed or logged, and all owned input/output buffers are cleared on drop.
fn run_keygen(
    executable: &Path,
    arguments: &[String],
    directory: &Path,
    passphrase: &Secret,
    cancelled: &AtomicBool,
) -> Result<Secret> {
    struct Process(pty::PtyProcess);
    impl Drop for Process {
        fn drop(&mut self) {
            for bytes in self.0.finish_output() {
                drop(Secret(bytes));
            }
        }
    }
    let mut process = Process(pty::spawn(
        executable,
        arguments,
        directory,
        &[("SSH_ASKPASS_REQUIRE".into(), "never".into())],
        240,
        24,
    )?);
    let mut output = Secret(Vec::with_capacity(8192));
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut first_sent = false;
    let mut second_sent = false;
    loop {
        if cancelled.load(Ordering::Acquire) {
            return Err("SSH key generation cancelled.".into());
        }
        if Instant::now() >= deadline {
            return Err("SSH key generation timed out. Please try again.".into());
        }
        for bytes in process.0.output() {
            let bytes = Secret(bytes);
            if output.0.len() + bytes.0.len() > 8192 {
                return Err("Unexpected output from SSH key generation.".into());
            }
            output.0.extend_from_slice(&bytes.0);
        }
        let contains = |prompt: &[u8]| output.0.windows(prompt.len()).any(|part| part == prompt);
        let first = !first_sent && contains(b"Enter passphrase");
        let second = !second_sent && contains(b"Enter same passphrase again:");
        for prompted in [first, second] {
            if prompted {
                let mut line = Secret(Vec::with_capacity(passphrase.0.len() + 1));
                line.0.extend_from_slice(&passphrase.0);
                line.0.push(b'\r');
                process
                    .0
                    .input()
                    .try_send(line)
                    .map_err(|_| "Cannot deliver the key passphrase to OpenSSH.")?;
            }
        }
        first_sent |= first;
        second_sent |= second;
        if let Some(code) = process.0.try_wait()? {
            for bytes in process.0.finish_output() {
                let bytes = Secret(bytes);
                if output.0.len() + bytes.0.len() > 8192 {
                    return Err("Unexpected output from SSH key generation.".into());
                }
                output.0.extend_from_slice(&bytes.0);
            }
            return if code == 0 {
                Ok(output)
            } else {
                Err(
                    "OpenSSH could not create the key pair. Check the key directory and try again."
                        .into(),
                )
            };
        }
        thread::sleep(Duration::from_millis(20));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        os::windows::process::CommandExt,
        process::{Command, Stdio},
    };
    use windows_sys::Win32::{
        Foundation::LocalFree,
        Security::{
            Authorization::{GetNamedSecurityInfoW, SE_FILE_OBJECT},
            *,
        },
        System::{SystemServices::ACCESS_ALLOWED_ACE_TYPE, Threading::CREATE_NO_WINDOW},
    };

    fn assert_private_permissions(path: &Path) {
        let mut descriptor = std::ptr::null_mut();
        let mut owner = std::ptr::null_mut();
        let mut dacl = std::ptr::null_mut();
        // SAFETY: owned test path and writable security-info outputs remain alive throughout this query.
        unsafe {
            assert_eq!(
                GetNamedSecurityInfoW(
                    paths::path_wide(path).as_ptr(),
                    SE_FILE_OBJECT,
                    OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                    &mut owner,
                    std::ptr::null_mut(),
                    &mut dacl,
                    std::ptr::null_mut(),
                    &mut descriptor
                ),
                0
            );
            assert!(!dacl.is_null());
            assert_eq!((*dacl).AceCount, 1);
            let mut ace = std::ptr::null_mut();
            assert_ne!(GetAce(dacl, 0, &mut ace), 0);
            let access = &*ace.cast::<ACCESS_ALLOWED_ACE>();
            assert_eq!(access.Header.AceType, ACCESS_ALLOWED_ACE_TYPE as u8);
            assert_ne!(
                EqualSid(owner, std::ptr::addr_of!(access.SidStart).cast_mut().cast()),
                0
            );
            let mut control = 0;
            let mut revision = 0;
            assert_ne!(
                GetSecurityDescriptorControl(descriptor, &mut control, &mut revision),
                0
            );
            assert_ne!(control & SE_DACL_PROTECTED, 0);
            LocalFree(descriptor);
        }
    }

    #[test]
    fn generates_unique_encrypted_and_unencrypted_openssh_pairs_with_private_acls() {
        let executable = paths::system_openssh_directory()
            .unwrap()
            .join("ssh-keygen.exe");
        if !executable.is_file() {
            eprintln!("Windows OpenSSH Client missing; key-generation test skipped.");
            return;
        }
        let root =
            std::env::temp_dir().join(format!("Sentinel SSH key test {}", std::process::id()));
        paths::secure_directory(&root).unwrap();
        let cancelled = AtomicBool::new(false);
        let passphrase = Secret(" fixture key passphrase ঢাকা ".as_bytes().to_vec());
        let encrypted = generate(&root, &passphrase, &cancelled).unwrap();
        assert_private_permissions(&encrypted.private_path);
        assert_private_permissions(&public_path(&encrypted.private_path));
        let filename = encrypted.private_path.to_str().unwrap();
        let wrong = Command::new(&executable)
            .args(["-y", "-P", "", "-f", filename])
            .creation_flags(CREATE_NO_WINDOW)
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert!(
            !wrong.status.success(),
            "Encrypted private key accepted an empty passphrase"
        );
        let output = run_keygen(
            &executable,
            &["-y".into(), "-f".into(), filename.into()],
            encrypted.private_path.parent().unwrap(),
            &passphrase,
            &cancelled,
        )
        .unwrap();
        let expected = encrypted
            .public_key
            .split_whitespace()
            .take(2)
            .collect::<Vec<_>>()
            .join(" ");
        assert!(String::from_utf8_lossy(&output.0).contains(&expected));
        assert!(
            !output
                .0
                .windows(passphrase.0.len())
                .any(|bytes| bytes == passphrase.0)
        );
        let original_public = std::fs::read(public_path(&encrypted.private_path)).unwrap();
        let unencrypted = generate(&root, &Secret(vec![]), &cancelled).unwrap();
        assert_ne!(encrypted.private_path, unencrypted.private_path);
        assert_eq!(
            std::fs::read(public_path(&encrypted.private_path)).unwrap(),
            original_public
        );
        let derived = Command::new(&executable)
            .args([
                "-y",
                "-P",
                "",
                "-f",
                unencrypted.private_path.to_str().unwrap(),
            ])
            .creation_flags(CREATE_NO_WINDOW)
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert!(derived.status.success());
        let expected = unencrypted
            .public_key
            .split_whitespace()
            .take(2)
            .collect::<Vec<_>>()
            .join(" ");
        assert!(String::from_utf8_lossy(&derived.stdout).contains(&expected));
        drop(encrypted);
        drop(unencrypted);
        assert_eq!(std::fs::read_dir(root.join("keys")).unwrap().count(), 0);
        std::fs::remove_dir(root.join("keys")).unwrap();
        std::fs::remove_dir(root).unwrap();
    }

    #[test]
    fn rejects_invalid_passphrases_and_cancels_without_creating_keys() {
        for value in [
            b"bad\npass".to_vec(),
            b"bad\rpass".to_vec(),
            b"bad\0pass".to_vec(),
            vec![b'x'; 1023],
            vec![0xff],
        ] {
            assert!(validate_passphrase(&Secret(value)).is_err());
        }
        let root =
            std::env::temp_dir().join(format!("sentinel-keygen-cancel-{}", std::process::id()));
        assert!(generate(&root, &Secret(vec![]), &AtomicBool::new(true)).is_err());
        assert!(!root.exists());
    }

    #[test]
    fn abandoning_generation_cleans_up_only_its_own_unsurfaced_key_files() {
        let root =
            std::env::temp_dir().join(format!("sentinel-keygen-abandon-{}", std::process::id()));
        paths::secure_directory(&root).unwrap();
        let sentinel = root.join("keep.txt");
        std::fs::write(&sentinel, b"keep this existing file").unwrap();
        let job = KeyGeneration::start(root.clone(), Secret(b"disposable key passphrase".to_vec()))
            .unwrap();
        thread::sleep(Duration::from_millis(150));
        drop(job);
        if root.join("keys").is_dir() {
            assert_eq!(std::fs::read_dir(root.join("keys")).unwrap().count(), 0);
            std::fs::remove_dir(root.join("keys")).unwrap();
        }
        assert_eq!(
            std::fs::read(&sentinel).unwrap(),
            b"keep this existing file"
        );
        std::fs::remove_file(sentinel).unwrap();
        std::fs::remove_dir(root).unwrap();
    }
}
