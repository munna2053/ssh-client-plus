use super::crypto::{self, DecryptError, Secret};
use crate::{
    Result,
    core::{
        CommandShortcut, Host, MAX_SSH_PASSWORD_BYTES, MAX_VAULT_BYTES, Reader, SavedPassword,
        decode_inventory, encode_inventory,
    },
};

const MAGIC: &[u8] = b"SENTINEL-VAULT\x01";
const ITERATIONS: u32 = 600_000;
const HOST_AAD: &[u8] = b"SentinelSSH/v1/host-inventory";

pub struct UnlockedVault {
    data_key: Secret,
    header: Vec<u8>,
    pub shortcuts: Vec<CommandShortcut>,
}

/// Nonsecret envelope metadata; inspecting it never attempts a master passphrase.
pub struct VaultMetadata {
    pub iterations: u32,
    pub wrapped_key_bytes: usize,
    pub inventory_bytes: usize,
}

pub fn inspect_without_password(bytes: &[u8]) -> Result<VaultMetadata> {
    if bytes.len() > MAX_VAULT_BYTES + 4096 {
        return Err("Vault exceeds size limit.".into());
    }
    let mut reader = Reader::new(bytes);
    if reader.take(MAGIC.len())? != MAGIC {
        return Err("Unsupported vault header.".into());
    }
    let iterations = reader.u32()?;
    reader.take(32)?;
    let bound_len = reader.u32()? as usize;
    if bound_len > 4096 {
        return Err("Invalid wrapped key size.".into());
    }
    let bound = reader.take(bound_len)?;
    let inventory_bytes = bytes
        .len()
        .checked_sub(MAGIC.len() + 4 + 32 + 4 + bound_len)
        .ok_or("Truncated vault header.")?;
    let wrapped = crypto::dpapi(bound, true)?;
    if wrapped.len() != 60 || inventory_bytes < 42 || !(600_000..=10_000_000).contains(&iterations)
    {
        return Err("Unexpected vault envelope dimensions or KDF parameters.".into());
    }
    Ok(VaultMetadata {
        iterations,
        wrapped_key_bytes: wrapped.len(),
        inventory_bytes,
    })
}

impl UnlockedVault {
    pub fn encrypt_password(&self, password: &Secret) -> Result<SavedPassword> {
        validate_password(password)?;
        let id = crypto::random::<16>()?;
        let ciphertext = crypto::encrypt(&self.data_key, &password_aad(&id), &password.0)?;
        Ok(SavedPassword { id, ciphertext })
    }

    pub fn decrypt_password(&self, password: &SavedPassword) -> Result<Secret> {
        let decrypted = crypto::decrypt(
            &self.data_key,
            &password_aad(&password.id),
            &password.ciphertext,
        ).map_err(|error| match error {
            DecryptError::Authentication => "Saved server password failed authentication. Its encrypted record may be damaged; replace the saved password. [SSH_PASSWORD_AUTH]".to_string(),
            other => format!("Cannot decrypt the saved server password: {other}"),
        })?;
        validate_password(&decrypted)?;
        Ok(decrypted)
    }

    pub fn create(password: &Secret) -> Result<Self> {
        let data_key = Secret(crypto::random::<32>()?.to_vec());
        let header = Self::wrap_key(password, &data_key)?;
        Ok(Self {
            data_key,
            header,
            shortcuts: vec![],
        })
    }

    // Rewrap the same data key so existing encrypted server passwords remain usable.
    pub fn change_passphrase(&self, password: &Secret) -> Result<Self> {
        let header = Self::wrap_key(password, &self.data_key)?;
        Ok(Self {
            data_key: Secret(self.data_key.0.clone()),
            header,
            shortcuts: self.shortcuts.clone(),
        })
    }

    fn wrap_key(password: &Secret, data_key: &Secret) -> Result<Vec<u8>> {
        if password.0.len() > 4096 {
            return Err("Master passphrase is too long.".into());
        }
        let passphrase =
            std::str::from_utf8(&password.0).map_err(|_| "Invalid passphrase text.")?;
        if passphrase.chars().count() < 12 {
            return Err("Use a master passphrase with at least 12 characters; a longer phrase is recommended.".into());
        }
        let salt = crypto::random::<32>()?;
        let kek = crypto::derive(password, &salt, ITERATIONS)?;
        let mut header = MAGIC.to_vec();
        header.extend_from_slice(&ITERATIONS.to_le_bytes());
        header.extend_from_slice(&salt);
        let wrapped = crypto::encrypt(&kek, &header, &data_key.0)?;
        let bound = crypto::dpapi(&wrapped, false)?;
        header.extend_from_slice(&(bound.len() as u32).to_le_bytes());
        header.extend_from_slice(&bound);
        Ok(header)
    }

    pub fn unlock(password: &Secret, bytes: &[u8]) -> Result<(Self, Vec<Host>)> {
        if bytes.len() > MAX_VAULT_BYTES + 4096 {
            return Err("Vault exceeds size limit.".into());
        }
        let mut reader = Reader::new(bytes);
        if reader.take(MAGIC.len())? != MAGIC {
            return Err("Unsupported vault format.".into());
        }
        let iterations = reader.u32()?;
        let salt = reader.take(32)?;
        let aad_end = MAGIC.len() + 4 + 32;
        let bound_len = reader.u32()? as usize;
        if bound_len > 4096 {
            return Err("Invalid wrapped key size.".into());
        }
        let bound = reader.take(bound_len)?;
        let kek = crypto::derive(password, salt, iterations)?;
        let wrapped = crypto::dpapi(bound, true)?;
        let data_key = crypto::decrypt(&kek, &bytes[..aad_end], &wrapped).map_err(|error| match error {
            DecryptError::Authentication => "Master passphrase could not verify the vault key. Check the original vault passphrase, keyboard layout, and spaces. The encrypted key/header may also be damaged. [VAULT_KEY_AUTH]".to_string(),
            other => format!("Cannot decrypt the vault key: {other}"),
        })?;
        if data_key.0.len() != 32 {
            return Err("Invalid vault data key.".into());
        }
        let header_end = aad_end + 4 + bound_len;
        let plaintext = crypto::decrypt(&data_key, HOST_AAD, &bytes[header_end..]).map_err(|error| match error {
            DecryptError::Authentication => "Master passphrase verified, but the saved inventory failed authentication. Keep the database and logs for recovery. [VAULT_DATA_AUTH]".to_string(),
            other => format!("Vault key verified, but inventory decryption failed: {other}"),
        })?;
        let (hosts, shortcuts) = decode_inventory(&plaintext.0).map_err(|error| {
            format!("Vault key verified, but the saved inventory format is invalid: {error}")
        })?;
        Ok((
            Self {
                data_key,
                header: bytes[..header_end].to_vec(),
                shortcuts,
            },
            hosts,
        ))
    }

    pub fn seal(&self, hosts: &[Host]) -> Result<Vec<u8>> {
        self.seal_with_shortcuts(hosts, &self.shortcuts)
    }

    pub fn seal_with_shortcuts(
        &self,
        hosts: &[Host],
        shortcuts: &[CommandShortcut],
    ) -> Result<Vec<u8>> {
        let plaintext = Secret(encode_inventory(hosts, shortcuts)?);
        let mut bytes = self.header.clone();
        bytes.extend_from_slice(&crypto::encrypt(&self.data_key, HOST_AAD, &plaintext.0)?);
        Ok(bytes)
    }
}

fn password_aad(id: &[u8; 16]) -> Vec<u8> {
    let mut aad = b"SentinelSSH/v1/ssh-password/".to_vec();
    aad.extend_from_slice(id);
    aad
}

fn validate_password(password: &Secret) -> Result<()> {
    if password.0.is_empty() || password.0.len() > MAX_SSH_PASSWORD_BYTES {
        return Err("The server password must contain 1 to 1022 UTF-8 bytes.".into());
    }
    if password
        .0
        .iter()
        .any(|byte| matches!(byte, 0 | b'\r' | b'\n'))
        || std::str::from_utf8(&password.0).is_err()
    {
        return Err("The server password must be valid text without nulls or line breaks.".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn changing_passphrase_preserves_passwords_and_shortcuts_and_rejects_old_key() {
        let old = Secret(b"original vault passphrase".to_vec());
        let new = Secret(
            "replacement vault passphrase \u{09ac}\u{09be}\u{0982}\u{09b2}\u{09be}"
                .as_bytes()
                .to_vec(),
        );
        let mut vault = UnlockedVault::create(&old).unwrap();
        vault.shortcuts.push(CommandShortcut {
            name: "Logs".into(),
            command: "journalctl -n 30".into(),
        });
        let saved = vault
            .encrypt_password(&Secret(b"saved server password".to_vec()))
            .unwrap();
        let host = Host {
            name: "Password server".into(),
            address: "example.com".into(),
            port: 22,
            username: "deploy".into(),
            identity_path: String::new(),
            authentication: crate::core::Authentication::Password,
            password: Some(saved),
        };
        let original = vault.seal(std::slice::from_ref(&host)).unwrap();
        assert!(
            vault
                .change_passphrase(&Secret(b"too short".to_vec()))
                .is_err()
        );
        assert!(vault.change_passphrase(&Secret(vec![b'a'; 4097])).is_err());
        let changed = vault.change_passphrase(&new).unwrap();
        let sealed = changed.seal(&[host]).unwrap();
        assert!(UnlockedVault::unlock(&old, &sealed).is_err());
        let (reopened, hosts) = UnlockedVault::unlock(&new, &sealed).unwrap();
        assert_eq!(reopened.shortcuts, vault.shortcuts);
        assert_eq!(
            reopened
                .decrypt_password(hosts[0].password.as_ref().unwrap())
                .unwrap()
                .0,
            b"saved server password"
        );
        assert!(UnlockedVault::unlock(&old, &original).is_ok());
        for plaintext in [b"journalctl -n 30".as_slice(), b"saved server password"] {
            assert!(
                !sealed
                    .windows(plaintext.len())
                    .any(|part| part == plaintext)
            );
        }
    }

    #[test]
    fn password_required_even_with_windows_account_access() {
        let password = Secret(b"a long test master passphrase".to_vec());
        let vault = UnlockedVault::create(&password).unwrap();
        let bytes = vault.seal(&[]).unwrap();
        let metadata = inspect_without_password(&bytes).unwrap();
        assert_eq!(metadata.iterations, ITERATIONS);
        assert_eq!(metadata.wrapped_key_bytes, 60);
        assert!(inspect_without_password(&bytes[..vault.header.len()]).is_err());
        let wrong = UnlockedVault::unlock(&Secret(b"incorrect passphrase".to_vec()), &bytes)
            .err()
            .unwrap();
        assert!(wrong.contains("[VAULT_KEY_AUTH]"));
        assert!(
            UnlockedVault::unlock(&password, &bytes)
                .unwrap()
                .1
                .is_empty()
        );
        let mut modified = bytes.clone();
        *modified.last_mut().unwrap() ^= 1;
        let damaged = UnlockedVault::unlock(&password, &modified).err().unwrap();
        assert!(damaged.contains("[VAULT_DATA_AUTH]"));
        let mut unsupported = bytes;
        unsupported[MAGIC.len()..MAGIC.len() + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(UnlockedVault::unlock(&password, &unsupported).is_err());
    }

    #[test]
    fn original_key_only_vault_unlocks_and_resaves_with_the_same_master_key() {
        let password = Secret(b"legacy master passphrase fixture".to_vec());
        let vault = UnlockedVault::create(&password).unwrap();
        let mut legacy = vault.header.clone();
        legacy
            .extend(crypto::encrypt(&vault.data_key, HOST_AAD, b"SSH-HOSTS\x01\0\0\0\0").unwrap());
        let (unlocked, hosts) = UnlockedVault::unlock(&password, &legacy).unwrap();
        assert!(hosts.is_empty());
        let upgraded = unlocked.seal(&hosts).unwrap();
        assert_eq!(
            &legacy[..vault.header.len()],
            &upgraded[..vault.header.len()]
        );
        assert!(UnlockedVault::unlock(&password, &upgraded).is_ok());
    }

    #[test]
    fn stored_password_stays_encrypted_after_inventory_unlock_and_requires_the_correct_data_key() {
        let master = Secret(b"a long test master passphrase".to_vec());
        let vault = UnlockedVault::create(&master).unwrap();
        let password = Secret(b"disposable secret server password".to_vec());
        let saved = vault.encrypt_password(&password).unwrap();
        assert!(
            !saved
                .ciphertext
                .windows(password.0.len())
                .any(|part| part == password.0)
        );
        let host = Host {
            name: "Password server".into(),
            address: "test.example.com".into(),
            port: 22,
            username: "deploy".into(),
            identity_path: String::new(),
            authentication: crate::core::Authentication::Password,
            password: Some(saved.clone()),
        };
        let bytes = vault.seal(&[host]).unwrap();
        let (reopened, hosts) = UnlockedVault::unlock(&master, &bytes).unwrap();
        assert_eq!(hosts[0].password.as_ref().unwrap(), &saved);
        assert_eq!(reopened.decrypt_password(&saved).unwrap().0, password.0);
        let other = UnlockedVault::create(&master).unwrap();
        assert!(other.decrypt_password(&saved).is_err());
        let mut swapped = saved.clone();
        swapped.id[0] ^= 1;
        assert!(vault.decrypt_password(&swapped).is_err());
        let mut damaged = saved;
        *damaged.ciphertext.last_mut().unwrap() ^= 1;
        assert!(vault.decrypt_password(&damaged).is_err());
        for invalid in [b"".as_slice(), b"line\nbreak", b"null\0byte"] {
            assert!(vault.encrypt_password(&Secret(invalid.to_vec())).is_err());
        }
    }
}
