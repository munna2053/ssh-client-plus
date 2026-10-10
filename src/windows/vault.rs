use super::crypto::{self, Secret};
use crate::{
    Result,
    core::{
        Host, MAX_SSH_PASSWORD_BYTES, MAX_VAULT_BYTES, Reader, SavedPassword, decode_hosts,
        encode_hosts,
    },
};

const MAGIC: &[u8] = b"SENTINEL-VAULT\x01";
const ITERATIONS: u32 = 600_000;
const HOST_AAD: &[u8] = b"SentinelSSH/v1/host-inventory";

pub struct UnlockedVault {
    data_key: Secret,
    header: Vec<u8>,
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
        )?;
        validate_password(&decrypted)?;
        Ok(decrypted)
    }

    pub fn create(password: &Secret) -> Result<Self> {
        let passphrase =
            std::str::from_utf8(&password.0).map_err(|_| "Invalid passphrase text.")?;
        if passphrase.chars().count() < 12 {
            return Err("Use a master passphrase with at least 12 characters; a longer phrase is recommended.".into());
        }
        let salt = crypto::random::<32>()?;
        let kek = crypto::derive(password, &salt, ITERATIONS)?;
        let data_key = Secret(crypto::random::<32>()?.to_vec());
        let mut header = MAGIC.to_vec();
        header.extend_from_slice(&ITERATIONS.to_le_bytes());
        header.extend_from_slice(&salt);
        let wrapped = crypto::encrypt(&kek, &header, &data_key.0)?;
        let bound = crypto::dpapi(&wrapped, false)?;
        header.extend_from_slice(&(bound.len() as u32).to_le_bytes());
        header.extend_from_slice(&bound);
        Ok(Self { data_key, header })
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
        let data_key = crypto::decrypt(&kek, &bytes[..aad_end], &wrapped)?;
        if data_key.0.len() != 32 {
            return Err("Invalid vault data key.".into());
        }
        let header_end = aad_end + 4 + bound_len;
        let plaintext = crypto::decrypt(&data_key, HOST_AAD, &bytes[header_end..])?;
        let hosts = decode_hosts(&plaintext.0)?;
        Ok((
            Self {
                data_key,
                header: bytes[..header_end].to_vec(),
            },
            hosts,
        ))
    }

    pub fn seal(&self, hosts: &[Host]) -> Result<Vec<u8>> {
        let plaintext = Secret(encode_hosts(hosts)?);
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
    fn password_required_even_with_windows_account_access() {
        let password = Secret(b"a long test master passphrase".to_vec());
        let vault = UnlockedVault::create(&password).unwrap();
        let bytes = vault.seal(&[]).unwrap();
        assert!(UnlockedVault::unlock(&Secret(b"incorrect passphrase".to_vec()), &bytes).is_err());
        assert!(
            UnlockedVault::unlock(&password, &bytes)
                .unwrap()
                .1
                .is_empty()
        );
        let mut modified = bytes.clone();
        *modified.last_mut().unwrap() ^= 1;
        assert!(UnlockedVault::unlock(&password, &modified).is_err());
        let mut unsupported = bytes;
        unsupported[MAGIC.len()..MAGIC.len() + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(UnlockedVault::unlock(&password, &unsupported).is_err());
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
