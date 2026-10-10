use super::crypto::{self, Secret};
use crate::{
    Result,
    core::{Host, MAX_VAULT_BYTES, Reader, decode_hosts, encode_hosts},
};

const MAGIC: &[u8] = b"SENTINEL-VAULT\x01";
const ITERATIONS: u32 = 600_000;
const HOST_AAD: &[u8] = b"SentinelSSH/v1/host-inventory";

pub struct UnlockedVault {
    data_key: Secret,
    header: Vec<u8>,
}

impl UnlockedVault {
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
}
