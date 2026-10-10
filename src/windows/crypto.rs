use crate::Result;
use std::{
    ptr::{null, null_mut},
    sync::atomic::{Ordering, compiler_fence},
};
use windows_sys::Win32::{Foundation::LocalFree, Security::Cryptography::*};

/// Best-effort clearing of buffers owned by this application; no Debug/Clone.
pub struct Secret(pub Vec<u8>);

impl Drop for Secret {
    fn drop(&mut self) {
        for byte in &mut self.0 {
            // SAFETY: byte is a valid exclusive reference into this owned buffer.
            unsafe { std::ptr::write_volatile(byte, 0) };
        }
        compiler_fence(Ordering::SeqCst);
    }
}

fn status(code: i32, operation: &str) -> Result<()> {
    if code < 0 {
        Err(format!(
            "{operation} failed (Windows status 0x{:08X}).",
            code as u32
        ))
    } else {
        Ok(())
    }
}

struct Algorithm(BCRYPT_ALG_HANDLE);

impl Algorithm {
    fn open(name: *const u16, flags: u32) -> Result<Self> {
        let mut handle = null_mut();
        status(
            // SAFETY: Windows constant name and writable handle out-parameter are valid.
            unsafe { BCryptOpenAlgorithmProvider(&mut handle, name, null(), flags) },
            "Open crypto provider",
        )?;
        Ok(Self(handle))
    }
}

impl Drop for Algorithm {
    fn drop(&mut self) {
        // SAFETY: this wrapper owns the successfully opened algorithm handle.
        unsafe { BCryptCloseAlgorithmProvider(self.0, 0) };
    }
}

struct Key(BCRYPT_KEY_HANDLE);

impl Drop for Key {
    fn drop(&mut self) {
        // SAFETY: this wrapper owns the successfully generated key handle.
        unsafe { BCryptDestroyKey(self.0) };
    }
}

pub fn random<const N: usize>() -> Result<[u8; N]> {
    let mut buffer = [0; N];
    status(
        // SAFETY: the OS RNG writes at most N bytes into buffer; null selects the system RNG.
        unsafe {
            BCryptGenRandom(
                null_mut(),
                buffer.as_mut_ptr(),
                N as u32,
                BCRYPT_USE_SYSTEM_PREFERRED_RNG,
            )
        },
        "Generate random bytes",
    )?;
    Ok(buffer)
}

pub fn derive(password: &Secret, salt: &[u8], iterations: u32) -> Result<Secret> {
    if password.0.len() > 4096 || !(600_000..=10_000_000).contains(&iterations) || salt.len() != 32
    {
        return Err("Unsupported password or vault KDF parameters.".into());
    }
    let algorithm = Algorithm::open(BCRYPT_SHA256_ALGORITHM, BCRYPT_ALG_HANDLE_HMAC_FLAG)?;
    let mut key = Secret(vec![0; 32]);
    status(
        // SAFETY: all buffers are alive, their lengths match, and key has a 32-byte writable allocation.
        unsafe {
            BCryptDeriveKeyPBKDF2(
                algorithm.0,
                password.0.as_ptr(),
                password.0.len() as u32,
                salt.as_ptr(),
                salt.len() as u32,
                u64::from(iterations),
                key.0.as_mut_ptr(),
                32,
                0,
            )
        },
        "Derive vault key",
    )?;
    Ok(key)
}

fn aes(
    key_bytes: &Secret,
    nonce: &[u8],
    aad: &[u8],
    input: &[u8],
    tag: &mut [u8; 16],
    decrypt: bool,
) -> Result<Secret> {
    if key_bytes.0.len() != 32 || nonce.len() != 12 || input.len() > crate::core::MAX_VAULT_BYTES {
        return Err("Invalid encryption parameters.".into());
    }
    let algorithm = Algorithm::open(BCRYPT_AES_ALGORITHM, 0)?;
    let mode = super::wide("ChainingModeGCM");
    status(
        // SAFETY: the UTF-16 property buffer includes a terminator and remains alive during the call.
        unsafe {
            BCryptSetProperty(
                algorithm.0,
                BCRYPT_CHAINING_MODE,
                mode.as_ptr().cast(),
                (mode.len() * 2) as u32,
                0,
            )
        },
        "Select AES-GCM",
    )?;
    let mut handle = null_mut();
    status(
        // SAFETY: CNG allocates its key object when both object pointer and length are zero.
        unsafe {
            BCryptGenerateSymmetricKey(
                algorithm.0,
                &mut handle,
                null_mut(),
                0,
                key_bytes.0.as_ptr(),
                32,
                0,
            )
        },
        "Create AES key",
    )?;
    let key = Key(handle);
    let mut nonce_owned = nonce.to_vec();
    let mut aad_owned = aad.to_vec();
    let mut info = BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO {
        cbSize: std::mem::size_of::<BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO>() as u32,
        dwInfoVersion: 1,
        pbNonce: nonce_owned.as_mut_ptr(),
        cbNonce: nonce_owned.len() as u32,
        pbAuthData: aad_owned.as_mut_ptr(),
        cbAuthData: aad_owned.len() as u32,
        pbTag: tag.as_mut_ptr(),
        cbTag: 16,
        ..Default::default()
    };
    // Empty plaintext is allowed; a non-null output buffer avoids a sizing-only call.
    let mut output = Secret(vec![0; input.len().max(1)]);
    let mut written = 0;
    // SAFETY: the key, authenticated-mode struct and all referenced buffers remain alive.
    let code = unsafe {
        let function = if decrypt {
            BCryptDecrypt
        } else {
            BCryptEncrypt
        };
        function(
            key.0,
            input.as_ptr(),
            input.len() as u32,
            (&mut info as *mut BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO).cast(),
            null_mut(),
            0,
            output.0.as_mut_ptr(),
            output.0.len() as u32,
            &mut written,
            0,
        )
    };
    if code < 0 && decrypt {
        return Err("Unlock failed: wrong passphrase or damaged vault data.".into());
    }
    status(code, "Encrypt vault data")?;
    if written as usize != input.len() {
        return Err("Unexpected encrypted record length.".into());
    }
    output.0.truncate(written as usize);
    Ok(output)
}

pub fn encrypt(key: &Secret, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    let nonce = random::<12>()?;
    let mut tag = [0; 16];
    let cipher = aes(key, &nonce, aad, plaintext, &mut tag, false)?;
    let mut envelope = Vec::with_capacity(28 + cipher.0.len());
    envelope.extend_from_slice(&nonce);
    envelope.extend_from_slice(&tag);
    envelope.extend_from_slice(&cipher.0);
    Ok(envelope)
}

pub fn decrypt(key: &Secret, aad: &[u8], envelope: &[u8]) -> Result<Secret> {
    if envelope.len() < 28 {
        return Err("Truncated encrypted record.".into());
    }
    let mut tag = envelope[12..28].try_into().unwrap();
    aes(key, &envelope[..12], aad, &envelope[28..], &mut tag, true)
}

pub fn dpapi(input: &[u8], decrypt: bool) -> Result<Vec<u8>> {
    let data = CRYPT_INTEGER_BLOB {
        cbData: input.len() as u32,
        pbData: input.as_ptr().cast_mut(),
    };
    let mut output = CRYPT_INTEGER_BLOB::default();
    // SAFETY: DPAPI reads input and returns a LocalAlloc-owned output on success; no UI is permitted.
    let success = unsafe {
        if decrypt {
            CryptUnprotectData(
                &data,
                null_mut(),
                null(),
                null(),
                null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output,
            )
        } else {
            CryptProtectData(
                &data,
                null(),
                null(),
                null(),
                null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output,
            )
        }
    };
    if success == 0 {
        return Err("Windows account protection failed. This vault is bound to the Windows account that created it.".into());
    }
    // SAFETY: DPAPI supplies cbData readable bytes, and the allocation is freed exactly once.
    let bytes = unsafe {
        let bytes = std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec();
        LocalFree(output.pbData.cast());
        bytes
    };
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gcm_rejects_tampering_wrong_key_and_changed_metadata() {
        let key = Secret(random::<32>().unwrap().to_vec());
        let envelope = encrypt(&key, b"host-record-v1", b"confidential server").unwrap();
        assert_eq!(
            decrypt(&key, b"host-record-v1", &envelope).unwrap().0,
            b"confidential server"
        );
        for index in 0..envelope.len() {
            let mut modified = envelope.clone();
            modified[index] ^= 1;
            assert!(decrypt(&key, b"host-record-v1", &modified).is_err());
        }
        assert!(decrypt(&key, b"different-record", &envelope).is_err());
        assert!(decrypt(&Secret(vec![7; 32]), b"host-record-v1", &envelope).is_err());
        assert_ne!(
            &envelope[..12],
            &encrypt(&key, b"host-record-v1", b"confidential server").unwrap()[..12]
        );
    }
}
