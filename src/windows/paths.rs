use crate::Result;
use std::{
    os::windows::{ffi::OsStrExt, fs::MetadataExt},
    path::{Path, PathBuf},
    ptr::{null, null_mut},
};
use windows_sys::Win32::{
    Foundation::{CloseHandle, ERROR_ALREADY_EXISTS, LocalFree},
    Security::{Authorization::*, *},
    Storage::FileSystem::{CreateDirectoryW, FILE_ATTRIBUTE_REPARSE_POINT},
    System::{
        Com::CoTaskMemFree,
        SystemInformation::GetSystemDirectoryW,
        Threading::{GetCurrentProcess, OpenProcessToken},
    },
    UI::Shell::{FOLDERID_LocalAppData, SHGetKnownFolderPath},
};

pub fn path_wide(path: &Path) -> Vec<u16> {
    path.as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

pub struct AppPaths {
    pub root: PathBuf,
    pub database_dir: PathBuf,
    pub known_hosts: PathBuf,
    pub ssh: PathBuf,
}

impl AppPaths {
    pub fn discover() -> Result<Self> {
        let mut local = null_mut();
        // SAFETY: valid known-folder GUID and writable out pointer; no token override.
        let result =
            unsafe { SHGetKnownFolderPath(&FOLDERID_LocalAppData, 0, null_mut(), &mut local) };
        if result < 0 {
            return Err("Cannot locate your Windows local application data directory.".into());
        }
        // SAFETY: on success Windows returns a null-terminated UTF-16 string allocated by COM.
        let local_path = unsafe {
            let mut length = 0;
            while *local.add(length) != 0 {
                length += 1;
            }
            let text = String::from_utf16_lossy(std::slice::from_raw_parts(local, length));
            CoTaskMemFree(local.cast());
            PathBuf::from(text)
        };
        let root = local_path.join("SentinelSSH");
        secure_directory(&root)?;
        let database_dir = root.join("database");
        secure_directory(&database_dir)?;
        let mut system = vec![0_u16; 32768];
        // SAFETY: the output allocation holds 32768 UTF-16 code units.
        let length =
            unsafe { GetSystemDirectoryW(system.as_mut_ptr(), system.len() as u32) } as usize;
        if length == 0 || length >= system.len() {
            return Err("Cannot locate the Windows system directory.".into());
        }
        let ssh = PathBuf::from(String::from_utf16_lossy(&system[..length]))
            .join("OpenSSH")
            .join("ssh.exe");
        let known_hosts = root.join("known_hosts");
        reject_reparse_point(&known_hosts)?;
        Ok(Self {
            root,
            database_dir,
            known_hosts,
            ssh,
        })
    }
}

fn reject_reparse_point(path: &Path) -> Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 => {
            Err("The application data path contains a link or reparse point. Use a normal per-user directory.".into())
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!("Cannot inspect application data path: {error}")),
    }
}

struct LocalAllocation(*mut std::ffi::c_void);

impl Drop for LocalAllocation {
    fn drop(&mut self) {
        // SAFETY: pointer was allocated by a Windows API that requires LocalFree.
        unsafe { LocalFree(self.0) };
    }
}

pub(crate) struct PrivateSecurity(LocalAllocation);

impl PrivateSecurity {
    pub(crate) fn attributes(&self) -> SECURITY_ATTRIBUTES {
        SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: self.0.0,
            bInheritHandle: 0,
        }
    }
}

pub(crate) fn private_security() -> Result<PrivateSecurity> {
    let mut token = null_mut();
    // SAFETY: current process pseudo-handle is valid and token is a writable out pointer.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err("Cannot query the Windows account for vault ACLs.".into());
    }
    let mut required = 0;
    // SAFETY: the first query asks for the buffer size; no output data buffer is provided.
    unsafe { GetTokenInformation(token, TokenUser, null_mut(), 0, &mut required) };
    let mut buffer = vec![0_usize; (required as usize).div_ceil(std::mem::size_of::<usize>())];
    // SAFETY: the allocated buffer is aligned for TOKEN_USER and covers the requested byte count.
    let queried = unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            buffer.as_mut_ptr().cast(),
            required,
            &mut required,
        )
    };
    // SAFETY: token is an owned real handle returned by OpenProcessToken.
    unsafe { CloseHandle(token) };
    if queried == 0 || buffer.is_empty() {
        return Err("Cannot read the Windows account identifier.".into());
    }
    // SAFETY: GetTokenInformation initialized a TOKEN_USER at this aligned buffer address.
    let user = unsafe { &*buffer.as_ptr().cast::<TOKEN_USER>() };
    let mut sid = null_mut();
    // SAFETY: the SID resides in the still-live token buffer; Windows allocates the string.
    if unsafe { ConvertSidToStringSidW(user.User.Sid, &mut sid) } == 0 {
        return Err("Cannot format the Windows account identifier.".into());
    }
    let _sid_allocation = LocalAllocation(sid.cast());
    // SAFETY: ConvertSidToStringSidW returns a null-terminated string on success.
    let sid_text = unsafe {
        let mut length = 0;
        while *sid.add(length) != 0 {
            length += 1;
        }
        String::from_utf16_lossy(std::slice::from_raw_parts(sid, length))
    };
    let descriptor_text = super::wide(&format!("D:P(A;OICI;FA;;;{sid_text})"));
    let mut descriptor = null_mut();
    // SAFETY: valid null-terminated SDDL and writable pointer; revision 1 is supported by Windows.
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            descriptor_text.as_ptr(),
            1,
            &mut descriptor,
            null_mut(),
        )
    } == 0
    {
        return Err("Cannot create vault directory permissions.".into());
    }
    Ok(PrivateSecurity(LocalAllocation(descriptor)))
}

pub fn secure_directory(path: &Path) -> Result<()> {
    reject_reparse_point(path)?;
    let security = private_security()?;
    let attributes = security.attributes();
    let descriptor = attributes.lpSecurityDescriptor;
    let name = path_wide(path);
    // SAFETY: directory name and security descriptor remain alive throughout creation.
    if unsafe { CreateDirectoryW(name.as_ptr(), &attributes) } == 0 {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() != Some(ERROR_ALREADY_EXISTS as i32) {
            return Err(format!("Cannot create protected data directory: {error}"));
        }
    }
    reject_reparse_point(path)?;
    let mut present = 0;
    let mut defaulted = 0;
    let mut dacl = null_mut();
    // SAFETY: descriptor is still alive, and all three out parameters are writable.
    if unsafe { GetSecurityDescriptorDacl(descriptor, &mut present, &mut dacl, &mut defaulted) }
        == 0
        || present == 0
        || dacl.is_null()
    {
        return Err("Cannot read vault directory permissions.".into());
    }
    // SAFETY: dacl is part of descriptor and path points to the directory just validated.
    let code = unsafe {
        SetNamedSecurityInfoW(
            name.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            dacl,
            null(),
        )
    };
    if code != 0 {
        return Err(format!(
            "Cannot enforce private vault directory permissions (Windows error {code})."
        ));
    }
    Ok(())
}
