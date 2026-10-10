use crate::{Result, core::MAX_VAULT_BYTES};
use std::{
    path::Path,
    ptr::{null, null_mut},
};
use windows_sys::Win32::Storage::Jet::*;

fn check(code: i32, operation: &str) -> Result<()> {
    if code < 0 {
        Err(format!(
            "{operation} failed (ESE error {code}). Close any other SentinelSSH instance; retain the database and logs for recovery."
        ))
    } else {
        Ok(())
    }
}

/// An exclusive, single-threaded ESE session. Only encrypted envelopes enter it.
pub struct RecordStore {
    instance: JET_INSTANCE,
    session: JET_SESID,
    database: u32,
    table: usize,
    column: u32,
    session_open: bool,
    database_open: bool,
    table_open: bool,
    // ESE sessions/cursors remain on their owning thread.
    thread_bound: std::marker::PhantomData<*mut ()>,
}

impl RecordStore {
    pub fn open(directory: &Path) -> Result<Self> {
        super::paths::secure_directory(directory)?;
        let mut store = Self {
            instance: 0,
            session: 0,
            database: 0,
            table: 0,
            column: 0,
            session_open: false,
            database_open: false,
            table_open: false,
            thread_bound: std::marker::PhantomData,
        };
        let instance_name = super::wide("SentinelSSH");
        check(
            // SAFETY: ESE writes an instance handle into a live out parameter.
            unsafe { JetCreateInstanceW(&mut store.instance, instance_name.as_ptr()) },
            "Create ESE instance",
        )?;
        let directory_text = super::wide(&format!("{}\\", directory.display()));
        for parameter in [JET_paramSystemPath, JET_paramLogFilePath, JET_paramTempPath] {
            check(
                // SAFETY: instance is created but not initialized; path buffer remains alive.
                unsafe {
                    JetSetSystemParameterW(
                        &mut store.instance,
                        0,
                        parameter,
                        0,
                        directory_text.as_ptr(),
                    )
                },
                "Set ESE data paths",
            )?;
        }
        check(
            // SAFETY: valid instance, numeric parameter, no string parameter needed.
            unsafe {
                JetSetSystemParameterW(&mut store.instance, 0, JET_paramCircularLog, 1, null())
            },
            "Enable ESE circular logs",
        )?;
        check(
            // SAFETY: initializes the exclusively owned instance.
            unsafe { JetInit(&mut store.instance) },
            "Recover and initialize ESE",
        )?;
        check(
            // SAFETY: instance is initialized and session out pointer is valid.
            unsafe { JetBeginSessionW(store.instance, &mut store.session, null(), null()) },
            "Begin ESE session",
        )?;
        store.session_open = true;
        let database_path = directory.join("vault.edb");
        let database_name = super::paths::path_wide(&database_path);
        if database_path.exists() {
            check(
                // SAFETY: database path buffer is valid and session is open.
                unsafe { JetAttachDatabaseW(store.session, database_name.as_ptr(), 0) },
                "Attach ESE database",
            )?;
            check(
                // SAFETY: same session and path; database out parameter is writable.
                unsafe {
                    JetOpenDatabaseW(
                        store.session,
                        database_name.as_ptr(),
                        null(),
                        &mut store.database,
                        JET_bitDbExclusive,
                    )
                },
                "Open ESE database",
            )?;
        } else {
            check(
                // SAFETY: creates a new database, without overwrite flags, in the protected directory.
                unsafe {
                    JetCreateDatabaseW(
                        store.session,
                        database_name.as_ptr(),
                        null(),
                        &mut store.database,
                        0,
                    )
                },
                "Create ESE database",
            )?;
        }
        store.database_open = true;
        let table_name = super::wide("encrypted_vault");
        // SAFETY: all handles belong to this session and table out pointer is writable.
        let code = unsafe {
            JetOpenTableW(
                store.session,
                store.database,
                table_name.as_ptr(),
                null(),
                0,
                0,
                &mut store.table,
            )
        };
        if code == JET_errObjectNotFound {
            check(
                // SAFETY: creates the missing singleton table with its default primary index.
                unsafe {
                    JetCreateTableW(
                        store.session,
                        store.database,
                        table_name.as_ptr(),
                        1,
                        100,
                        &mut store.table,
                    )
                },
                "Create encrypted record table",
            )?;
            store.table_open = true;
            let definition = JET_COLUMNDEF {
                cbStruct: std::mem::size_of::<JET_COLUMNDEF>() as u32,
                coltyp: JET_coltypLongBinary,
                grbit: JET_bitColumnTagged,
                ..Default::default()
            };
            let column_name = super::wide("envelope");
            check(
                // SAFETY: valid table and definition; ESE receives no plaintext defaults.
                unsafe {
                    JetAddColumnW(
                        store.session,
                        store.table,
                        column_name.as_ptr(),
                        &definition,
                        null(),
                        0,
                        &mut store.column,
                    )
                },
                "Create encrypted record column",
            )?;
        } else {
            check(code, "Open encrypted record table")?;
            store.table_open = true;
            let mut definition = JET_COLUMNDEF::default();
            let column_name = super::wide("envelope");
            check(
                // SAFETY: the output buffer has exactly the size of JET_COLUMNDEF; info level zero selects it.
                unsafe {
                    JetGetTableColumnInfoW(
                        store.session,
                        store.table,
                        column_name.as_ptr(),
                        (&mut definition as *mut JET_COLUMNDEF).cast(),
                        std::mem::size_of::<JET_COLUMNDEF>() as u32,
                        0,
                    )
                },
                "Read encrypted record schema",
            )?;
            store.column = definition.columnid;
        }
        Ok(store)
    }

    pub fn read(&self) -> Result<Option<Vec<u8>>> {
        // SAFETY: session and table are valid; moves to the singleton record.
        let code = unsafe { JetMove(self.session, self.table, JET_MoveFirst as i32, 0) };
        if code == JET_errNoCurrentRecord {
            return Ok(None);
        }
        check(code, "Locate vault record")?;
        let mut length = 0;
        check(
            // SAFETY: a null output buffer requests the length of the encrypted column.
            unsafe {
                JetRetrieveColumn(
                    self.session,
                    self.table,
                    self.column,
                    null_mut(),
                    0,
                    &mut length,
                    0,
                    null_mut(),
                )
            },
            "Read vault record length",
        )?;
        if length == 0 || length as usize > MAX_VAULT_BYTES + 4096 {
            return Err("Invalid encrypted vault record size.".into());
        }
        let mut bytes = vec![0; length as usize];
        let mut actual = 0;
        check(
            // SAFETY: bytes has space for the full column length reported by ESE.
            unsafe {
                JetRetrieveColumn(
                    self.session,
                    self.table,
                    self.column,
                    bytes.as_mut_ptr().cast(),
                    length,
                    &mut actual,
                    0,
                    null_mut(),
                )
            },
            "Read encrypted vault record",
        )?;
        if actual != length {
            return Err("Vault record changed while being read.".into());
        }
        Ok(Some(bytes))
    }

    pub fn write(&self, encrypted: &[u8]) -> Result<()> {
        if encrypted.is_empty() || encrypted.len() > MAX_VAULT_BYTES + 4096 {
            return Err("Invalid encrypted vault record size.".into());
        }
        check(
            // SAFETY: starts a transaction on the exclusively owned session.
            unsafe { JetBeginTransaction(self.session) },
            "Begin vault transaction",
        )?;
        let result = (|| {
            // SAFETY: moves the valid table cursor to its singleton record.
            let code = unsafe { JetMove(self.session, self.table, JET_MoveFirst as i32, 0) };
            let prep = if code == JET_errNoCurrentRecord {
                JET_prepInsert
            } else {
                check(code, "Locate vault record")?;
                JET_prepReplace
            };
            check(
                // SAFETY: valid cursor position or new-record insertion in the active transaction.
                unsafe { JetPrepareUpdate(self.session, self.table, prep) },
                "Prepare vault record",
            )?;
            check(
                // SAFETY: ESE reads exactly encrypted.len() bytes from the live encrypted buffer.
                unsafe {
                    JetSetColumn(
                        self.session,
                        self.table,
                        self.column,
                        encrypted.as_ptr().cast(),
                        encrypted.len() as u32,
                        0,
                        null(),
                    )
                },
                "Store encrypted vault record",
            )?;
            check(
                // SAFETY: finalizes the prepared update without requesting a bookmark.
                unsafe { JetUpdate(self.session, self.table, null_mut(), 0, null_mut()) },
                "Update vault record",
            )?;
            check(
                // SAFETY: commits without lazy-flush flags, requiring durable log flush.
                unsafe { JetCommitTransaction(self.session, 0) },
                "Commit vault transaction",
            )
        })();
        if result.is_err() {
            // SAFETY: cancels any prepared update and rolls back this session's failed transaction.
            unsafe {
                JetPrepareUpdate(self.session, self.table, JET_prepCancel);
                JetRollback(self.session, JET_bitRollbackAll);
            }
        }
        result
    }
}

impl Drop for RecordStore {
    fn drop(&mut self) {
        // SAFETY: each flagged handle was successfully opened and is closed in dependency order.
        unsafe {
            if self.table_open {
                JetCloseTable(self.session, self.table);
            }
            if self.database_open {
                JetCloseDatabase(self.session, self.database, 0);
            }
            if self.session_open {
                JetEndSession(self.session, 0);
            }
            if self.instance != 0 {
                JetTerm(self.instance);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        core::Host,
        windows::{crypto::Secret, vault::UnlockedVault},
    };
    use std::os::windows::process::CommandExt;
    use windows_sys::Win32::System::Threading::{
        CREATE_NO_WINDOW, GetCurrentProcess, TerminateProcess,
    };

    #[test]
    fn recovers_committed_data_and_discards_uncommitted_data_after_process_termination() {
        const PASSWORD: &[u8] = b"disposable crash test passphrase";
        const TEST_NAME: &str = "windows::storage::tests::recovers_committed_data_and_discards_uncommitted_data_after_process_termination";
        if let Some(directory) = std::env::var_os("SENTINEL_CRASH_TEST_DIRECTORY") {
            let store = RecordStore::open(Path::new(&directory)).unwrap();
            let vault = UnlockedVault::create(&Secret(PASSWORD.to_vec())).unwrap();
            let host = Host {
                name: "committed-host".into(),
                address: "committed.example.com".into(),
                port: 22,
                username: "deploy".into(),
                identity_path: String::new(),
                authentication: crate::core::Authentication::Key,
                password: None,
            };
            store.write(&vault.seal(&[host]).unwrap()).unwrap();
            if std::env::var_os("SENTINEL_CRASH_TEST_UNCOMMITTED").is_some() {
                // SAFETY: deliberately leave an outer transaction uncommitted in this disposable child.
                check(
                    unsafe { JetBeginTransaction(store.session) },
                    "Begin crash-test transaction",
                )
                .unwrap();
                // write() commits its nested transaction; the outer transaction is still uncommitted.
                let host = Host {
                    name: "uncommitted-host".into(),
                    address: "uncommitted.example.com".into(),
                    port: 2222,
                    username: "deploy".into(),
                    identity_path: String::new(),
                    authentication: crate::core::Authentication::Key,
                    password: None,
                };
                store.write(&vault.seal(&[host]).unwrap()).unwrap();
            }
            // SAFETY: terminates only this disposable child, deliberately bypassing Rust/ESE cleanup.
            unsafe {
                TerminateProcess(GetCurrentProcess(), 0);
            }
            panic!("The crash-test child should have terminated.");
        }

        for uncommitted in [false, true] {
            let directory = std::env::temp_dir().join(format!(
                "sentinel-crash-test-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            let mut child = std::process::Command::new(std::env::current_exe().unwrap());
            child
                .args(["--exact", TEST_NAME, "--test-threads=1"])
                .env("SENTINEL_CRASH_TEST_DIRECTORY", &directory)
                .creation_flags(CREATE_NO_WINDOW);
            if uncommitted {
                child.env("SENTINEL_CRASH_TEST_UNCOMMITTED", "1");
            }
            let output = child.output().unwrap();
            assert!(
                output.status.success(),
                "Crash-test child failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            let store = RecordStore::open(&directory).unwrap();
            let envelope = store.read().unwrap().unwrap();
            let (_, hosts) = UnlockedVault::unlock(&Secret(PASSWORD.to_vec()), &envelope).unwrap();
            assert_eq!(hosts.len(), 1);
            assert_eq!(hosts[0].name, "committed-host");
        }
    }
}
