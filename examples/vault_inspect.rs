//! Inspect an encrypted copy without asking for or attempting any master passphrase.
#[cfg(windows)]
fn main() {
    if let Err(error) = inspect() {
        eprintln!("Inspection failed: {error}");
        std::process::exit(1);
    }
}

#[cfg(windows)]
fn inspect() -> sentinel_ssh::Result<()> {
    use sentinel_ssh::windows::{storage::RecordStore, vault::inspect_without_password};
    let snapshot = std::env::args_os().nth(1).ok_or("Supply an isolated snapshot directory under .scratch, containing a clean-shutdown copy of vault.edb.")?;
    let snapshot = std::path::Path::new(&snapshot)
        .canonicalize()
        .map_err(|_| "Cannot locate the snapshot directory.")?;
    let scratch = std::env::current_dir()
        .map_err(|_| "Cannot locate workspace.")?
        .join(".scratch")
        .canonicalize()
        .map_err(|_| "Create an isolated .scratch snapshot first.")?;
    if !snapshot.starts_with(&scratch) || snapshot == scratch {
        return Err(
            "Inspect only an isolated snapshot inside this workspace's .scratch directory.".into(),
        );
    }
    let store = RecordStore::open(&snapshot)?;
    let bytes = store
        .read()?
        .ok_or("No encrypted vault record exists in the snapshot.")?;
    let metadata = inspect_without_password(&bytes)?;
    println!("Vault header: version 1, structurally valid");
    println!("KDF: PBKDF2-SHA256, {} iterations", metadata.iterations);
    println!("Windows account protection: verified");
    println!(
        "Encrypted wrapped key: {} bytes",
        metadata.wrapped_key_bytes
    );
    println!("Encrypted inventory: {} bytes", metadata.inventory_bytes);
    println!(
        "Master passphrase and inventory authentication: require interactive unlock; not attempted"
    );
    Ok(())
}

#[cfg(not(windows))]
fn main() {
    eprintln!("Vault inspection requires Windows.");
}
