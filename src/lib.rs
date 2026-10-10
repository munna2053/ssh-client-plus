pub mod core;

#[cfg(windows)]
pub mod windows;

pub type Result<T> = std::result::Result<T, String>;
