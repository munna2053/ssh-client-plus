pub mod core;
pub mod terminal;

#[cfg(windows)]
pub mod windows;

pub type Result<T> = std::result::Result<T, String>;
