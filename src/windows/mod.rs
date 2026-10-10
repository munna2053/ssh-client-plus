pub mod crypto;
pub mod paths;
pub mod process;
pub mod ssh;
pub mod storage;
pub mod ui;
pub mod vault;

pub fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}
