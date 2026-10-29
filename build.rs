//! Embed the application icon as a compiled Windows resource without an external resource compiler.
use std::{env, fs, path::PathBuf};

const ICON: &str = "assets/icon/sentinel-ssh.ico";
const RT_ICON: u16 = 3;
const RT_GROUP_ICON: u16 = 14;
// The frontend loads its window icon from this group ID.
const ICON_GROUP_ID: u16 = 1;
const LANGUAGE_EN_US: u16 = 0x0409;
const MOVEABLE_DISCARDABLE: u16 = 0x1010;
const MOVEABLE_PURE_DISCARDABLE: u16 = 0x1030;

fn main() {
    println!("cargo:rerun-if-changed={ICON}");
    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }
    let icon = fs::read(ICON).unwrap_or_else(|error| panic!("Cannot read {ICON}: {error}"));
    let path =
        PathBuf::from(env::var_os("OUT_DIR").expect("Cargo sets OUT_DIR")).join("sentinel-ssh.res");
    fs::write(&path, icon_resources(&icon)).expect("Cannot write the icon resource");
    // MSVC link.exe and LLVM's COFF and MinGW linkers all accept a compiled .res file as input.
    println!("cargo:rustc-link-arg-bins={}", path.display());
}

// Converts an .ico file into RT_ICON images plus the RT_GROUP_ICON directory that refers to them.
fn icon_resources(icon: &[u8]) -> Vec<u8> {
    let word = |offset: usize| u16::from_le_bytes([icon[offset], icon[offset + 1]]);
    let dword = |offset: usize| u32::from_le_bytes(icon[offset..offset + 4].try_into().unwrap());
    assert!(
        icon.len() >= 6 && word(0) == 0 && word(2) == 1,
        "{ICON} is not an icon file"
    );
    let count = word(4);
    let mut resources = Vec::new();
    // Every .res file starts with an empty entry.
    push_resource(&mut resources, 0, 0, 0, 0, &[]);
    let mut group = [0, 1, count].map(u16::to_le_bytes).concat();
    for index in 0..count {
        let entry = 6 + 16 * usize::from(index);
        let length = dword(entry + 8) as usize;
        let offset = dword(entry + 12) as usize;
        let image = icon
            .get(offset..offset + length)
            .unwrap_or_else(|| panic!("{ICON} has an image outside the file"));
        let id = index + 1;
        push_resource(
            &mut resources,
            RT_ICON,
            id,
            MOVEABLE_DISCARDABLE,
            LANGUAGE_EN_US,
            image,
        );
        // A group entry repeats the icon entry's dimensions, colour format, and length, then the image ID.
        group.extend_from_slice(&icon[entry..entry + 12]);
        group.extend_from_slice(&id.to_le_bytes());
    }
    push_resource(
        &mut resources,
        RT_GROUP_ICON,
        ICON_GROUP_ID,
        MOVEABLE_PURE_DISCARDABLE,
        LANGUAGE_EN_US,
        &group,
    );
    resources
}

// Appends one resource with a 32-byte header that names its type and ID by ordinal.
fn push_resource(
    resources: &mut Vec<u8>,
    kind: u16,
    id: u16,
    flags: u16,
    language: u16,
    data: &[u8],
) {
    let data_size = u32::try_from(data.len()).expect("Icon resource is too large");
    resources.extend_from_slice(&data_size.to_le_bytes());
    resources.extend_from_slice(&32u32.to_le_bytes());
    for value in [0xffff, kind, 0xffff, id] {
        resources.extend_from_slice(&value.to_le_bytes());
    }
    resources.extend_from_slice(&0u32.to_le_bytes());
    resources.extend_from_slice(&flags.to_le_bytes());
    resources.extend_from_slice(&language.to_le_bytes());
    resources.extend_from_slice(&[0; 8]);
    resources.extend_from_slice(data);
    resources.resize(resources.len().next_multiple_of(4), 0);
}
