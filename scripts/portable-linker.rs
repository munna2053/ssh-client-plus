//! Normalize Rust's Windows module-definition files before invoking LLVM's GNU linker.
use std::{
    env, fs,
    process::{Command, ExitCode},
};

fn main() -> ExitCode {
    let mut arguments: Vec<_> = env::args_os()
        .skip(1)
        .map(|value| {
            if value.to_string_lossy().contains('\r') {
                value.to_string_lossy().replace('\r', "").into()
            } else {
                value
            }
        })
        .collect();
    let mut shared = arguments.iter().any(|argument| argument == "-shared");
    for argument in &arguments {
        let argument_text = argument.to_string_lossy();
        let path = std::path::Path::new(argument_text.strip_prefix('@').unwrap_or(&argument_text));
        if argument_text.starts_with('@')
            || path.extension().is_some_and(|extension| extension == "def")
        {
            match fs::read_to_string(path) {
                Ok(text) if text.contains('\r') => {
                    shared |= text.contains("-shared");
                    if let Err(error) = fs::write(path, text.replace('\r', "")) {
                        eprintln!(
                            "Cannot normalize linker definition {}: {error}",
                            path.display()
                        );
                        return ExitCode::FAILURE;
                    }
                }
                Ok(text) => {
                    shared |= text.contains("-shared");
                }
                Err(error) => {
                    eprintln!("Cannot read linker definition {}: {error}", path.display());
                    return ExitCode::FAILURE;
                }
            }
        }
    }
    if shared {
        arguments.push("--entry=DllMainCRTStartup".into());
    }
    let Some(linker) = env::var_os("SENTINEL_PORTABLE_LLD") else {
        eprintln!("SENTINEL_PORTABLE_LLD must point to LLVM's GNU linker.");
        return ExitCode::FAILURE;
    };
    match Command::new(linker)
        .args(["-flavor", "gnu"])
        .args(arguments)
        .status()
    {
        Ok(status) => ExitCode::from(status.code().unwrap_or(1) as u8),
        Err(error) => {
            eprintln!("Cannot start LLVM linker: {error}");
            ExitCode::FAILURE
        }
    }
}
