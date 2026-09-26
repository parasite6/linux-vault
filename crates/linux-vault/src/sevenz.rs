use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

use crate::error::{Error, Result};

/// Arguments for archive, test, extract, and list. The passphrase is not here.
///
/// Create passes bare `-p`, which makes 7z encrypt and read the passphrase
/// from stdin. Test, extract, and list omit `-p`: on 7-Zip 26.02 a bare `-p`
/// is an empty password, and 7z then does not read stdin. An encrypted archive
/// makes test and extract ask on their own, and that prompt reads stdin.
/// `output_dir` is the `-o` directory for extract.
pub fn command_args(verb: &str, archive_name: &str, output_dir: Option<&str>) -> Vec<String> {
    let mut args = vec![verb.to_string()];
    if verb == "a" {
        args.extend(["-p", "-mhe=on", "-mx=0"].map(str::to_string));
    }
    args.extend(["-y", "-bd"].map(str::to_string));
    if let Some(dir) = output_dir {
        args.push(format!("-o{dir}"));
    }
    args.extend(["--", archive_name].map(str::to_string));
    args
}

pub fn run(seven_zip: &Path, args: &[String], cwd: &Path, passphrase: &[u8]) -> Result<()> {
    finish(spawn(seven_zip, args, cwd)?, Some(passphrase))
}

/// Run 7z with stdin closed and no passphrase bytes.
///
/// `7z l` on an archive with encrypted headers fails this way. A list that
/// succeeds means the archive is not encrypted.
pub fn run_without_passphrase(seven_zip: &Path, args: &[String], cwd: &Path) -> Result<()> {
    finish(spawn(seven_zip, args, cwd)?, None)
}

fn spawn(seven_zip: &Path, args: &[String], cwd: &Path) -> Result<std::process::Child> {
    Command::new(seven_zip)
        .args(args)
        .current_dir(cwd)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                Error::SevenZipMissing
            } else {
                Error::Io(error)
            }
        })
}

fn finish(mut child: std::process::Child, passphrase: Option<&[u8]>) -> Result<()> {
    let write_error = match passphrase {
        Some(passphrase) => child.stdin.take().and_then(|mut stdin| {
            stdin
                .write_all(passphrase)
                .err()
                .or_else(|| stdin.flush().err())
        }),
        None => {
            drop(child.stdin.take());
            None
        }
    };

    let output = child.wait_with_output()?;
    if output.status.success() {
        if let Some(error) = write_error {
            return Err(error.into());
        }
        return Ok(());
    }

    let message = clamp_message(&output.stdout, &output.stderr);
    if is_wrong_passphrase(&message) {
        return Err(Error::WrongPassphrase { message });
    }
    Err(Error::SevenZip {
        status: output.status.code(),
        message,
    })
}

fn is_wrong_passphrase(message: &str) -> bool {
    message.to_ascii_lowercase().contains("wrong password")
}

fn clamp_message(stdout: &[u8], stderr: &[u8]) -> String {
    let mut text = String::from_utf8_lossy(stdout).into_owned();
    if !text.is_empty() && !text.ends_with('\n') {
        text.push('\n');
    }
    text.push_str(&String::from_utf8_lossy(stderr));
    let text = text.trim().to_string();
    const MAX: usize = 2_000;
    if text.len() <= MAX {
        text
    } else {
        let mut end = MAX;
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        text[..end].to_string()
    }
}

pub fn find_seven_zip() -> Result<std::path::PathBuf> {
    if let Some(paths) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&paths) {
            let candidate = dir.join("7z");
            if candidate.is_file() {
                return Ok(candidate);
            }
        }
    }
    let fallback = std::path::PathBuf::from("/usr/bin/7z");
    if fallback.is_file() {
        return Ok(fallback);
    }
    Err(Error::SevenZipMissing)
}
