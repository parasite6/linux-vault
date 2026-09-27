//! Nautilus bookmarks, `<home>/.config/gtk-3.0/bookmarks`.
//!
//! `home` is the passwd directory for the caller's uid, passed in by the
//! worker. `HOME` and `XDG_CONFIG_HOME` are not read. One `file://` URI per
//! line. Create adds the vault. Lock and unlock put the line back if it is
//! missing. Remove leaves the file alone. Terminate removes only that line.
//! A symlink is followed only when its target stays inside this home and is
//! owned by the caller. Otherwise the bookmark is left alone.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

use crate::error::HelperError;

/// Add the vault's line if it is not already there.
///
/// The line is `file://` plus the percent-encoded path, a space, and the
/// vault name. Other lines stay as they are.
pub fn ensure(home: &Path, vault: &Path, name: &str) -> Result<(), HelperError> {
    let Some((directory, path)) = destination(home, true)? else {
        return Ok(());
    };
    let text = read_marks(&path)?;
    if text
        .split_inclusive('\n')
        .any(|line| bookmark_points_at(line, vault))
    {
        return Ok(());
    }
    let mut next = text;
    if !next.is_empty() && !next.ends_with('\n') {
        next.push('\n');
    }
    next.push_str(&format!(
        "file://{} {name}\n",
        percent_encode(&vault_text(vault))
    ));
    write_marks(&directory, &path, &next)
}

/// Remove the bookmark that points at `vault`. A missing file is success.
/// Every other line stays.
pub fn remove(home: &Path, vault: &Path) -> Result<(), HelperError> {
    let Some((directory, path)) = destination(home, false)? else {
        return Ok(());
    };
    let text = read_marks(&path)?;
    let mut kept = String::new();
    for line in text.split_inclusive('\n') {
        if bookmark_points_at(line, vault) {
            continue;
        }
        kept.push_str(line);
    }
    if kept == text {
        return Ok(());
    }
    write_marks(&directory, &path, &kept)
}

/// Where the bytes are written. A symlink is resolved first, so the rename
/// replaces the real file and leaves the link in place.
fn destination(
    home: &Path,
    create: bool,
) -> Result<Option<(std::path::PathBuf, std::path::PathBuf)>, HelperError> {
    let link = home.join(".config/gtk-3.0/bookmarks");
    match link.symlink_metadata() {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            if !create {
                return Ok(None);
            }
            let directory = config_dir(home)?;
            Ok(Some((directory.clone(), directory.join("bookmarks"))))
        }
        Ok(meta) if meta.file_type().is_symlink() => Ok(resolved_target(home, &link)),
        Ok(meta) if meta.is_file() => {
            let directory = link
                .parent()
                .ok_or_else(|| HelperError::Failed("bookmarks path has no parent".into()))?
                .to_path_buf();
            Ok(Some((directory, link)))
        }
        Ok(_) => Err(HelperError::Failed(
            "bookmarks file is not a regular file".into(),
        )),
        Err(error) => Err(HelperError::Failed(format!(
            "cannot read bookmarks: {error}"
        ))),
    }
}

/// `None` means the link is left alone. The target must be a regular file
/// inside `home`, owned by this process.
fn resolved_target(home: &Path, link: &Path) -> Option<(std::path::PathBuf, std::path::PathBuf)> {
    let skip = |reason: &str| {
        eprintln!("linux-vault-helper: bookmark skipped: {reason}");
        None
    };
    let Some(home) = fs::canonicalize(home).ok() else {
        return skip("the home directory cannot be resolved");
    };
    let Some(target) = fs::canonicalize(link).ok() else {
        return skip("the bookmarks symlink cannot be resolved");
    };
    if target != home && !target.starts_with(&home) {
        return skip("the bookmarks symlink points outside the home");
    }
    let Ok(meta) = target.symlink_metadata() else {
        return skip("the bookmarks target cannot be read");
    };
    if !meta.is_file() {
        return skip("the bookmarks target is not a regular file");
    }
    if meta.uid() != unsafe { nix::libc::getuid() } {
        return skip("the bookmarks target is owned by someone else");
    }
    let Some(directory) = target.parent().map(std::path::Path::to_path_buf) else {
        return skip("the bookmarks target has no parent");
    };
    Some((directory, target))
}

fn config_dir(home: &Path) -> Result<std::path::PathBuf, HelperError> {
    let config = home.join(".config");
    let gtk = config.join("gtk-3.0");
    real_dir(&config)?;
    real_dir(&gtk)?;
    Ok(gtk)
}

fn real_dir(path: &Path) -> Result<(), HelperError> {
    match path.symlink_metadata() {
        Ok(meta) if meta.file_type().is_symlink() => Err(HelperError::Failed(format!(
            "{} is a symlink",
            path.display()
        ))),
        Ok(meta) if meta.is_dir() => Ok(()),
        Ok(_) => Err(HelperError::Failed(format!(
            "{} is not a directory",
            path.display()
        ))),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir(path).map_err(|error| {
                HelperError::Failed(format!("cannot create {}: {error}", path.display()))
            })
        }
        Err(error) => Err(HelperError::Failed(format!(
            "cannot read {}: {error}",
            path.display()
        ))),
    }
}

fn read_marks(path: &Path) -> Result<String, HelperError> {
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(String::new()),
        Err(error) if error.raw_os_error() == Some(nix::libc::ELOOP) => {
            return Err(HelperError::Failed("bookmarks file is a symlink".into()));
        }
        Err(error) => {
            return Err(HelperError::Failed(format!(
                "cannot read bookmarks: {error}"
            )));
        }
    };
    std::io::read_to_string(file)
        .map_err(|error| HelperError::Failed(format!("cannot read bookmarks: {error}")))
}

fn write_marks(directory: &Path, path: &Path, text: &str) -> Result<(), HelperError> {
    let temporary = directory.join("bookmarks.lve-tmp");
    {
        let mut out = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o644)
            .custom_flags(nix::libc::O_NOFOLLOW)
            .open(&temporary)
            .map_err(|error| HelperError::Failed(format!("cannot write bookmarks: {error}")))?;
        out.write_all(text.as_bytes())
            .map_err(|error| HelperError::Failed(format!("cannot write bookmarks: {error}")))?;
        out.sync_all()
            .map_err(|error| HelperError::Failed(format!("cannot write bookmarks: {error}")))?;
    }
    fs::rename(&temporary, path)
        .map_err(|error| HelperError::Failed(format!("cannot replace bookmarks: {error}")))?;
    if let Ok(dir) = fs::File::open(directory) {
        let _ = dir.sync_all();
    }
    Ok(())
}

fn vault_text(vault: &Path) -> String {
    vault.to_string_lossy().into_owned()
}

fn percent_encode(text: &str) -> String {
    let mut out = String::new();
    for byte in text.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' | b'/' => {
                out.push(byte as char);
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

fn bookmark_points_at(line: &str, vault: &Path) -> bool {
    let uri = line.split_whitespace().next().unwrap_or("");
    let Some(rest) = uri.strip_prefix("file://") else {
        return false;
    };
    if !rest.starts_with('/') {
        return false;
    }
    let Some(decoded) = percent_decode(rest) else {
        return false;
    };
    Path::new(&decoded) == vault
}

fn percent_decode(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            if index + 2 >= bytes.len() {
                return None;
            }
            let hex = std::str::from_utf8(&bytes[index + 1..index + 3]).ok()?;
            out.push(u8::from_str_radix(hex, 16).ok()?);
            index += 3;
        } else {
            out.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(out).ok()
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    #[test]
    fn the_vault_line_goes_and_the_other_line_stays() {
        let root = std::env::temp_dir().join(format!("lve-bookmarks-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join(".config/gtk-3.0")).unwrap();
        let vault = root.join("Forge");
        let other = root.join("Anvil");
        fs::write(
            root.join(".config/gtk-3.0/bookmarks"),
            format!(
                "file://{}\nfile://{} Anvil\n",
                other.display(),
                vault.display()
            ),
        )
        .unwrap();
        remove(&root, &vault).unwrap();
        let text = fs::read_to_string(root.join(".config/gtk-3.0/bookmarks")).unwrap();
        assert_eq!(text, format!("file://{}\n", other.display()));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn a_percent_encoded_space_matches_the_vault() {
        let vault = PathBuf::from("/home/user/My Vault");
        assert!(bookmark_points_at("file:///home/user/My%20Vault\n", &vault));
        assert!(!bookmark_points_at(
            "file:///home/user/My%20Vault2\n",
            &vault
        ));
    }

    #[test]
    fn a_missing_file_gains_one_encoded_line_and_a_second_call_does_not_repeat_it() {
        let root = std::env::temp_dir().join(format!("lve-bookmarks-add-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join(".config/gtk-3.0")).unwrap();
        fs::write(
            root.join(".config/gtk-3.0/bookmarks"),
            "file:///keep/Other Other\n",
        )
        .unwrap();
        let vault = root.join("My Vault");
        ensure(&root, &vault, "My Vault").unwrap();
        ensure(&root, &vault, "My Vault").unwrap();
        let text = fs::read_to_string(root.join(".config/gtk-3.0/bookmarks")).unwrap();
        let expected = format!(
            "file:///keep/Other Other\nfile://{} My Vault\n",
            vault.display().to_string().replace(' ', "%20")
        );
        assert_eq!(text, expected, "{text}");
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn a_symlink_inside_the_home_is_updated_without_replacing_the_link() {
        let root = std::env::temp_dir().join(format!("lve-bookmarks-link-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let real_dir = root.join("dotfiles");
        fs::create_dir_all(&real_dir).unwrap();
        let real = real_dir.join("bookmarks");
        fs::write(&real, "file:///keep/Other Other\n").unwrap();
        fs::create_dir_all(root.join(".config/gtk-3.0")).unwrap();
        std::os::unix::fs::symlink(&real, root.join(".config/gtk-3.0/bookmarks")).unwrap();
        let vault = root.join("Forge");
        ensure(&root, &vault, "Forge").unwrap();
        assert!(root
            .join(".config/gtk-3.0/bookmarks")
            .symlink_metadata()
            .unwrap()
            .file_type()
            .is_symlink());
        let text = fs::read_to_string(&real).unwrap();
        assert!(text.starts_with("file:///keep/Other Other\n"), "{text}");
        assert!(text.contains("Forge"), "{text}");
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn a_symlink_outside_the_home_is_left_alone() {
        let root = std::env::temp_dir().join(format!("lve-bookmarks-out-{}", std::process::id()));
        let outside =
            std::env::temp_dir().join(format!("lve-bookmarks-far-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let _ = fs::remove_dir_all(&outside);
        fs::create_dir_all(&outside).unwrap();
        let real = outside.join("bookmarks");
        fs::write(&real, "file:///keep/Other Other\n").unwrap();
        fs::create_dir_all(root.join(".config/gtk-3.0")).unwrap();
        std::os::unix::fs::symlink(&real, root.join(".config/gtk-3.0/bookmarks")).unwrap();
        ensure(&root, &root.join("Forge"), "Forge").unwrap();
        assert_eq!(
            fs::read_to_string(&real).unwrap(),
            "file:///keep/Other Other\n"
        );
        assert!(root
            .join(".config/gtk-3.0/bookmarks")
            .symlink_metadata()
            .unwrap()
            .file_type()
            .is_symlink());
        let _ = fs::remove_dir_all(&root);
        let _ = fs::remove_dir_all(&outside);
    }
}
