//! Nautilus bookmarks, `~/.config/gtk-3.0/bookmarks`.
//!
//! One `file://` URI per line. Terminate removes the vault's line. Remove
//! leaves the file alone. A symlink is not followed.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use crate::error::HelperError;

/// Remove the bookmark that points at `vault`.
///
/// The home directory is the nearest ancestor of `vault` that contains
/// `.config/gtk-3.0/bookmarks`. The password database is the wrong place to
/// look: a test vault does not live under that home. No such file is success.
pub fn remove_along(vault: &Path) -> Result<(), HelperError> {
    let Some(home) = ancestor_with_bookmarks(vault) else {
        return Ok(());
    };
    remove_vault(&home, vault)
}

fn ancestor_with_bookmarks(vault: &Path) -> Option<std::path::PathBuf> {
    let mut dir = vault.parent()?;
    loop {
        let marks = dir.join(".config/gtk-3.0/bookmarks");
        match marks.symlink_metadata() {
            Ok(meta) if meta.file_type().is_symlink() || meta.is_file() => {
                return Some(dir.to_path_buf());
            }
            _ => {}
        }
        dir = dir.parent()?;
    }
}

/// Remove the bookmark that points at `vault`. A missing file is success.
pub fn remove_vault(home: &Path, vault: &Path) -> Result<(), HelperError> {
    let path = home.join(".config/gtk-3.0/bookmarks");
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW)
        .open(&path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) if error.raw_os_error() == Some(nix::libc::ELOOP) => {
            return Err(HelperError::Failed("bookmarks file is a symlink".into()));
        }
        Err(error) => {
            return Err(HelperError::Failed(format!(
                "cannot read bookmarks: {error}"
            )));
        }
    };
    let text = std::io::read_to_string(file)
        .map_err(|error| HelperError::Failed(format!("cannot read bookmarks: {error}")))?;
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
    let directory = path
        .parent()
        .ok_or_else(|| HelperError::Failed("bookmarks path has no parent".into()))?;
    let temporary = directory.join("bookmarks.lve-tmp");
    {
        let mut out = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .custom_flags(nix::libc::O_NOFOLLOW)
            .open(&temporary)
            .map_err(|error| HelperError::Failed(format!("cannot write bookmarks: {error}")))?;
        out.write_all(kept.as_bytes())
            .map_err(|error| HelperError::Failed(format!("cannot write bookmarks: {error}")))?;
        out.sync_all()
            .map_err(|error| HelperError::Failed(format!("cannot write bookmarks: {error}")))?;
    }
    fs::rename(&temporary, &path)
        .map_err(|error| HelperError::Failed(format!("cannot replace bookmarks: {error}")))?;
    Ok(())
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
        remove_vault(&root, &vault).unwrap();
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
}
