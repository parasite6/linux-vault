<img width="1152" height="768" alt="logolve" src="https://github.com/user-attachments/assets/80716337-2109-40b0-b4c0-cd4b08018a53" />

# Linux-Vault

linux-vault locks a folder in your home. While a vault is unlocked it is an ordinary folder. Lock packs that folder into one encrypted 7z archive beside it, with filenames encrypted, and marks the archive immutable. Unlock asks for the passphrase once, clears the immutable flag, and extracts the folder again.

The command is `lve`. The passphrase is typed into pinentry, never on the command line and never on stdin. A root helper holds it in its process keyring while the vault is unlocked, and locks every open vault before shutdown.

v1 is this command and that helper. It is for regular Fedora, where home is `/home`. Silverblue and Kinoite keep home at `/var/home` and are not supported.

## Install

The package is `linux-vault`. It depends on `7zip` and `pinentry-qt`.

```bash
sudo dnf install linux-vault-0.1.4-1.fc44.x86_64.rpm
```

That installs `lve`, the helper at `/usr/libexec/linux-vault-helper`, and the systemd unit `linux-vault-helper.service`. The unit starts on the system bus as `org.linuxvault.Helper`. An upgrade does not restart the helper, so a `dnf upgrade` does not drop passphrases that are still held. The new helper takes effect at the next boot, or when you restart the service yourself. A restart locks every vault that is still unlocked.

The package also sets `kernel.yama.ptrace_scope=1`, so one process running as you cannot attach to another. A later file in `/etc/sysctl.d/` can override that.

## Platform. 
linux-vault v0.1 is built and tested only on Fedora Workstation (Fedora 44, x86_64). It depends on systemd (logind, user services), 7-Zip, and pinentry-qt, and ships as an RPM. Fedora Atomic desktops (Silverblue, Kinoite) are not supported, because home directories live under /var/home. Other distributions may work with manual setup, but they are untested and not officially unsupported.

## Use

```bash
lve create ~/Example
lve lock Example
lve unlock Example
lve ls
lve remove Example
lve terminate Example
```

`create ~/Example` registers the folder, adds a Nautilus bookmark, and asks for the passphrase twice. The folder stays plaintext until you lock it. The bookmark keeps pointing at the folder, so Nautilus shows it as missing while the vault is locked. Lock and unlock put that line back if it is missing. Terminate removes only that line.

`lock Example` packs `~/Example` into `~/Example.7z` and deletes the folder. It does not ask for the passphrase. After a crash, when the helper no longer holds the key, lock asks twice and then packs. A vault with no files, including one that contains only empty folders, is refused: `Example is empty; nothing to lock.` The vault stays as it is.

`unlock Example` asks once, extracts the archive back to `~/Example`, and deletes the archive. The helper keeps the passphrase for the next lock.

`ls` lists only your vaults. A vault can be `unlocked`, `locked`, `needs_recovery`, `locking`, or `unlocking`.

`remove Example` drops the registry entry. The vaults contents are preserved. If the vault is locked, it unlocks first, which asks for the passphrase. The folder and the bookmark stay.

`terminate Example` deletes the vault AND the vaults contents. It always asks for the passphrase. A locked vault is checked against the archive and then the archive is deleted. An unlocked vault is checked against the held key and then the folder is deleted. A vault that needs recovery cannot be terminated until you lock it.

Each vault has its own passphrase and its own name. Two people can each have a vault called Example. Neither can lock, unlock, remove, or terminate the other's. That name looks the same as a name that does not exist: `org.linuxvault.Error.NotFound`, with the text `vault not found`. `lve` exits 11. `lve ls` simply omits the other person's vaults.

Root cannot own a vault.

Add `--json` for one JSON object per line on stdout. `ls` writes a `vault` line for each vault. Lock and unlock write a status line while the state is `locking` or `unlocking`, then a `locked` or `unlocked` line. The status is that state, not a percentage. Vaults that need recovery are reported on stderr, so a parser of stdout is left alone. With `--json` that report is `{"type":"recovery_needed","vault":"Example"}`.

There is no timeout on the D-Bus calls. Lock and unlock wait while pinentry and 7z run. Ctrl-C stops `lve`. The helper finishes the operation it already accepted.

## Shutdown and recovery

While any vault is unlocked, the helper holds a logind delay inhibitor. On shutdown, and on `systemctl stop` or `systemctl restart`, it cancels open prompts, aborts an extract that is still running, puts the immutable flag back on that archive, and locks every vault that is still unlocked. If a file in a vault is still open, it warns and locks anyway. The sequence is allowed 120 seconds. Fast machines finish in seconds.

A vault that is still unlocked and whose passphrase is gone is marked `needs_recovery`. The folder is plaintext. The next `lve` run says so on stderr. Lock it and enter the passphrase twice. Until then, only disk encryption protects that folder.

A lock or unlock that dies in the middle is reconciled from the filenames. A partial archive or a staging folder is discarded. If both the folder and the archive exist, the folder is deleted and the vault is locked. If only the folder remains, the vault needs recovery.

## What the passphrase touches

The helper stores the passphrase in its process keyring, possessor-only, and only while the vault is unlocked. It is not linked into your user or session keyring. No bus method returns it. Buffers that hold it are locked in memory and wiped after use. The helper does not dump core.

7z is started as you. The passphrase is written to its stdin and the pipe is closed. It is never placed in the command line or the environment. Pinentry runs in your session through the user manager, and the passphrase comes back to the helper over that pipe.

While a vault is unlocked, anything running as you can read the files. That is what an ordinary folder means. Code running as you can also tamper with the pinentry window. linux-vault assumes nothing malicious is running as you.

Lock refuses when it can see a vault file still open. A process that cannot be inspected is skipped, so that check is best-effort. Shutdown locks even if a file is open.

The archive is AES-256 with filenames encrypted and no compression (`-mx=0`). 7z does not keep every Linux permission, xattr, or SELinux label. Deleting the plaintext folder is not secure erasure. A snapshot taken while the vault is unlocked still contains plaintext.

## Exit codes

| Code | Meaning                                                      |
| ---- | ------------------------------------------------------------ |
| 0    | success                                                      |
| 1    | other failure                                                |
| 2    | usage                                                        |
| 3    | wrong passphrase. The terminal says `Wrong password.`        |
| 4    | busy (the registry, or a vault that is locking or unlocking) |
| 5    | a file in the vault is open                                  |
| 6    | needs recovery                                               |
| 7    | not authorized                                               |
| 8    | not logged in                                                |
| 9    | not enough free space                                        |
| 10   | prompt cancelled                                             |
| 11   | vault not found                                              |
| 12   | vault is empty                                               |

Exit 11 is `org.linuxvault.Error.NotFound`. Exit 12 is `org.linuxvault.Error.Empty`, and the terminal prints `Name is empty; nothing to lock.` A missing name and another user's name are that same error. A wrong passphrase is `org.linuxvault.Error.WrongPassphrase` with the message `wrong passphrase`. The terminal prints `Wrong password.` and nothing from 7z. The helper always logs 7z's own text to the journal at debug priority, one `<7>` prefix per line, whether or not `RUST_LOG` is set. Read it with `journalctl -u linux-vault-helper -p debug`. A full disk prints `Not enough disk space.` A damaged archive prints `The archive is damaged.`

## Build

The workspace is Rust. Release binaries:

```bash
cargo build --release --locked -p linux-vault-helper -p linux-vault-lve
```

`/tmp` is RAM on Fedora. Keep Cargo's target directory on disk (`target/` in this repo, or set `CARGO_TARGET_DIR` to a directory on disk). Build the RPM with `rpmbuild` `_topdir` at `dist/rpmbuild` or `~/rpmbuild`, not under `/tmp`.

Gui coming soon

## License

GPL-3.0-only. See [LICENSE](LICENSE).

_A substantial amount of the code in this repository was generated/produced with or by AI with a human in the loop._
