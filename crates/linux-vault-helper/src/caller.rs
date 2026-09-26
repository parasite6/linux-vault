//! Who called a method, from credentials the kernel recorded at connect time.

use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd};

use zbus::fdo::ConnectionCredentials;
use zbus::message::Header;
use zbus::names::{BusName, OwnedUniqueName};
use zbus::{fdo, Connection};

use crate::error::HelperError;

/// Identity of one method call.
///
/// `uid` and `pid` come from the bus (`GetConnectionCredentials`) or, on a
/// direct socket, from `SO_PEERCRED`. `pidfd` is the bus `ProcessFD`
/// (`SO_PEERPIDFD` at connect time) when the kernel and the bus provide it.
/// Otherwise it is opened from the pid and kept only when the process start
/// time does not change across that open.
pub struct Caller {
    pub uid: u32,
    pub pid: u32,
    pub pidfd: Option<OwnedFd>,
    /// Unique bus name, such as `:1.42`. Absent on a peer-to-peer connection.
    pub bus_name: Option<OwnedUniqueName>,
}

pub async fn caller_from_header(
    connection: &Connection,
    header: &Header<'_>,
) -> Result<Caller, HelperError> {
    let bus_name = match header.sender() {
        Some(name) => Some(
            OwnedUniqueName::try_from(name.as_str())
                .map_err(|_| HelperError::NotAuthorized("sender is not a unique name".into()))?,
        ),
        None => None,
    };
    caller_from_connection(connection, bus_name).await
}

pub async fn caller_from_connection(
    connection: &Connection,
    bus_name: Option<OwnedUniqueName>,
) -> Result<Caller, HelperError> {
    match &bus_name {
        Some(name) => {
            let credentials = bus_credentials(connection, name).await?;
            caller_from_credentials(&credentials, bus_name)
        }
        None => {
            let credentials = connection.peer_creds().await.map_err(|error| {
                HelperError::NotAuthorized(format!("peer credentials are unavailable: {error}"))
            })?;
            caller_from_credentials(credentials, bus_name)
        }
    }
}

fn caller_from_credentials(
    credentials: &ConnectionCredentials,
    bus_name: Option<OwnedUniqueName>,
) -> Result<Caller, HelperError> {
    let uid = credentials.unix_user_id().ok_or_else(|| {
        HelperError::NotAuthorized("caller UID is missing from peer credentials".into())
    })?;
    let pid = credentials.process_id().ok_or_else(|| {
        HelperError::NotAuthorized("caller PID is missing from peer credentials".into())
    })?;
    let pidfd = credentials
        .process_fd()
        .and_then(|fd| fd.as_fd().try_clone_to_owned().ok())
        .or_else(|| open_pidfd(pid));
    Ok(Caller {
        uid,
        pid,
        pidfd,
        bus_name,
    })
}

async fn bus_credentials(
    connection: &Connection,
    name: &OwnedUniqueName,
) -> Result<ConnectionCredentials, HelperError> {
    let bus = fdo::DBusProxy::new(connection).await.map_err(|error| {
        HelperError::NotAuthorized(format!("cannot reach the bus for credentials: {error}"))
    })?;
    let bus_name = BusName::try_from(name.as_str()).map_err(|error| {
        HelperError::NotAuthorized(format!("caller bus name is unusable: {error}"))
    })?;
    bus.get_connection_credentials(bus_name)
        .await
        .map_err(|error| {
            HelperError::NotAuthorized(format!("peer credentials were refused: {error}"))
        })
}

/// Open a pidfd for `pid` when the process stays the same across the open.
fn open_pidfd(pid: u32) -> Option<OwnedFd> {
    let before = start_time(pid)?;
    let raw = unsafe { nix::libc::syscall(nix::libc::SYS_pidfd_open, pid as nix::libc::pid_t, 0) };
    if raw < 0 {
        return None;
    }
    let fd = unsafe { OwnedFd::from_raw_fd(raw as i32) };
    set_cloexec(&fd);
    let after = start_time(pid)?;
    if before != after {
        return None;
    }
    let info = std::fs::read_to_string(format!("/proc/self/fdinfo/{}", fd.as_raw_fd())).ok()?;
    let recorded = info.lines().find_map(|line| line.strip_prefix("Pid:"))?;
    if recorded.trim() != pid.to_string() {
        return None;
    }
    Some(fd)
}

/// `starttime` from `/proc/<pid>/stat`, field 22.
///
/// The command name is the only field that can contain `)`, and it ends at
/// the last `)` on the line.
pub(crate) fn start_time(pid: u32) -> Option<u64> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let rest = stat.rsplit_once(')')?.1;
    rest.split_whitespace().nth(19)?.parse().ok()
}

fn set_cloexec(fd: &OwnedFd) {
    let flags = unsafe { nix::libc::fcntl(fd.as_raw_fd(), nix::libc::F_GETFD) };
    if flags < 0 || flags & nix::libc::FD_CLOEXEC != 0 {
        return;
    }
    unsafe {
        nix::libc::fcntl(
            fd.as_raw_fd(),
            nix::libc::F_SETFD,
            flags | nix::libc::FD_CLOEXEC,
        );
    }
}

#[cfg(test)]
mod tests {
    use std::io::{BufRead, BufReader};
    use std::os::fd::AsRawFd;
    use std::process::{Command, Stdio};

    use super::{open_pidfd, start_time};

    #[test]
    fn pidfd_is_close_on_exec() {
        let fd = open_pidfd(std::process::id()).expect("pidfd");
        let flags = unsafe { nix::libc::fcntl(fd.as_raw_fd(), nix::libc::F_GETFD) };
        assert!(flags & nix::libc::FD_CLOEXEC != 0);
    }

    #[test]
    fn start_time_survives_a_command_name_with_parentheses() {
        let mut child = Command::new("python3")
            .arg("-c")
            .arg(
                "import ctypes, os, time\n\
                 libc = ctypes.CDLL(None)\n\
                 libc.prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong]\n\
                 libc.prctl.restype = ctypes.c_int\n\
                 name = ctypes.create_string_buffer(b'a) b (c')\n\
                 if libc.prctl(15, ctypes.addressof(name), 0, 0, 0) != 0:\n\
                 \traise SystemExit('prctl failed')\n\
                 print(os.getpid(), flush=True)\n\
                 time.sleep(30)\n",
            )
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("python3");
        let mut line = String::new();
        BufReader::new(child.stdout.take().expect("stdout"))
            .read_line(&mut line)
            .expect("pid");
        let pid: u32 = line.trim().parse().expect("pid number");
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).expect("stat");
        assert!(stat.contains("a) b (c"), "{stat}");
        let expected: u64 = stat
            .rsplit_once(')')
            .expect("comm")
            .1
            .split_whitespace()
            .nth(19)
            .expect("starttime")
            .parse()
            .expect("starttime number");
        assert_eq!(start_time(pid), Some(expected));
        let _ = child.kill();
        let _ = child.wait();
    }
}
