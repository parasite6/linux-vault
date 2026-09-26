//! Round-trip 7-Zip's stdin passphrase.
//!
//! Creates a header-encrypted, uncompressed archive (`-mhe=on -mx=0`) and
//! opens it with `-p<passphrase>` and no stdin. That is the "typed normally"
//! side: the passphrase is the switch post-string, not another pipe.
//!
//! `-p-` is the invocation in the design. Bare `-p` (empty post-string) is the
//! form that asks 7-Zip to read a passphrase. This spike measures both.

use std::fs;
use std::io::{Read, Write};
use std::os::unix::ffi::OsStringExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const FILE_NAME: &str = "marker-file.txt";
const PAYLOAD: &[u8] = b"linux-vault-round-trip\n";
const TIMEOUT: Duration = Duration::from_secs(5);
const LANG_UTF8: &str = "en_US.UTF-8";
const LANG_C: &str = "C";

fn main() {
    let bin = locate_7z();
    let version = version_line(&bin);
    println!("binary: {}", bin.display());
    println!("version: {version}");
    println!("timeout: {}s", TIMEOUT.as_secs());
    println!();

    let mut results = Vec::new();

    println!("# design invocation: -p-");
    for case in hyphen_cases() {
        results.push(run_case(&bin, case));
    }

    println!("# bare -p pipe edges (always)");
    for case in bare_pipe_edges() {
        results.push(run_case(&bin, case));
    }

    let hyphen_reads_stdin = results
        .iter()
        .find(|r| r.name == "hyphen secret nl")
        .and_then(|r| r.round_trip)
        == Some(true);

    let locale_switch = if hyphen_reads_stdin {
        Switch::Hyphen
    } else {
        println!("# bare -p with passphrase\\n (workaround matrix)");
        for case in bare_newline_cases() {
            results.push(run_case(&bin, case));
        }
        Switch::Bare
    };

    println!("# non-ASCII locale pairs");
    let mut locale_names = Vec::new();
    for case in locale_cases(locale_switch) {
        locale_names.push(case.name);
        results.push(run_case(&bin, case));
    }

    let failed_crosses: Vec<&str> = locale_names
        .iter()
        .copied()
        .filter(|name| name.contains("cross"))
        .filter(|name| {
            results
                .iter()
                .find(|r| r.name == *name)
                .and_then(|r| r.round_trip)
                != Some(true)
        })
        .collect();

    if !failed_crosses.is_empty() {
        println!("# failed crosses retried with -sccUTF-8 on both sides");
        for name in failed_crosses {
            let case = locale_cases(locale_switch)
                .into_iter()
                .find(|c| c.name == name)
                .expect("cross case")
                .with_scc();
            results.push(run_case(&bin, case));
        }
    }

    print_facts(&results, hyphen_reads_stdin, locale_switch);
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Switch {
    /// `-p-`: post-string is the character `-`.
    Hyphen,
    /// `-p`: empty post-string, so 7-Zip prompts and reads stdin.
    Bare,
}

enum Feed {
    Bytes(Vec<u8>),
    /// Piped stdin, nothing written, then the write end is closed.
    EmptyPipe,
    /// Descriptor 0 is closed before exec.
    ClosedFd,
}

struct Probe {
    label: &'static str,
    password: Vec<u8>,
}

enum Goal {
    RoundTrip(Vec<u8>),
    /// Create must fail and must not leave an archive that opens with an empty passphrase.
    RejectEmpty,
}

struct Case {
    name: &'static str,
    switch: Switch,
    feed: Feed,
    goal: Goal,
    lang_create: &'static str,
    lang_open: &'static str,
    scc_utf8: bool,
    probes: Vec<Probe>,
}

impl Case {
    fn with_scc(mut self) -> Self {
        self.name = match self.name {
            "locale cross C to utf8" => "locale cross C to utf8 scc",
            "locale cross utf8 to C" => "locale cross utf8 to C scc",
            other => panic!("no scc name for {other}"),
        };
        self.scc_utf8 = true;
        self
    }
}

fn hyphen_cases() -> Vec<Case> {
    vec![
        secret_case(
            "hyphen secret nl",
            Switch::Hyphen,
            b"secret\n",
            b"secret",
            vec![probe("literal hyphen", b"-")],
        ),
        secret_case(
            "hyphen secret eof",
            Switch::Hyphen,
            b"secret",
            b"secret",
            vec![probe("literal hyphen", b"-")],
        ),
        secret_case(
            "hyphen secret crlf",
            Switch::Hyphen,
            b"secret\r\n",
            b"secret",
            vec![probe("CR kept", b"secret\r"), probe("literal hyphen", b"-")],
        ),
        secret_case(
            "hyphen passphrase hyphen",
            Switch::Hyphen,
            b"-\n",
            b"-",
            Vec::new(),
        ),
        secret_case(
            "hyphen metachar",
            Switch::Hyphen,
            b"pa ss'word$\n",
            b"pa ss'word$",
            vec![probe("literal hyphen", b"-")],
        ),
        secret_case(
            "hyphen spaces",
            Switch::Hyphen,
            b" secret \n",
            b" secret ",
            vec![probe("trimmed", b"secret"), probe("literal hyphen", b"-")],
        ),
        secret_case(
            "hyphen nonascii",
            Switch::Hyphen,
            &nl("sécret"),
            "sécret".as_bytes(),
            vec![probe("literal hyphen", b"-")],
        ),
    ]
}

fn bare_pipe_edges() -> Vec<Case> {
    vec![
        secret_case(
            "bare secret eof",
            Switch::Bare,
            b"secret",
            b"secret",
            Vec::new(),
        ),
        Case {
            name: "bare empty pipe",
            switch: Switch::Bare,
            feed: Feed::EmptyPipe,
            goal: Goal::RejectEmpty,
            lang_create: LANG_UTF8,
            lang_open: LANG_UTF8,
            scc_utf8: false,
            probes: Vec::new(),
        },
        Case {
            name: "bare closed fd",
            switch: Switch::Bare,
            feed: Feed::ClosedFd,
            goal: Goal::RejectEmpty,
            lang_create: LANG_UTF8,
            lang_open: LANG_UTF8,
            scc_utf8: false,
            probes: Vec::new(),
        },
    ]
}

fn bare_newline_cases() -> Vec<Case> {
    vec![
        secret_case(
            "bare secret nl",
            Switch::Bare,
            b"secret\n",
            b"secret",
            Vec::new(),
        ),
        secret_case(
            "bare secret crlf",
            Switch::Bare,
            b"secret\r\n",
            b"secret",
            vec![probe("CR kept", b"secret\r")],
        ),
        secret_case(
            "bare passphrase hyphen",
            Switch::Bare,
            b"-\n",
            b"-",
            Vec::new(),
        ),
        secret_case(
            "bare metachar",
            Switch::Bare,
            b"pa ss'word$\n",
            b"pa ss'word$",
            Vec::new(),
        ),
        secret_case(
            "bare spaces",
            Switch::Bare,
            b" secret \n",
            b" secret ",
            vec![probe("trimmed", b"secret")],
        ),
        secret_case(
            "bare nonascii",
            Switch::Bare,
            &nl("sécret"),
            "sécret".as_bytes(),
            Vec::new(),
        ),
    ]
}

fn locale_cases(switch: Switch) -> Vec<Case> {
    let stdin = nl("sécret");
    let intended = "sécret".as_bytes();
    vec![
        locale_case("locale C C", switch, &stdin, intended, LANG_C, LANG_C),
        locale_case(
            "locale utf8 utf8",
            switch,
            &stdin,
            intended,
            LANG_UTF8,
            LANG_UTF8,
        ),
        locale_case(
            "locale cross C to utf8",
            switch,
            &stdin,
            intended,
            LANG_C,
            LANG_UTF8,
        ),
        locale_case(
            "locale cross utf8 to C",
            switch,
            &stdin,
            intended,
            LANG_UTF8,
            LANG_C,
        ),
    ]
}

fn locale_case(
    name: &'static str,
    switch: Switch,
    stdin: &[u8],
    intended: &[u8],
    lang_create: &'static str,
    lang_open: &'static str,
) -> Case {
    let mut case = secret_case(name, switch, stdin, intended, Vec::new());
    case.lang_create = lang_create;
    case.lang_open = lang_open;
    case
}

fn secret_case(
    name: &'static str,
    switch: Switch,
    stdin: &[u8],
    intended: &[u8],
    probes: Vec<Probe>,
) -> Case {
    Case {
        name,
        switch,
        feed: Feed::Bytes(stdin.to_vec()),
        goal: Goal::RoundTrip(intended.to_vec()),
        lang_create: LANG_UTF8,
        lang_open: LANG_UTF8,
        scc_utf8: false,
        probes,
    }
}

fn probe(label: &'static str, password: &[u8]) -> Probe {
    Probe {
        label,
        password: password.to_vec(),
    }
}

fn nl(text: &str) -> Vec<u8> {
    let mut bytes = text.as_bytes().to_vec();
    bytes.push(b'\n');
    bytes
}

struct Outcome {
    name: &'static str,
    create_exit: String,
    timed_out: bool,
    archive_bytes: Option<u64>,
    intended_test: Option<bool>,
    intended_extract: Option<bool>,
    round_trip: Option<bool>,
    clean_failure: Option<bool>,
    wrong_fails: Option<bool>,
    list_hides: Option<bool>,
    empty_opens: Option<bool>,
    probes: Vec<(&'static str, bool)>,
    detail: String,
}

fn run_case(bin: &Path, case: Case) -> Outcome {
    println!("-- {}", case.name);
    println!(
        "   switch={} create_lang={} open_lang={} scc={}",
        switch_label(case.switch),
        case.lang_create,
        case.lang_open,
        case.scc_utf8
    );
    println!("   stdin={}", feed_label(&case.feed));

    let work = WorkDir::new(case.name);
    let archive = work.path.join("archive.7z");
    let created = run_7z(
        bin,
        &create_args(case.switch, case.scc_utf8, &archive),
        &work.path,
        case.lang_create,
        &case.feed,
    );

    let archive_bytes = fs::metadata(&archive)
        .ok()
        .map(|m| m.len())
        .filter(|_| archive.is_file());
    let create_exit = status_label(&created);
    println!(
        "   create {create_exit} archive={}",
        archive_label(archive_bytes)
    );

    let detail = interesting(&created.stdout, &created.stderr);
    if !detail.is_empty() {
        println!("   create output: {detail}");
    }

    let mut outcome = Outcome {
        name: case.name,
        create_exit,
        timed_out: created.timed_out,
        archive_bytes,
        intended_test: None,
        intended_extract: None,
        round_trip: None,
        clean_failure: None,
        wrong_fails: None,
        list_hides: None,
        empty_opens: None,
        probes: Vec::new(),
        detail,
    };

    if created.timed_out {
        match case.goal {
            Goal::RejectEmpty => {
                outcome.clean_failure = Some(false);
                println!("   clean failure: no (hung)");
            }
            Goal::RoundTrip(_) => {
                outcome.round_trip = Some(false);
                println!("   round trip: no (create hung)");
            }
        }
        println!();
        return outcome;
    }

    match case.goal {
        Goal::RejectEmpty => finish_reject(bin, &case, &work, &archive, &mut outcome),
        Goal::RoundTrip(ref intended) => {
            finish_round_trip(bin, &case, &work, &archive, intended, &mut outcome)
        }
    }
    println!();
    outcome
}

fn finish_reject(bin: &Path, case: &Case, work: &WorkDir, archive: &Path, outcome: &mut Outcome) {
    if archive.is_file() {
        let opened = password_test(bin, work, archive, case, &Feed::Bytes(b"\n".to_vec()));
        outcome.empty_opens = Some(opened.ok && !opened.timed_out);
        println!(
            "   empty-password open: {}",
            yes_no(outcome.empty_opens.unwrap())
        );
    } else {
        println!("   empty-password open: n/a");
    }

    let failed = matches!(outcome.create_exit.parse::<i32>(), Ok(code) if code != 0);
    let clean = failed && outcome.empty_opens != Some(true);
    outcome.clean_failure = Some(clean);
    println!("   clean failure: {}", yes_no(clean));
}

fn finish_round_trip(
    bin: &Path,
    case: &Case,
    work: &WorkDir,
    archive: &Path,
    intended: &[u8],
    outcome: &mut Outcome,
) {
    if !archive.is_file() {
        outcome.round_trip = Some(false);
        println!("   round trip: no (no archive)");
        return;
    }

    // The passphrase is the `-p` post-string. Stdin is an empty pipe, so a
    // surprise prompt cannot hang and cannot supply the passphrase.
    let tested = open_with_password(bin, work, archive, case, intended, OpenKind::Test);
    let extracted = open_with_password(bin, work, archive, case, intended, OpenKind::Extract);
    outcome.intended_test = Some(tested);
    outcome.intended_extract = Some(extracted);
    println!(
        "   intended {}: test={} extract={}",
        escape(intended),
        yes_no(tested),
        yes_no(extracted)
    );

    for probe in &case.probes {
        let ok = open_with_password(bin, work, archive, case, &probe.password, OpenKind::Test);
        outcome.probes.push((probe.label, ok));
        println!("   probe {}: {}", probe.label, yes_no(ok));
    }

    let wrong = !open_with_password(
        bin,
        work,
        archive,
        case,
        b"definitely-wrong",
        OpenKind::Test,
    );
    outcome.wrong_fails = Some(wrong);
    println!("   wrong password fails: {}", yes_no(wrong));

    let hides = list_hides_name(bin, work, archive, case);
    outcome.list_hides = Some(hides);
    println!("   list hides name: {}", yes_no(hides));

    let round_trip = tested && extracted;
    outcome.round_trip = Some(round_trip);
    println!("   round trip: {}", yes_no(round_trip));
}

enum OpenKind {
    Test,
    Extract,
}

fn open_with_password(
    bin: &Path,
    work: &WorkDir,
    archive: &Path,
    case: &Case,
    password: &[u8],
    kind: OpenKind,
) -> bool {
    let mut args = Vec::new();
    match kind {
        OpenKind::Test => args.push(os("t")),
        OpenKind::Extract => {
            let _ = fs::remove_dir_all(work.path.join("out"));
            args.push(os("x"));
        }
    }
    args.push(password_arg(password));
    args.push(os("-y"));
    args.push(os("-bd"));
    if case.scc_utf8 {
        args.push(os("-sccUTF-8"));
    }
    if matches!(kind, OpenKind::Extract) {
        args.push(os("-oout"));
    }
    args.push(archive.as_os_str().to_os_string());

    let ran = run_7z(bin, &args, &work.path, case.lang_open, &Feed::EmptyPipe);
    if ran.timed_out || ran.code != Some(0) {
        return false;
    }
    match kind {
        OpenKind::Test => true,
        OpenKind::Extract => extracted_payload(&work.path.join("out")).as_deref() == Some(PAYLOAD),
    }
}

fn extracted_payload(dir: &Path) -> Option<Vec<u8>> {
    let mut stack = vec![dir.to_path_buf()];
    while let Some(current) = stack.pop() {
        let Ok(entries) = fs::read_dir(&current) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.file_name().is_some_and(|name| name == FILE_NAME) {
                return fs::read(path).ok();
            }
        }
    }
    None
}

fn list_hides_name(bin: &Path, work: &WorkDir, archive: &Path, case: &Case) -> bool {
    let mut args = vec![os("l"), os("-bd")];
    if case.scc_utf8 {
        args.push(os("-sccUTF-8"));
    }
    args.push(archive.as_os_str().to_os_string());
    let ran = run_7z(bin, &args, &work.path, case.lang_open, &Feed::EmptyPipe);
    if ran.timed_out {
        return false;
    }
    let combined = format!("{}{}", ran.stdout, ran.stderr);
    !combined.contains(FILE_NAME)
}

struct Ran {
    code: Option<i32>,
    timed_out: bool,
    stdout: String,
    stderr: String,
}

fn password_test(bin: &Path, work: &WorkDir, archive: &Path, case: &Case, feed: &Feed) -> RanOk {
    let mut args = vec![os("t"), os("-p"), os("-y"), os("-bd")];
    if case.scc_utf8 {
        args.push(os("-sccUTF-8"));
    }
    args.push(archive.as_os_str().to_os_string());
    let ran = run_7z(bin, &args, &work.path, case.lang_open, feed);
    RanOk {
        ok: ran.code == Some(0),
        timed_out: ran.timed_out,
    }
}

struct RanOk {
    ok: bool,
    timed_out: bool,
}

fn create_args(switch: Switch, scc_utf8: bool, archive: &Path) -> Vec<std::ffi::OsString> {
    let mut args = vec![os("a")];
    args.push(match switch {
        Switch::Hyphen => os("-p-"),
        Switch::Bare => os("-p"),
    });
    for flag in ["-mhe=on", "-mx=0", "-y", "-bd"] {
        args.push(os(flag));
    }
    if scc_utf8 {
        args.push(os("-sccUTF-8"));
    }
    args.push(archive.file_name().unwrap().to_os_string());
    args.push(os(FILE_NAME));
    args
}

fn run_7z(bin: &Path, args: &[std::ffi::OsString], dir: &Path, lang: &str, feed: &Feed) -> Ran {
    let mut cmd = Command::new(bin);
    cmd.current_dir(dir)
        .env("LANG", lang)
        .env("LC_ALL", lang)
        .env("LC_CTYPE", lang)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    match feed {
        Feed::ClosedFd => {
            cmd.stdin(Stdio::null());
            unsafe {
                cmd.pre_exec(|| {
                    close_fd(0);
                    Ok(())
                });
            }
        }
        Feed::EmptyPipe | Feed::Bytes(_) => {
            cmd.stdin(Stdio::piped());
        }
    }

    let mut child = match cmd.spawn() {
        Ok(child) => child,
        Err(error) => {
            return Ran {
                code: None,
                timed_out: false,
                stdout: String::new(),
                stderr: format!("spawn error: {error}"),
            };
        }
    };

    let mut stdout = child.stdout.take();
    let mut stderr = child.stderr.take();
    let stdout_thread = thread::spawn(move || read_pipe(&mut stdout));
    let stderr_thread = thread::spawn(move || read_pipe(&mut stderr));

    if let Feed::Bytes(bytes) = feed {
        if let Some(mut stdin) = child.stdin.take() {
            let _ = stdin.write_all(bytes);
        }
    } else {
        // Drop the write end so the child sees EOF. ClosedFd has no pipe.
        drop(child.stdin.take());
    }

    let started = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) if started.elapsed() >= TIMEOUT => {
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
            Ok(None) => thread::sleep(Duration::from_millis(20)),
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Ran {
                    code: None,
                    timed_out: false,
                    stdout: String::new(),
                    stderr: format!("wait error: {error}"),
                };
            }
        }
    };

    Ran {
        code: status.as_ref().and_then(ExitStatus::code),
        timed_out: status.is_none(),
        stdout: stdout_thread.join().unwrap_or_default(),
        stderr: stderr_thread.join().unwrap_or_default(),
    }
}

fn read_pipe(pipe: &mut Option<impl Read>) -> String {
    let mut bytes = Vec::new();
    if let Some(pipe) = pipe.as_mut() {
        let _ = pipe.read_to_end(&mut bytes);
    }
    String::from_utf8_lossy(&bytes).into_owned()
}

unsafe fn close_fd(fd: i32) {
    unsafe {
        extern "C" {
            fn close(fd: i32) -> i32;
        }
        close(fd);
    }
}

fn password_arg(password: &[u8]) -> std::ffi::OsString {
    let mut bytes = b"-p".to_vec();
    bytes.extend_from_slice(password);
    std::ffi::OsString::from_vec(bytes)
}

fn os(text: &str) -> std::ffi::OsString {
    std::ffi::OsString::from(text)
}

struct WorkDir {
    path: PathBuf,
}

impl WorkDir {
    fn new(name: &str) -> Self {
        let slug: String = name
            .chars()
            .map(|ch| if ch.is_ascii_alphanumeric() { ch } else { '-' })
            .collect();
        let path = std::env::temp_dir().join(format!("lve-7z-stdin-{}-{slug}", std::process::id()));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).unwrap_or_else(|error| {
            panic!("create {}: {error}", path.display());
        });
        fs::write(path.join(FILE_NAME), PAYLOAD).expect("write payload");
        Self { path }
    }
}

impl Drop for WorkDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn locate_7z() -> PathBuf {
    if let Some(path) = search_path("7zz") {
        return path;
    }
    let fallback = PathBuf::from("/usr/bin/7z");
    if fallback.is_file() {
        return fallback;
    }
    if let Some(path) = search_path("7z") {
        return path;
    }
    eprintln!("neither 7zz nor 7z is on PATH");
    std::process::exit(1);
}

fn search_path(name: &str) -> Option<PathBuf> {
    let paths = std::env::var_os("PATH")?;
    std::env::split_paths(&paths)
        .map(|dir| dir.join(name))
        .find(|path| path.is_file())
}

fn version_line(path: &Path) -> String {
    let Ok(output) = Command::new(path).output() else {
        return "failed to execute".to_string();
    };
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    stdout
        .lines()
        .chain(stderr.lines())
        .find(|line| !line.trim().is_empty())
        .unwrap_or("")
        .trim()
        .to_string()
}

fn status_label(ran: &Ran) -> String {
    if ran.timed_out {
        "timeout".to_string()
    } else if let Some(code) = ran.code {
        code.to_string()
    } else if !ran.stderr.is_empty() {
        ran.stderr.lines().next().unwrap_or("error").to_string()
    } else {
        "no-status".to_string()
    }
}

fn archive_label(bytes: Option<u64>) -> String {
    match bytes {
        Some(bytes) => format!("yes ({bytes} bytes)"),
        None => "no".to_string(),
    }
}

fn switch_label(switch: Switch) -> &'static str {
    match switch {
        Switch::Hyphen => "-p-",
        Switch::Bare => "-p",
    }
}

fn feed_label(feed: &Feed) -> String {
    match feed {
        Feed::Bytes(bytes) => escape(bytes),
        Feed::EmptyPipe => "empty pipe".to_string(),
        Feed::ClosedFd => "closed fd".to_string(),
    }
}

fn interesting(stdout: &str, stderr: &str) -> String {
    stdout
        .lines()
        .chain(stderr.lines())
        .filter(|line| {
            let lower = line.to_ascii_lowercase();
            lower.contains("password") || lower.contains("error") || lower.contains("wrong")
        })
        .take(4)
        .collect::<Vec<_>>()
        .join(" | ")
}

fn escape(bytes: &[u8]) -> String {
    let mut out = String::new();
    for &byte in bytes {
        match byte {
            b'\n' => out.push_str("\\n"),
            b'\r' => out.push_str("\\r"),
            b'\t' => out.push_str("\\t"),
            b'\\' => out.push_str("\\\\"),
            0x20..=0x7e => out.push(byte as char),
            _ => out.push_str(&format!("\\x{byte:02x}")),
        }
    }
    out
}

fn yes_no(value: bool) -> &'static str {
    if value {
        "yes"
    } else {
        "no"
    }
}

fn print_facts(results: &[Outcome], hyphen_reads_stdin: bool, locale_switch: Switch) {
    println!("# facts");
    println!(
        "p-minus reads stdin (secret+newline round trip): {}",
        yes_no(hyphen_reads_stdin)
    );
    if let Some(primary) = find(results, "hyphen secret nl") {
        println!(
            "p-minus secret archive opens with literal '-': {}",
            probe_yn(primary, "literal hyphen")
        );
    }
    print_named(results, "bare secret eof", "bare -p secret then EOF");
    print_named(
        results,
        "bare empty pipe",
        "bare -p empty pipe clean failure",
    );
    print_named(results, "bare closed fd", "bare -p closed fd clean failure");

    if !hyphen_reads_stdin {
        print_named(
            results,
            "bare secret nl",
            "bare -p secret+newline round trip",
        );
        print_named(
            results,
            "bare secret crlf",
            "bare -p CR LF round trip as typed secret",
        );
        if let Some(crlf) = find(results, "bare secret crlf") {
            println!("bare -p CR kept probe: {}", probe_yn(crlf, "CR kept"));
        }
        print_named(
            results,
            "bare passphrase hyphen",
            "bare -p passphrase '-' round trip",
        );
        print_named(results, "bare metachar", "bare -p metachar round trip");
        print_named(results, "bare spaces", "bare -p spaces round trip");
        if let Some(spaces) = find(results, "bare spaces") {
            println!(
                "bare -p spaces trimmed probe: {}",
                probe_yn(spaces, "trimmed")
            );
        }
    } else {
        print_named(results, "hyphen spaces", "-p- spaces round trip");
        if let Some(spaces) = find(results, "hyphen spaces") {
            println!("-p- spaces trimmed probe: {}", probe_yn(spaces, "trimmed"));
        }
        print_named(
            results,
            "hyphen secret crlf",
            "-p- CR LF round trip as typed secret",
        );
        if let Some(crlf) = find(results, "hyphen secret crlf") {
            println!("-p- CR kept probe: {}", probe_yn(crlf, "CR kept"));
        }
        print_named(results, "hyphen secret eof", "-p- secret then EOF");
    }

    println!("locale switch: {}", switch_label(locale_switch));
    for name in [
        "locale C C",
        "locale utf8 utf8",
        "locale cross C to utf8",
        "locale cross utf8 to C",
        "locale cross C to utf8 scc",
        "locale cross utf8 to C scc",
    ] {
        if find(results, name).is_some() {
            print_named(results, name, name);
        }
    }
}

fn print_named(results: &[Outcome], name: &str, label: &str) {
    let Some(outcome) = find(results, name) else {
        println!("{label}: not run");
        return;
    };
    let verdict = outcome
        .round_trip
        .or(outcome.clean_failure)
        .map(yes_no)
        .unwrap_or("n/a");
    let archive = match outcome.archive_bytes {
        Some(bytes) => format!(" archive={bytes}b"),
        None => String::new(),
    };
    let note = if outcome.timed_out {
        " (hung)".to_string()
    } else if verdict == "no" && !outcome.detail.is_empty() {
        format!(" ({})", outcome.detail)
    } else {
        String::new()
    };
    println!("{label}: {verdict}{archive}{note}");
}

fn probe_yn(outcome: &Outcome, label: &str) -> &'static str {
    match outcome.probes.iter().find(|(name, _)| *name == label) {
        Some((_, true)) => "opens",
        Some((_, false)) => "does not open",
        None => "n/a",
    }
}

fn find<'a>(results: &'a [Outcome], name: &str) -> Option<&'a Outcome> {
    results.iter().find(|result| result.name == name)
}
