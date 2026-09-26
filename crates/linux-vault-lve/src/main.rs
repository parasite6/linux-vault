//! `lve`. Connects to the helper with no method timeout.
//!
//! Ctrl-C ends this process. The helper finishes the operation it already
//! accepted.

use std::io::{self, Write};
use std::process::ExitCode;

use linux_vault_lve::{parse, write_help, write_usage, Invocation};

struct Out;

impl Write for Out {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        io::stdout().write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        io::stdout().flush()
    }
}

struct ErrOut;

impl Write for ErrOut {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        io::stderr().write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        io::stderr().flush()
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut stdout = Out;
    let mut stderr = ErrOut;
    match parse(&args) {
        Err(code) => {
            write_usage(&mut stderr);
            ExitCode::from(code)
        }
        Ok(Invocation::Help) => {
            write_help(&mut stdout);
            ExitCode::SUCCESS
        }
        Ok(Invocation::Run(request)) => {
            let code = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .expect("runtime")
                .block_on(async move {
                    match linux_vault_dbus::connect_client().await {
                        Ok(connection) => {
                            linux_vault_lve::run(&connection, &request, &mut stdout, &mut stderr)
                                .await
                        }
                        Err(error) => {
                            let _ = writeln!(stderr, "lve: cannot reach the helper: {error}");
                            linux_vault_lve::FAILURE
                        }
                    }
                });
            ExitCode::from(code)
        }
    }
}
