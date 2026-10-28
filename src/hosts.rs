// The capture's line in /etc/hosts (the Linux stand-in for
// %SystemDirectory%\drivers\etc\hosts) and the DNS cache flush that follows.

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::log::Logger;

pub const MARKER: &str = "# HellForge-CaptureProxy";

fn mapping(host: &str) -> String {
    format!("127.0.0.1 {host}")
}

/// Appends a marker line and the loopback mapping. A marker that joined the player's last line
/// would later take that line away with it, so the file gets a newline first when it needs one.
pub fn add(path: &Path, host: &str) -> io::Result<()> {
    let needs_newline = match fs::metadata(path) {
        Ok(metadata) if metadata.len() > 0 => {
            let bytes = fs::read(path)?;
            bytes.last() != Some(&b'\n')
        }
        _ => false,
    };
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    if needs_newline {
        file.write_all(b"\n")?;
    }
    file.write_all(format!("{MARKER}\n{}\n", mapping(host)).as_bytes())?;
    Ok(())
}

/// Removes every line holding the marker and any exact loopback mapping for the host.
/// Returns whether anything was removed.
pub fn remove(path: &Path, host: &str) -> io::Result<bool> {
    if !path.exists() {
        return Ok(false);
    }
    let text = fs::read_to_string(path)?;
    let expected = mapping(host);
    let mut kept = String::with_capacity(text.len());
    let mut removed = false;
    for line in text.split_inclusive('\n') {
        let bare = line.trim_end_matches(['\r', '\n']);
        let is_marker = bare
            .to_ascii_lowercase()
            .contains(&MARKER.to_ascii_lowercase());
        let is_mapping = bare.trim().eq_ignore_ascii_case(&expected);
        if is_marker || is_mapping {
            removed = true;
        } else {
            kept.push_str(line);
        }
    }
    if !removed {
        return Ok(false);
    }
    // In place rather than rename: /etc/hosts is a bind mount in containers and some sandboxes.
    fs::write(path, kept)?;
    Ok(true)
}

/// systemd-resolved, the older systemd-resolve, and nscd cache lookups. Best effort only.
pub fn flush_dns() {
    let commands: &[(&str, &[&str])] = &[
        ("resolvectl", &["flush-caches"]),
        ("systemd-resolve", &["--flush-caches"]),
        ("nscd", &["-i", "hosts"]),
    ];
    for (program, arguments) in commands {
        let started = Command::new(program)
            .args(*arguments)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        if matches!(started, Ok(status) if status.success()) {
            return;
        }
    }
}

/// Runs a hosts step and logs its failure without aborting the caller's other steps.
pub fn step_add(log: &Logger, path: &Path, host: &str) -> bool {
    match add(path, host) {
        Ok(()) => {
            flush_dns();
            true
        }
        Err(error) => {
            log.line(format!("hosts add failed: {error}"));
            false
        }
    }
}

pub fn step_remove(log: &Logger, path: &Path, host: &str) -> bool {
    match remove(path, host) {
        Ok(true) => {
            flush_dns();
            log.line("hosts line removed");
            true
        }
        Ok(false) => true,
        Err(error) => {
            log.line(format!("hosts cleanup failed: {error}"));
            false
        }
    }
}

pub fn default_path() -> PathBuf {
    PathBuf::from("/etc/hosts")
}
