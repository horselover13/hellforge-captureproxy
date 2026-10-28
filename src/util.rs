// Small filesystem and process helpers shared by the rest of the proxy.
//
// Linux specifics the Windows original did not need:
//  * files are created 0600 and directories 0700, because they hold an inventory;
//  * when started through sudo, what the player is meant to keep (the capture, its log and
//    state) is handed to the invoking user, while the seal key stays root-only;
//  * time is rendered the way .NET's "O" format does, so a seal made here is byte-for-byte
//    the payload the Windows implementation signs.

use std::ffi::CString;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::Error;
use chrono::{DateTime, Local, Utc};

pub fn is_root() -> bool {
    // SAFETY: geteuid has no preconditions.
    unsafe { libc::geteuid() == 0 }
}

/// The uid/gid of the user who invoked sudo, when this process runs as root through it.
fn sudo_owner() -> Option<(u32, u32)> {
    if !is_root() {
        return None;
    }
    let uid = std::env::var("SUDO_UID").ok()?.parse().ok()?;
    let gid = std::env::var("SUDO_GID")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(uid);
    Some((uid, gid))
}

/// Hand a file this run created to the user behind sudo. Failure is never fatal: the file is
/// still readable by root and the capture itself does not depend on it.
pub fn give_to_sudo_user(path: &Path) {
    let Some((uid, gid)) = sudo_owner() else {
        return;
    };
    let Ok(c_path) = CString::new(path.as_os_str().as_bytes()) else {
        return;
    };
    // SAFETY: c_path is a valid NUL-terminated string for the duration of the call.
    unsafe {
        libc::chown(c_path.as_ptr(), uid, gid);
    }
}

pub fn set_mode(path: &Path, mode: u32) {
    if let Ok(metadata) = fs::metadata(path) {
        let mut permissions = metadata.permissions();
        permissions.set_mode(mode);
        let _ = fs::set_permissions(path, permissions);
    }
}

/// Creates the sync folder private to this run.
pub fn ensure_private_dir(path: &Path) -> io::Result<()> {
    fs::create_dir_all(path)?;
    set_mode(path, 0o700);
    give_to_sudo_user(path);
    Ok(())
}

fn temp_name(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(".tmp");
    PathBuf::from(name)
}

fn write_bytes(path: &Path, bytes: &[u8], chown: bool) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let temp = temp_name(path);
    {
        let mut file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o600)
            .open(&temp)?;
        file.write_all(bytes)?;
    }
    fs::rename(&temp, path)?;
    if chown {
        give_to_sudo_user(path);
    }
    Ok(())
}

/// Writes beside the destination and renames, so a reader never sees half a file.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    write_bytes(path, bytes, true)
}

/// The seal key belongs to root, not to the invoking user.
pub fn write_atomic_root(path: &Path, bytes: &[u8]) -> io::Result<()> {
    write_bytes(path, bytes, false)
}

/// .NET's `DateTime.ToUniversalTime().ToString("O")`: exactly seven fractional digits and `Z`.
pub fn dotnet_o_time(time: SystemTime) -> String {
    let utc: DateTime<Utc> = time.into();
    format!(
        "{}.{:07}Z",
        utc.format("%Y-%m-%dT%H:%M:%S"),
        utc.timestamp_subsec_nanos() / 100
    )
}

/// `DateTime.Now.ToString("HH:mm:ss.fff")` for every log line.
pub fn log_stamp() -> String {
    Local::now().format("%H:%M:%S%.3f").to_string()
}

/// `DateTime.UtcNow.ToString("u")`, used for the executable's build time.
pub fn utc_seconds(time: SystemTime) -> String {
    let utc: DateTime<Utc> = time.into();
    utc.format("%Y-%m-%d %H:%M:%SZ").to_string()
}

/// Fractions of a second as the API's `ct` header wants them: microseconds since the epoch.
pub fn microseconds_since_epoch(time: SystemTime) -> String {
    time.duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_micros()
        .to_string()
}

/// A one-line, cause-joined error, mirroring CaptureDiagnostics.Chain without the .NET type names.
/// Query strings are cut out, because an error from the HTTP client can name the full URL and
/// proxy.log must never carry a value the game sent.
pub fn describe(error: &Error) -> String {
    redact_urls(&format!("{error:#}").replace('\n', " "))
}

fn redact_urls(text: &str) -> String {
    text.split_whitespace()
        .map(|token| {
            let lower = token.to_ascii_lowercase();
            let scheme = lower.find("http://").or_else(|| lower.find("https://"));
            match (scheme, token.find('?')) {
                (Some(start), Some(query)) if query > start => {
                    format!("{}?<redacted>", &token[..query])
                }
                _ => token.to_string(),
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

pub fn describe_io(error: &io::Error) -> String {
    let mut text = error.to_string();
    if let Some(code) = error.raw_os_error() {
        text.push_str(&format!(" (os error {code})"));
    }
    if let Some(inner) = error.get_ref() {
        text.push_str(&format!(": {inner}"));
    }
    text.replace('\n', " ")
}

/// Reads a `KEY=value` line from /etc/os-release without requiring a shell.
pub fn os_pretty_name() -> String {
    let text = fs::read_to_string("/etc/os-release").unwrap_or_default();
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("PRETTY_NAME=") {
            return rest.trim_matches('"').to_string();
        }
    }
    "Linux".to_string()
}

pub fn kernel_release() -> String {
    fs::read_to_string("/proc/sys/kernel/osrelease")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "unknown".to_string())
}
