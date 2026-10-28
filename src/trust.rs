// Installing and removing the per-run CA in the distribution's system trust store.
//
// Linux has no single LocalMachine\Root. The common layouts are:
//   Debian/Ubuntu/Mint  /usr/local/share/ca-certificates  + update-ca-certificates
//   Fedora/RHEL         /etc/pki/ca-trust/source/anchors   + update-ca-trust extract
//   Arch                /etc/ca-certificates/trust-source/anchors + trust extract-compat
//   openSUSE            /etc/pki/trust/anchors (or /usr/share/pki/trust/anchors)
// NixOS and immutable systems generate /etc/ssl/certs themselves; there `--ca-out` plus the
// system configuration is the answer, and this module says so rather than failing silently.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{bail, Result};

use crate::log::Logger;
use crate::util;

pub const ANCHOR_PREFIX: &str = "hellforge-capture-ca";

struct Store {
    dir: PathBuf,
    program: &'static str,
    arguments: &'static [&'static str],
}

impl Store {
    fn update(&self) -> Result<(), String> {
        if !command_exists(self.program) {
            return Err(format!("{} is not installed", self.program));
        }
        match Command::new(self.program).args(self.arguments).output() {
            Ok(output) if output.status.success() => Ok(()),
            Ok(output) => {
                let tail = String::from_utf8_lossy(&output.stderr);
                let line = tail
                    .lines()
                    .rev()
                    .find(|line| !line.trim().is_empty())
                    .unwrap_or("")
                    .trim()
                    .to_string();
                Err(format!(
                    "{} {} failed ({}): {}",
                    self.program,
                    self.arguments.join(" "),
                    output.status,
                    line.chars().take(300).collect::<String>()
                ))
            }
            Err(error) => Err(format!("{}: {error}", self.program)),
        }
    }
}

fn command_exists(program: &str) -> bool {
    let Some(path) = std::env::var_os("PATH") else {
        return false;
    };
    std::env::split_paths(&path).any(|dir| {
        let candidate = dir.join(program);
        candidate.is_file()
    })
}

/// Every layout this host has, most specific first.
fn candidates() -> Vec<Store> {
    vec![
        Store {
            dir: PathBuf::from("/usr/local/share/ca-certificates"),
            program: "update-ca-certificates",
            arguments: &[],
        },
        Store {
            dir: PathBuf::from("/etc/pki/ca-trust/source/anchors"),
            program: "update-ca-trust",
            arguments: &["extract"],
        },
        Store {
            dir: PathBuf::from("/etc/ca-certificates/trust-source/anchors"),
            program: "trust",
            arguments: &["extract-compat"],
        },
        Store {
            dir: PathBuf::from("/etc/pki/trust/anchors"),
            program: "update-ca-certificates",
            arguments: &[],
        },
        Store {
            dir: PathBuf::from("/usr/share/pki/trust/anchors"),
            program: "update-ca-certificates",
            arguments: &[],
        },
    ]
}

fn writable_store() -> Option<Store> {
    candidates()
        .into_iter()
        .find(|store| store.dir.is_dir() && command_exists(store.program))
}

fn anchor_path(store: &Store) -> PathBuf {
    store.dir.join(format!("{ANCHOR_PREFIX}.crt"))
}

/// Installs (or replaces) this run's CA. Fails loudly when there is nowhere to put it.
pub fn install(pem: &str, log: &Logger) -> Result<()> {
    let Some(store) = writable_store() else {
        bail!(
            "no writable system trust store was found (looked for update-ca-certificates, \
             update-ca-trust and trust). Pass --ca-out <file.pem> and add the CA to your \
             system trust configuration, or run with --no-ca for a local plumbing test."
        );
    };
    fs::create_dir_all(&store.dir)?;
    let path = anchor_path(&store);
    util::write_atomic_root(&path, pem.as_bytes())?;
    util::set_mode(&path, 0o644);
    log.line(format!("CA written to {}", path.display()));
    store
        .update()
        .map_err(|error| anyhow::anyhow!("CA trust refresh failed: {error}"))?;
    log.line(format!(
        "CA installed ({} {})",
        store.program,
        store.arguments.join(" ")
    ));
    Ok(())
}

fn remove_anchors_in(dir: &Path) -> std::io::Result<bool> {
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error),
    };
    let mut removed = false;
    let mut failure = None;
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                failure.get_or_insert(error);
                continue;
            }
        };
        let name = entry.file_name().to_string_lossy().to_string();
        let anchor =
            name.starts_with(ANCHOR_PREFIX) && (name.ends_with(".crt") || name.ends_with(".pem"));
        if !anchor {
            continue;
        }
        match fs::remove_file(entry.path()) {
            Ok(()) => removed = true,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                failure.get_or_insert(error);
            }
        }
    }
    match failure {
        Some(error) => Err(error),
        None => Ok(removed),
    }
}

/// Removes every anchor this tool ever left behind and refreshes each store that had one.
/// True when every step worked (including "there was nothing to remove").
pub fn remove(log: &Logger) -> bool {
    let mut ok = true;
    for store in candidates() {
        match remove_anchors_in(&store.dir) {
            Ok(false) => {}
            Ok(true) => {
                log.line(format!("CA removed from {}", store.dir.display()));
                if let Err(error) = store.update() {
                    log.line(format!("CA trust refresh failed: {error}"));
                    ok = false;
                }
            }
            Err(error) => {
                log.line(format!(
                    "CA cleanup failed in {}: {error}",
                    store.dir.display()
                ));
                ok = false;
            }
        }
    }
    ok
}
