// The capture's detailed, value-free diagnostics: proxy.log itself, plus the ports of
// CaptureLog, CaptureDiagnostics/Tally, CaptureState and Shorten from the Windows tool.
// Bodies, header values, query values and the session never reach a line.

use std::collections::BTreeMap;
use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use percent_encoding::percent_decode_str;
use serde_json::Value;

use crate::util;

const CA_NAME: &str = "HellForge Capture CA";
pub const LOGIN_PATH: &str = "/api/Account/Login";
pub const PROGRESSION_PATH: &str = "/api/Progression";
pub const INVENTORY_PATH: &str = "/api/Progression/inventory";

#[derive(Clone)]
pub struct Logger {
    inner: Arc<LoggerInner>,
}

struct LoggerInner {
    dir: PathBuf,
    gate: Mutex<()>,
}

impl Logger {
    pub fn new(dir: PathBuf) -> Self {
        // Touch the log now so it can be handed to the invoking user before the first line.
        let path = dir.join("proxy.log");
        if let Ok(file) = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(&path)
        {
            drop(file);
            util::give_to_sudo_user(&path);
        }
        Self {
            inner: Arc::new(LoggerInner {
                dir,
                gate: Mutex::new(()),
            }),
        }
    }

    pub fn line(&self, message: impl AsRef<str>) {
        let message = message.as_ref();
        let stamp = util::log_stamp();
        println!("{stamp} {message}");
        let _guard = self
            .inner
            .gate
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        match OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(self.inner.dir.join("proxy.log"))
        {
            Ok(mut file) => {
                let _ = writeln!(file, "{stamp} {message}");
            }
            Err(error) => eprintln!("log write failed: {error}"),
        }
    }
}

pub fn is_capture_path(path: &str) -> bool {
    path.eq_ignore_ascii_case(LOGIN_PATH)
        || path.eq_ignore_ascii_case(PROGRESSION_PATH)
        || path.eq_ignore_ascii_case(INVENTORY_PATH)
}

/// "/api/FriendsV2/Recent" stays, "/api/Proxy/<id>/<id>" becomes "/api/Proxy/...": later
/// segments can carry account ids.
pub fn shorten(path: &str) -> String {
    let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    let exact_capture = path == LOGIN_PATH || path == PROGRESSION_PATH || path == INVENTORY_PATH;
    if segments.len() <= 3 && exact_capture {
        return path.to_string();
    }
    let head: Vec<&str> = segments.iter().take(2).copied().collect();
    let mut text = format!("/{}", head.join("/"));
    if segments.len() > 2 {
        text.push_str("/...");
    }
    text
}

fn cap(text: String, max: usize, tail: &str) -> String {
    if text.len() <= max {
        return text;
    }
    let mut end = max;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}{}", &text[..end], tail)
}

fn value_kind(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(true) => "true",
        Value::Bool(false) => "false",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

/// "object{items[724], limitSettings{3}, loadouts[2]}": top-level keys with array lengths or
/// key counts, never a value.
pub fn json_shape(body: &[u8]) -> String {
    if body.is_empty() {
        return "empty".to_string();
    }
    let document: Value = match serde_json::from_slice(body) {
        Ok(value) => value,
        Err(_) => return format!("not JSON, {} bytes", body.len()),
    };
    match document {
        Value::Object(map) => {
            let mut parts = Vec::new();
            for (name, value) in map.iter().take(24) {
                let suffix = match value {
                    Value::Array(items) => format!("[{}]", items.len()),
                    Value::Object(entries) => format!("{{{}}}", entries.len()),
                    other => format!(":{}", value_kind(other)),
                };
                parts.push(format!("{name}{suffix}"));
            }
            let mut text = format!("object{{{}", parts.join(", "));
            if map.len() > 24 {
                text.push_str(", ...");
            }
            text.push('}');
            cap(text, 400, "...}")
        }
        Value::Array(items) => format!("array[{}]", items.len()),
        other => value_kind(&other).to_string(),
    }
}

/// "title=Bad request; errors.version[0]=The version field is required." for a JSON error body.
pub fn error_text(body: &[u8]) -> String {
    if body.is_empty() {
        return "empty body".to_string();
    }
    let document: Value = match serde_json::from_slice(body) {
        Ok(value) => value,
        Err(_) => return format!("not JSON, {} bytes", body.len()),
    };
    let mut fields = Vec::new();
    collect_error_fields(&document, "", 0, &mut fields);
    if fields.is_empty() {
        "no fields".to_string()
    } else {
        cap(fields.join("; "), 300, "...")
    }
}

fn collect_error_fields(element: &Value, path: &str, depth: usize, fields: &mut Vec<String>) {
    if depth > 4 {
        return;
    }
    match element {
        Value::Object(map) => {
            for (name, value) in map {
                let next = if path.is_empty() {
                    name.clone()
                } else {
                    format!("{path}.{name}")
                };
                collect_error_fields(value, &next, depth + 1, fields);
            }
        }
        Value::Array(items) => {
            for (index, value) in items.iter().enumerate() {
                collect_error_fields(value, &format!("{path}[{index}]"), depth + 1, fields);
            }
        }
        Value::String(text) => {
            let text = plain_text(text);
            fields.push(if path.is_empty() {
                text
            } else {
                format!("{path}={text}")
            });
        }
        other => {
            let text = other.to_string();
            fields.push(if path.is_empty() {
                text
            } else {
                format!("{path}={text}")
            });
        }
    }
}

fn plain_text(value: &str) -> String {
    if value.chars().count() > 24 && !value.contains(' ') {
        return format!("<{} characters>", value.chars().count());
    }
    value
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect()
}

/// Names only, sorted, so the log never holds a value.
pub fn names<'a>(names: impl IntoIterator<Item = &'a str>) -> String {
    let mut names: Vec<&str> = names.into_iter().collect();
    names.sort_by_key(|name| name.to_ascii_lowercase());
    names.join(", ")
}

/// The query's parameter names ("none" without a query).
pub fn query_names(target: &str) -> String {
    let Some((_, query)) = target.split_once('?') else {
        return "none".to_string();
    };
    if query.is_empty() {
        return "none".to_string();
    }
    let decoded: Vec<String> = query
        .split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| {
            let raw = pair.split('=').next().unwrap_or("");
            percent_decode_str(raw).decode_utf8_lossy().into_owned()
        })
        .collect();
    names(decoded.iter().map(|name| name.as_str()))
}

pub fn ca_name() -> &'static str {
    CA_NAME
}

/// Requests by shortened path and status: "POST /api/Proxy/... 200 x3".
#[derive(Default)]
pub struct Tally {
    counts: BTreeMap<String, u64>,
}

impl Tally {
    pub fn add(&mut self, method: &str, path: &str, status: u16) {
        let key = format!("{method} {path} {status}");
        *self.counts.entry(key).or_insert(0) += 1;
    }

    pub fn total(&self) -> u64 {
        self.counts.values().sum()
    }

    pub fn lines(&self) -> Vec<String> {
        self.counts
            .iter()
            .map(|(key, count)| format!("{key} x{count}"))
            .collect()
    }
}

pub const STATE_FILE: &str = "capture-state.json";

/// Written once the capture listens and again once it is sealed; the launcher takes it away.
pub fn write_state(dir: &Path, pid: u32, sealed: bool, progression: bool) -> std::io::Result<()> {
    let state = serde_json::json!({
        "pid": pid,
        "sealed": sealed,
        "progression": progression,
    });
    util::write_atomic(&dir.join(STATE_FILE), format!("{state}\n").as_bytes())
}
