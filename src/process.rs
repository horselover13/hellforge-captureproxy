// The game's and Easy Anti-Cheat's processes coming and going, read from /proc because Linux
// has no Process.GetProcessesByName. Wine/Proton renames the game's Unix process to
// helldivers2.exe, so both forms are matched, and the basename is considered on its own for
// command lines such as `Z:\...\helldivers2.exe`.

use std::collections::BTreeMap;
use std::fs;

pub const GAME_PROCESS: &str = "helldivers2";

/// The names the original watched, in its order.
pub const WATCHED: &[&str] = &[
    "helldivers2",
    "EasyAntiCheat_EOS",
    "EasyAntiCheat",
    "start_protected_game",
];

fn matches(raw: &str, watched: &str) -> bool {
    let base = raw
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(raw)
        .trim_end_matches('\0');
    let base = base.to_ascii_lowercase();
    let base = base.strip_suffix(".exe").unwrap_or(&base);
    base.eq_ignore_ascii_case(&watched.to_ascii_lowercase())
}

/// pid -> the watched name it matched. A pid appears once, under the first name that matched.
pub fn snapshot() -> BTreeMap<i32, String> {
    let mut seen = BTreeMap::new();
    let Ok(entries) = fs::read_dir("/proc") else {
        return seen;
    };
    for entry in entries.flatten() {
        let Ok(pid) = entry.file_name().to_string_lossy().parse::<i32>() else {
            continue;
        };
        let path = entry.path();
        let mut names: Vec<String> = Vec::new();
        if let Ok(comm) = fs::read_to_string(path.join("comm")) {
            names.push(comm.trim().to_string());
        }
        if let Ok(command_line) = fs::read(path.join("cmdline")) {
            for part in command_line
                .split(|byte| *byte == 0)
                .filter(|p| !p.is_empty())
            {
                if let Ok(text) = std::str::from_utf8(part) {
                    names.push(text.to_string());
                }
            }
        }
        for watched in WATCHED {
            if names.iter().any(|name| matches(name, watched)) {
                seen.insert(pid, (*watched).to_string());
                break;
            }
        }
    }
    seen
}

pub fn is_game_running() -> bool {
    snapshot()
        .values()
        .any(|name| name.eq_ignore_ascii_case(GAME_PROCESS))
}
