// The snapshot seal, ported from HellForge.Core SnapshotSeal.
//
// The payload, hashes, JSON shape and HMAC-SHA256 are identical to the Windows tool. The key
// protection is not: Windows wraps a machine-scoped DPAPI blob, which Linux does not have. Here
// the 32-byte key lives in a root-only (0600) file with a short Linux marker, so a copy of the
// snapshot folder without that file verifies nowhere, but a copy of both does. Like the
// original this is a good-faith check, not a guarantee. A `seal.key` made by the Windows tool is
// recognised as foreign and never overwritten.

use std::fs;
use std::io;
use std::path::Path;
use std::time::SystemTime;

use anyhow::{anyhow, bail, Context, Result};
use hmac::{Hmac, Mac};
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::util;

pub const FILE_NAME: &str = "seal.json";
pub const INVENTORY_FILE: &str = "real-inventory.json";
pub const PROGRESSION_FILE: &str = "progression.json";
const VERSION: i32 = 1;
const MAC_DOMAIN: &str = "hellforge-snapshot-seal";
const KEY_MAGIC: &[u8; 8] = b"HFLINUX1";
const KEY_LEN: usize = 32;

type HmacSha256 = Hmac<Sha256>;

fn hash_file(path: &Path) -> io::Result<Option<String>> {
    match fs::read(path) {
        Ok(bytes) => Ok(Some(hex::encode_upper(Sha256::digest(&bytes)))),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

fn load_or_create_key(path: &Path) -> Result<Vec<u8>> {
    match fs::read(path) {
        Ok(mut data) => {
            if data.len() != KEY_MAGIC.len() + KEY_LEN
                || data.get(..KEY_MAGIC.len()) != Some(KEY_MAGIC)
            {
                bail!(
                    "{} exists but is not a Linux capture seal key (it may be the Windows \
                     DPAPI-protected one). Remove it deliberately, or point --seal-key \
                     elsewhere.",
                    path.display()
                );
            }
            Ok(data.split_off(KEY_MAGIC.len()))
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let mut key = vec![0u8; KEY_LEN];
            rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut key);
            let mut data = KEY_MAGIC.to_vec();
            data.extend_from_slice(&key);
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)?;
            }
            util::write_atomic_root(path, &data)
                .with_context(|| format!("cannot write {}", path.display()))?;
            util::set_mode(path, 0o600);
            Ok(key)
        }
        Err(error) => Err(error.into()),
    }
}

/// The newline-joined fields the seal MAC covers. Kept separate from [`mac`] so the Rust and
/// C# implementations share one obvious shape.
fn seal_payload(
    account: u64,
    captured_utc: &str,
    inventory_sha256: &str,
    progression_sha256: Option<&str>,
) -> String {
    [
        MAC_DOMAIN.to_string(),
        VERSION.to_string(),
        account.to_string(),
        captured_utc.to_string(),
        inventory_sha256.to_string(),
        progression_sha256.unwrap_or("-").to_string(),
    ]
    .join("\n")
}

fn mac(
    key: &[u8],
    account: u64,
    captured_utc: &str,
    inventory_sha256: &str,
    progression_sha256: Option<&str>,
) -> String {
    let payload = seal_payload(account, captured_utc, inventory_sha256, progression_sha256);
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(payload.as_bytes());
    hex::encode_upper(mac.finalize().into_bytes())
}

/// Seals the inventory (required) and progression (when present) in `folder`.
pub fn write(folder: &Path, key_path: &Path, account: u64, captured: SystemTime) -> Result<()> {
    let inventory =
        hash_file(&folder.join(INVENTORY_FILE))?.ok_or_else(|| anyhow!("No inventory to seal."))?;
    let progression = hash_file(&folder.join(PROGRESSION_FILE))?;
    let key = load_or_create_key(key_path)?;
    let captured_utc = util::dotnet_o_time(captured);
    let seal = json!({
        "version": VERSION,
        "steamAccount": account.to_string(),
        "capturedUtc": captured_utc,
        "inventorySha256": inventory,
        "progressionSha256": progression,
        "mac": mac(&key, account, &captured_utc, &inventory, progression.as_deref()),
    });
    util::write_atomic(&folder.join(FILE_NAME), format!("{seal}\n").as_bytes())?;
    Ok(())
}
