//! Parser for the recovery input file: `name = value`, one per line, no quotes.
//! Lines starting with `#` are comments. Friendlier to hand-edit than JSON
//! (no quotes to get smart-quoted, no commas, inline comments allowed).

use anyhow::{anyhow, bail, Result};

use crate::backup::{Backup, BlocktrailKey};

pub fn parse(text: &str) -> Result<Backup> {
    let mut testnet = None;
    let mut version = None;
    let mut password = None;
    let mut primary_passphrase = None;
    let mut primary = None;
    let mut encrypted_primary = None;
    let mut password_encrypted_secret = None;
    let mut backup = None;
    let mut keys: Vec<BlocktrailKey> = Vec::new();

    for (i, raw) in text.lines().enumerate() {
        let n = i + 1;
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (key, val) = line
            .split_once('=')
            .ok_or_else(|| anyhow!("line {n}: expected  name = value"))?;
        let (key, val) = (key.trim(), val.trim());
        if val.is_empty() {
            continue;
        }
        let keyl = key.to_ascii_lowercase();

        // "key 9999 = tpub..." / "key9999 = tpub..."
        if keyl.starts_with("key") {
            if let Ok(key_index) = key[3..].trim().parse::<u32>() {
                keys.push(BlocktrailKey { key_index, pubkey: val.to_string() });
                continue;
            }
        }
        match keyl.as_str() {
            "testnet" => {
                testnet = Some(matches!(val.to_ascii_lowercase().as_str(), "true" | "1" | "yes"))
            }
            "version" | "walletversion" => {
                version = Some(
                    val.parse::<u32>()
                        .map_err(|_| anyhow!("line {n}: version must be 1, 2, or 3"))?,
                )
            }
            "password" => password = Some(val.to_string()),
            "primary_passphrase" | "primarypassphrase" => primary_passphrase = Some(val.to_string()),
            "primary" | "primary_mnemonic" | "primarymnemonic" => primary = Some(val.to_string()),
            "encrypted_primary" | "encrypted_primary_mnemonic" | "encryptedprimarymnemonic" => {
                encrypted_primary = Some(val.to_string())
            }
            "password_encrypted_secret"
            | "password_encrypted_secret_mnemonic"
            | "passwordencryptedsecretmnemonic" => {
                password_encrypted_secret = Some(val.to_string())
            }
            "backup" | "backup_mnemonic" | "backupmnemonic" => backup = Some(val.to_string()),
            other => bail!("line {n}: unknown setting '{other}'"),
        }
    }

    let wallet_version = version.ok_or_else(|| anyhow!("missing 'version' (1, 2, or 3)"))?;
    if keys.is_empty() {
        bail!("no BlockTrail keys — add at least one line like  key 9999 = tpub...");
    }

    Ok(Backup {
        testnet,
        wallet_version,
        primary_mnemonic: primary,
        primary_passphrase,
        encrypted_primary_mnemonic: encrypted_primary,
        password_encrypted_secret_mnemonic: password_encrypted_secret,
        backup_mnemonic: backup,
        password,
        blocktrail_keys: keys,
    })
}
