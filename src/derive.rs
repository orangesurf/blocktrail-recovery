//! HD derivation -> Sparrow descriptor + xprvs + P2SH addresses.
//! BlockTrail's paths: primary at m/<index>' (hardened), backup at m/<index> (unhardened);
//! 2-of-3 sortedmulti (BIP67) wrapped in P2SH.

use anyhow::{anyhow, Result};
use bitcoin::bip32::{ChildNumber, DerivationPath, Xpriv, Xpub};
use bitcoin::opcodes::all::OP_CHECKMULTISIG;
use bitcoin::script::Builder;
use bitcoin::secp256k1::{All, Secp256k1};
use bitcoin::{Address, Network, NetworkKind, PublicKey};
use serde::Serialize;
use std::str::FromStr;

use crate::backup::Backup;
use crate::decrypt::derive_seeds;

#[derive(Serialize)]
pub struct KeyBlock {
    pub key_index: u32,
    /// Watch-only descriptor (xpubs) — what you paste into Sparrow to create the wallet.
    pub descriptor: String,
    /// Fingerprint of the BlockTrail (watch-only) keystore for this key index.
    pub fpr_blocktrail: String,
    pub receive: Vec<String>,
    pub change: Vec<String>,
}

#[derive(Serialize)]
pub struct Output {
    pub network: String,
    pub fpr_primary: String,
    pub fpr_backup: String,
    pub primary_xprv: String,
    pub backup_xprv: String,
    pub keys: Vec<KeyBlock>,
}

fn addr_at(
    secp: &Secp256k1<All>,
    accts: &[&Xpub; 3],
    chain: u32,
    i: u32,
    network: Network,
) -> Result<String> {
    let path = DerivationPath::from(vec![
        ChildNumber::from_normal_idx(chain)?,
        ChildNumber::from_normal_idx(i)?,
    ]);
    let mut pubkeys: Vec<PublicKey> = Vec::with_capacity(3);
    for a in accts {
        let child = a.derive_pub(secp, &path)?;
        pubkeys.push(PublicKey::new(child.public_key));
    }
    // BIP67: sort by compressed pubkey bytes
    pubkeys.sort_by(|x, y| x.inner.serialize().cmp(&y.inner.serialize()));
    let mut b = Builder::new().push_int(2);
    for pk in &pubkeys {
        b = b.push_key(pk);
    }
    let script = b
        .push_int(pubkeys.len() as i64)
        .push_opcode(OP_CHECKMULTISIG)
        .into_script();
    let addr = Address::p2sh(&script, network).map_err(|e| anyhow!("p2sh: {e}"))?;
    Ok(addr.to_string())
}

pub fn generate(bd: &Backup, n_addr: u32) -> Result<Output> {
    let secp = Secp256k1::new();
    let testnet = bd.testnet.unwrap_or(false);
    let netkind = if testnet { NetworkKind::Test } else { NetworkKind::Main };
    let network = if testnet { Network::Testnet } else { Network::Bitcoin };

    let seeds = derive_seeds(bd)?;
    let prim_master = Xpriv::new_master(netkind, &seeds.primary)?;
    let back_master = Xpriv::new_master(netkind, &seeds.backup)?;
    let fpr_primary = prim_master.fingerprint(&secp).to_string();
    let fpr_backup = back_master.fingerprint(&secp).to_string();

    let mut keys = Vec::new();
    for k in &bd.blocktrail_keys {
        let ki = k.key_index;
        let bt_xpub = Xpub::from_str(&k.pubkey).map_err(|e| anyhow!("bad BlockTrail key: {e}"))?;
        let fbt = bt_xpub.fingerprint().to_string();

        let prim_acct_xpriv = prim_master.derive_priv(
            &secp,
            &DerivationPath::from(vec![ChildNumber::from_hardened_idx(ki)?]),
        )?;
        let prim_acct = Xpub::from_priv(&secp, &prim_acct_xpriv);

        let back_acct_xpriv = back_master.derive_priv(
            &secp,
            &DerivationPath::from(vec![ChildNumber::from_normal_idx(ki)?]),
        )?;
        let back_acct = Xpub::from_priv(&secp, &back_acct_xpriv);

        let descriptor = format!(
            "sh(sortedmulti(2,[{fpr_primary}/{ki}']{prim_acct}/<0;1>/*,[{fpr_backup}/{ki}]{back_acct}/<0;1>/*,[{fbt}/{ki}']{bt_xpub}/<0;1>/*))"
        );

        let accts = [&prim_acct, &back_acct, &bt_xpub];
        let mut receive = Vec::new();
        let mut change = Vec::new();
        for i in 0..n_addr {
            receive.push(addr_at(&secp, &accts, 0, i, network)?);
            change.push(addr_at(&secp, &accts, 1, i, network)?);
        }
        keys.push(KeyBlock { key_index: ki, descriptor, fpr_blocktrail: fbt, receive, change });
    }

    Ok(Output {
        network: if testnet { "testnet".into() } else { "mainnet".into() },
        fpr_primary,
        fpr_backup,
        primary_xprv: prim_master.to_string(),
        backup_xprv: back_master.to_string(),
        keys,
    })
}
