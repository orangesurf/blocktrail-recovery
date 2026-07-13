//! HD derivation -> Sparrow descriptors + xprvs + addresses.
//! BlockTrail's paths: primary at m/<index>' (hardened), backup at m/<index> (unhardened),
//! BlockTrail xpub already at M/<index>'; 2-of-3 sortedmulti (BIP67).
//!
//! The chain element (`m/<index>'/<chain>/<addr>`) is a SCRIPT/COIN selector, not a
//! receive/change split: 0 = BTC legacy P2SH, 1 = Bitcoin Cash, 2 = BTC nested SegWit
//! (P2SH-P2WSH). BlockTrail's change goes to the *next index on the same chain*
//! (`changeChain == chain`), so a single chain holds both receive and change. We emit
//! one wallet per BTC script type — legacy (chain 0) and SegWit (chain 2) — and never
//! touch chain 1 (BCH). Wallets created before ~July 2018 are legacy-only; later ones
//! keep their main funds on the SegWit chain.

use anyhow::{anyhow, Result};
use bitcoin::bip32::{ChildNumber, DerivationPath, Xpriv, Xpub};
use bitcoin::opcodes::all::OP_CHECKMULTISIG;
use bitcoin::script::Builder;
use bitcoin::secp256k1::{All, Secp256k1};
use bitcoin::{Address, Network, NetworkKind, PublicKey, ScriptBuf};
use serde::Serialize;
use std::str::FromStr;

use crate::backup::Backup;
use crate::decrypt::derive_seeds;

/// BlockTrail chain (script-type) indices. Chain 1 (Bitcoin Cash) is intentionally absent.
const CHAIN_LEGACY: u32 = 0;
const CHAIN_SEGWIT: u32 = 2;

#[derive(Serialize)]
pub struct WalletKind {
    /// Watch-only descriptor (xpubs) to paste into Sparrow.
    pub descriptor: String,
    /// Sample addresses on this chain. Receive and change share the chain, so this
    /// list covers both — scan far enough and it finds every address the wallet used.
    pub addresses: Vec<String>,
}

#[derive(Serialize)]
pub struct KeyBlock {
    pub key_index: u32,
    /// Fingerprint of the BlockTrail (watch-only) keystore for this key index.
    pub fpr_blocktrail: String,
    /// Legacy P2SH wallet (chain 0).
    pub legacy: WalletKind,
    /// Nested-SegWit P2SH-P2WSH wallet (chain 2).
    pub segwit: WalletKind,
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

/// The two decrypted signing keys (xprvs) are secret; wipe them when the Output drops.
impl Drop for Output {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.primary_xprv.zeroize();
        self.backup_xprv.zeroize();
    }
}

/// The 2-of-3 multisig redeem/witness script for a given derivation, BIP67-sorted.
fn multisig_script(
    secp: &Secp256k1<All>,
    accts: &[&Xpub; 3],
    chain: u32,
    i: u32,
) -> Result<ScriptBuf> {
    let path = DerivationPath::from(vec![
        ChildNumber::from_normal_idx(chain)?,
        ChildNumber::from_normal_idx(i)?,
    ]);
    let mut pubkeys: Vec<PublicKey> = Vec::with_capacity(3);
    for a in accts {
        let child = a.derive_pub(secp, &path)?;
        pubkeys.push(PublicKey::new(child.public_key));
    }
    // BIP67: sort by compressed pubkey bytes.
    pubkeys.sort_by_key(|pk| pk.inner.serialize());
    let mut b = Builder::new().push_int(2);
    for pk in &pubkeys {
        b = b.push_key(pk);
    }
    Ok(b.push_int(pubkeys.len() as i64)
        .push_opcode(OP_CHECKMULTISIG)
        .into_script())
}

/// Address at `chain`/`i`. Legacy = P2SH(multisig); SegWit = P2SH(P2WSH(multisig)).
fn addr_at(
    secp: &Secp256k1<All>,
    accts: &[&Xpub; 3],
    chain: u32,
    i: u32,
    network: Network,
    segwit: bool,
) -> Result<String> {
    let multisig = multisig_script(secp, accts, chain, i)?;
    let addr = if segwit {
        // Nested SegWit: the P2SH redeem script IS the P2WSH program (OP_0 <sha256(ws)>).
        let redeem = ScriptBuf::new_p2wsh(&multisig.wscript_hash());
        Address::p2sh(&redeem, network).map_err(|e| anyhow!("p2sh-p2wsh: {e}"))?
    } else {
        Address::p2sh(&multisig, network).map_err(|e| anyhow!("p2sh: {e}"))?
    };
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

        let accts = [&prim_acct, &back_acct, &bt_xpub];

        // Origin is [master_fpr/keyIndex(')] for the primary/backup (their real master
        // fingerprints); for the BlockTrail key we only hold the account xpub, so its
        // own fingerprint stands in — cosmetic, addresses derive purely from the pubkeys.
        let legacy_descriptor = format!(
            "sh(sortedmulti(2,[{fpr_primary}/{ki}']{prim_acct}/{CHAIN_LEGACY}/*,[{fpr_backup}/{ki}]{back_acct}/{CHAIN_LEGACY}/*,[{fbt}/{ki}']{bt_xpub}/{CHAIN_LEGACY}/*))"
        );
        let segwit_descriptor = format!(
            "sh(wsh(sortedmulti(2,[{fpr_primary}/{ki}']{prim_acct}/{CHAIN_SEGWIT}/*,[{fpr_backup}/{ki}]{back_acct}/{CHAIN_SEGWIT}/*,[{fbt}/{ki}']{bt_xpub}/{CHAIN_SEGWIT}/*)))"
        );

        let mut legacy_addresses = Vec::with_capacity(n_addr as usize);
        let mut segwit_addresses = Vec::with_capacity(n_addr as usize);
        for i in 0..n_addr {
            legacy_addresses.push(addr_at(&secp, &accts, CHAIN_LEGACY, i, network, false)?);
            segwit_addresses.push(addr_at(&secp, &accts, CHAIN_SEGWIT, i, network, true)?);
        }

        keys.push(KeyBlock {
            key_index: ki,
            fpr_blocktrail: fbt,
            legacy: WalletKind { descriptor: legacy_descriptor, addresses: legacy_addresses },
            segwit: WalletKind { descriptor: segwit_descriptor, addresses: segwit_addresses },
        });
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
