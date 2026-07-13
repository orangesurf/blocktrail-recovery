//! BlockTrail-specific decryption + BIP39 handling.
//! Mirrors the verified JS: v3 = PBKDF2-SHA512 + AES-256-GCM (16-byte IV, header as AAD);
//! v2 = OpenSSL EVP_BytesToKey(MD5) + AES-256-CBC; oversized "encrypted mnemonics"
//! decoded manually because standard BIP39 libraries reject them.

use aes::Aes256;
use aes_gcm::aead::consts::U16;
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{AesGcm, Nonce};
use anyhow::{anyhow, bail, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use cbc::cipher::block_padding::Pkcs7;
use cbc::cipher::{BlockDecryptMut, KeyIvInit};
use md5::Md5;
use pbkdf2::pbkdf2_hmac;
use sha2::{Digest, Sha256, Sha512};
use zeroize::Zeroizing;

use crate::backup::Backup;

type Aes256Gcm16 = AesGcm<Aes256, U16>;
type Aes256CbcDec = cbc::Decryptor<Aes256>;

/// BIP39 mnemonic -> entropy. Standard lengths via the bip39 crate; BlockTrail's
/// longer encrypted mnemonics decoded manually (word->11 bits, SHA-256 checksum).
pub fn mnemonic_to_entropy(m: &str) -> Result<Vec<u8>> {
    let words: Vec<&str> = m.split_whitespace().collect();
    if words.len() <= 24 {
        let mn = bip39::Mnemonic::parse_in_normalized(bip39::Language::English, m.trim())
            .map_err(|e| anyhow!("invalid mnemonic: {e}"))?;
        return Ok(mn.to_entropy());
    }
    if words.len() % 3 != 0 {
        bail!("word count must be a multiple of 3");
    }
    let wl = bip39::Language::English.word_list();
    let mut bits = String::new();
    for w in &words {
        let idx = wl
            .iter()
            .position(|x| x == w)
            .ok_or_else(|| anyhow!("unknown word: {w}"))?;
        bits.push_str(&format!("{idx:011b}"));
    }
    let div = (bits.len() / 33) * 32;
    let (ent_bits, cs_bits) = bits.split_at(div);
    let mut entropy = Vec::with_capacity(ent_bits.len() / 8);
    for chunk in ent_bits.as_bytes().chunks(8) {
        let s = std::str::from_utf8(chunk).unwrap();
        entropy.push(u8::from_str_radix(s, 2).unwrap());
    }
    let hash = Sha256::digest(&entropy);
    let mut cs = String::new();
    for b in hash.iter() {
        if cs.len() >= cs_bits.len() {
            break;
        }
        cs.push_str(&format!("{b:08b}"));
    }
    if &cs[..cs_bits.len()] != cs_bits {
        bail!("mnemonic checksum mismatch — a word is likely wrong or out of order");
    }
    Ok(entropy)
}

/// Standard BIP39 mnemonic -> 64-byte seed (v1 wallets).
fn mnemonic_to_seed(m: &str, pass: &str) -> Result<Vec<u8>> {
    let mn = bip39::Mnemonic::parse_in_normalized(bip39::Language::English, m.trim())
        .map_err(|e| anyhow!("invalid mnemonic: {e}"))?;
    Ok(mn.to_seed(pass).to_vec())
}

/// EncryptionMnemonic.decode: mnemonic -> entropy -> strip leading 0x81 padding.
fn enc_mnem_decode(m: &str) -> Result<Vec<u8>> {
    let d = mnemonic_to_entropy(m)?;
    let mut p = 0;
    while p < d.len() && d[p] == 0x81 {
        p += 1;
    }
    Ok(d[p..].to_vec())
}

/// v3: saltLen(1) | salt | iter(4 LE) | iv(16) | ciphertext+tag ; AES-256-GCM, AAD = header.
fn v3_decrypt(ct: &[u8], pw: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if ct.len() < 1 + 4 + 16 {
        bail!("v3: ciphertext too short");
    }
    let salt_len = ct[0] as usize;
    let salt = &ct[1..1 + salt_len];
    let mut c = 1 + salt_len;
    let iter = u32::from_le_bytes(ct[c..c + 4].try_into()?);
    c += 4;
    let header = &ct[0..c];
    let iv = &ct[c..c + 16];
    c += 16;
    let ct_tag = &ct[c..];

    let mut key = Zeroizing::new([0u8; 32]);
    pbkdf2_hmac::<Sha512>(pw, salt, iter, key.as_mut_slice());
    let cipher = Aes256Gcm16::new_from_slice(key.as_slice()).map_err(|_| anyhow!("bad key length"))?;
    let nonce = Nonce::<U16>::from_slice(iv);
    let pt = cipher
        .decrypt(nonce, Payload { msg: ct_tag, aad: header })
        .map_err(|_| anyhow!("decryption failed — wrong wallet password, or corrupt data"))?;
    Ok(Zeroizing::new(pt))
}

/// OpenSSL EVP_BytesToKey (MD5, 1 iteration) — what CryptoJS uses for string passwords.
fn evp_kdf(pw: &[u8], salt: &[u8], key_len: usize, iv_len: usize) -> (Vec<u8>, Vec<u8>) {
    let mut d: Vec<u8> = Vec::new();
    let mut prev: Vec<u8> = Vec::new();
    while d.len() < key_len + iv_len {
        let mut h = Md5::new();
        h.update(&prev);
        h.update(pw);
        h.update(salt);
        prev = h.finalize().to_vec();
        d.extend_from_slice(&prev);
    }
    (d[..key_len].to_vec(), d[key_len..key_len + iv_len].to_vec())
}

/// v2: entropy = "Salted__" | salt(8) | ciphertext ; AES-256-CBC, PKCS7.
fn v2_decrypt(entropy: &[u8], password: &str) -> Result<Zeroizing<Vec<u8>>> {
    if entropy.len() < 16 || &entropy[0..8] != b"Salted__" {
        bail!("v2: missing Salted__ header");
    }
    let salt = &entropy[8..16];
    let body = &entropy[16..];
    let (key, iv) = evp_kdf(password.as_bytes(), salt, 32, 16);
    let pt = Aes256CbcDec::new_from_slices(&key, &iv)
        .map_err(|_| anyhow!("bad key/iv"))?
        .decrypt_padded_vec_mut::<Pkcs7>(body)
        .map_err(|_| anyhow!("decryption failed — wrong wallet password, or corrupt data"))?;
    Ok(Zeroizing::new(pt))
}

pub struct Seeds {
    pub primary: Zeroizing<Vec<u8>>,
    pub backup: Zeroizing<Vec<u8>>,
}

fn req<'a>(o: &'a Option<String>, name: &str) -> Result<&'a str> {
    o.as_deref().ok_or_else(|| anyhow!("missing {name}"))
}

/// Decrypt/derive the primary and backup HD seeds for the wallet version.
pub fn derive_seeds(bd: &Backup) -> Result<Seeds> {
    match bd.wallet_version {
        1 => {
            let primary = mnemonic_to_seed(
                req(&bd.primary_mnemonic, "primaryMnemonic")?,
                bd.primary_passphrase.as_deref().unwrap_or(""),
            )?;
            let backup = mnemonic_to_seed(req(&bd.backup_mnemonic, "backupMnemonic")?, "")?;
            Ok(Seeds { primary: Zeroizing::new(primary), backup: Zeroizing::new(backup) })
        }
        2 => {
            let pw = req(&bd.password, "password")?;
            let secret = v2_decrypt(
                &mnemonic_to_entropy(req(&bd.password_encrypted_secret_mnemonic, "passwordEncryptedSecretMnemonic")?)?,
                pw,
            )?;
            let secret_str = String::from_utf8(secret.to_vec()).map_err(|_| anyhow!("secret not valid UTF-8"))?;
            let prim_plain = v2_decrypt(
                &mnemonic_to_entropy(req(&bd.encrypted_primary_mnemonic, "encryptedPrimaryMnemonic")?)?,
                &secret_str,
            )?;
            let prim_str = String::from_utf8(prim_plain.to_vec()).map_err(|_| anyhow!("primary not valid UTF-8"))?;
            let primary = B64.decode(prim_str.trim()).map_err(|_| anyhow!("primary not valid base64"))?;
            let backup = mnemonic_to_entropy(req(&bd.backup_mnemonic, "backupMnemonic")?)?;
            Ok(Seeds { primary: Zeroizing::new(primary), backup: Zeroizing::new(backup) })
        }
        3 => {
            let pw = req(&bd.password, "password")?;
            let secret = v3_decrypt(
                &enc_mnem_decode(req(&bd.password_encrypted_secret_mnemonic, "passwordEncryptedSecretMnemonic")?)?,
                pw.as_bytes(),
            )?;
            let primary = v3_decrypt(
                &enc_mnem_decode(req(&bd.encrypted_primary_mnemonic, "encryptedPrimaryMnemonic")?)?,
                secret.as_slice(),
            )?;
            let backup = mnemonic_to_entropy(req(&bd.backup_mnemonic, "backupMnemonic")?)?;
            Ok(Seeds { primary: Zeroizing::new(primary.to_vec()), backup: Zeroizing::new(backup) })
        }
        v => bail!("unsupported walletVersion {v}"),
    }
}
