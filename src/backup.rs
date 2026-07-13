use serde::{Deserialize, Serialize};

#[derive(Deserialize, Clone)]
pub struct Backup {
    #[serde(default)] pub testnet: Option<bool>,
    #[serde(rename = "walletVersion")] pub wallet_version: u32,
    #[serde(rename = "primaryMnemonic", default)] pub primary_mnemonic: Option<String>,
    #[serde(rename = "primaryPassphrase", default)] pub primary_passphrase: Option<String>,
    #[serde(rename = "encryptedPrimaryMnemonic", default)] pub encrypted_primary_mnemonic: Option<String>,
    #[serde(rename = "passwordEncryptedSecretMnemonic", default)] pub password_encrypted_secret_mnemonic: Option<String>,
    #[serde(rename = "backupMnemonic", default)] pub backup_mnemonic: Option<String>,
    #[serde(default)] pub password: Option<String>,
    #[serde(rename = "blocktrailKeys")] pub blocktrail_keys: Vec<BlocktrailKey>,
}

#[derive(Deserialize, Serialize, Clone)]
pub struct BlocktrailKey {
    #[serde(rename = "keyIndex")] pub key_index: u32,
    pub pubkey: String,
}
