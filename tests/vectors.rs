use blocktrail_recover::{backup::Backup, config, generate};

fn testnet_v3() -> Backup {
    serde_json::from_str(r#"{
        "testnet": true, "walletVersion": 3,
        "encryptedPrimaryMnemonic": "library fish steak unfair series jacket enhance unique witness session abandon ability hole spread black stuff gun country icon hair sugar mixture rib mansion neglect afraid unlock barrel today misery shift replace unusual ticket zone habit aspect globe glad find space tape remove priority describe smart annual sign direct regular can pear huge rather wish travel stomach mobile situate stand",
        "passwordEncryptedSecretMnemonic": "library faith derive beach blast sustain index fold actor session abandon access forest around canal theme body denial excuse believe voyage anchor state meadow assist ostrich trick lock near uniform suspect person autumn dentist rent square idle motion calm time focus help legal subject quality pupil atom weather start kite enable today primary rail flag clarify clarify syrup fee clump",
        "backupMnemonic": "snap lyrics december view youth dynamic physical shed certain govern cigar top submit measure minute flight used glass tragic basket alarm scorpion wagon oblige",
        "password": "roobsieroobs",
        "blocktrailKeys": [
            {"keyIndex": 0, "pubkey": "tpubD8UrAbbGkiJUnPP85sYJZ6ozSsgfk4qH9jbzWFMUGhfsgKPEzLLpNvgkFm9P4ktkAbPpX1ACns2PdfBT8ZF9vFjaU5GKQCZ892AJSJ2VgDK"},
            {"keyIndex": 9999, "pubkey": "tpubD9q6vq9zdP3gbhpjs7n2TRvT7h4PeBhxg1Kv9jEc1XAss7429VenxvQTsJaZhzTk54gnsHRpgeeNMbm1QTag4Wf1QpQ3gy221GDuUCxgfeZ"}
        ]
    }"#).unwrap()
}

/// Legacy (chain 0) P2SH addresses — the historically-verified SDK vector.
#[test]
fn key_9999_legacy_addresses_match_sdk() {
    let out = generate(&testnet_v3(), 3).unwrap();
    let k = out.keys.iter().find(|k| k.key_index == 9999).unwrap();
    assert_eq!(k.legacy.addresses[0], "2NFLXEc5m1X2Z8NB5QTVd9KJtN8bJBqz1Xp");
    assert_eq!(k.legacy.addresses[1], "2N3D7TTVsjrqrkCqT1sE5rqD8fJWCe8NAGh");
    assert_eq!(k.legacy.addresses[2], "2MwRLGFGu5Voip2fGZyChznVPXrnA158Pxm");
}

/// Nested SegWit (chain 2) P2SH-P2WSH addresses — cross-checked against BlockTrail's SDK.
#[test]
fn key_9999_segwit_addresses_match_sdk() {
    let out = generate(&testnet_v3(), 3).unwrap();
    let k = out.keys.iter().find(|k| k.key_index == 9999).unwrap();
    assert_eq!(k.segwit.addresses[0], "2N68bVxLgfJRmPEwguJHhSMRJke8Z4RBqE6");
    assert_eq!(k.segwit.addresses[1], "2Mvm5pgb4HzjvvtrBaVi3adkF5BS8nfe3eX");
    assert_eq!(k.segwit.addresses[2], "2NBgkeuACoz2uMDVQD45Rv8jiTjouoNsmvt");
}

/// v1 wallet: BlockTrail's 512-bit / 48-word mnemonics (rejected by the standard BIP39
/// parser before this fix). Vector from the official SDK wallet_recovery_example.js.
#[test]
fn v1_48word_mnemonic_matches_sdk() {
    let bd: Backup = serde_json::from_str(r#"{
        "testnet": true, "walletVersion": 1,
        "primaryMnemonic": "plug employ detail flee ethics junior cover surround aspect slender venue faith devote ice sword camp pepper baby decrease mushroom feel endless cactus group deposit achieve cheese fire alone size enlist sail labor pulp venture wet gas object fruit dutch industry lend glad category between hidden april network",
        "primaryPassphrase": "test",
        "backupMnemonic": "disorder husband build smart also alley uncle buffalo scene club reduce fringe assault inquiry damage gravity receive champion coffee awesome conduct two mouse wisdom super lend dice toe emotion video analyst worry charge sleep bless pride motion oxygen congress jewel push bag ozone approve enroll valley picnic flight",
        "blocktrailKeys": [
            {"keyIndex": 9999, "pubkey": "tpubD9q6vq9zdP3gbhpjs7n2TRvT7h4PeBhxg1Kv9jEc1XAss7429VenxvQTsJaZhzTk54gnsHRpgeeNMbm1QTag4Wf1QpQ3gy221GDuUCxgfeZ"}
        ]
    }"#).unwrap();
    let out = generate(&bd, 1).unwrap();
    let k = out.keys.iter().find(|k| k.key_index == 9999).unwrap();
    assert_eq!(k.legacy.addresses[0], "2NEVKJeVJeNiwcXwbmSDuVNX1jkZkVbSBxP");
    assert_eq!(out.primary_xprv, "tprv8ZgxMBicQKsPf45wX7BncHixEXraXSKjEYvNehGr4xMRDnQKoUXCLZdbKZ4bKP9onoyojKbtrwTx3e5QzcjTfSj6CsDkQfnGhNg3umfJw9o");
    assert_eq!(out.backup_xprv, "tprv8ZgxMBicQKsPdmtqjdfDRZWVUYuuL1qoej6UaSYZmhpXYndEyvW3uQP2FsnRhvfjXSSgMhvoKk3cdxHHkBsjrngfvt62hk8fQV7KHpD2Xhy");
}

/// v2 wallet on MAINNET (EVP_BytesToKey + AES-256-CBC). Vector from the official SDK.
#[test]
fn v2_mainnet_matches_sdk() {
    let bd: Backup = serde_json::from_str(r#"{
        "testnet": false, "walletVersion": 2,
        "encryptedPrimaryMnemonic": "fat arena brown skull echo quiz diesel beach gift olympic riot orphan sketch chief exchange height danger nasty clutch dune wing run drastic roast exist super toddler combine vault salute salad trap spider tenant draw million insane alley pelican spot alpha cheese version clog arm tomorrow slush plunge",
        "passwordEncryptedSecretMnemonic": "fat arena brown skull echo quick damage toe later above jewel life void despair outer model annual various original stool answer vessel tired fragile visa summer step dash inform unit member social liberty valve tonight ocean pretty dial ability special angry like ancient unit shiver safe hospital ocean around poet album split they random decide ginger guilt mix evolve click avoid oven sad gospel worry chaos another lonely essence lucky health view",
        "backupMnemonic": "aerobic breeze taste swear whip service bone siege tackle grow drip few tray clay crumble glass athlete bronze office roast learn tuition exist symptom",
        "password": "test",
        "blocktrailKeys": [
            {"keyIndex": 0, "pubkey": "xpub687DeMmb3SM2WUySJREg6F2vvRCQE1uSHcm5DY6HKyJe5oCczqavKHWUS8e5hDdx5bU4EWzFq9vSRSbi2rEYShdw6ectgbxAqmBgg8ZaqtC"}
        ]
    }"#).unwrap();
    let out = generate(&bd, 1).unwrap();
    assert_eq!(out.network, "mainnet");
    let k = out.keys.iter().find(|k| k.key_index == 0).unwrap();
    assert_eq!(k.legacy.addresses[0], "342RpXeWgJdjnvCiEMGvBaSn1Yncq8qqCg");
    assert_eq!(out.primary_xprv, "xprv9s21ZrQH143K3wQ8MeY3EmVP9gUHDF1iY1v3nLT1fyYzw4JgZKLbVjutpKzRGLAuypQhhRc3fLiUtTEfjLwM7TtD4srnfnmuBGmvdu27gM2");
    assert_eq!(out.backup_xprv, "xprv9s21ZrQH143K4KnT6rVFK7GhYDrXZZvbhrCdkZ8c5tBFtJ15rVyWKo4nHeZYPJuTQvBykbUhSxM6qYnEELXChymAEPNLakEKwJ1P7d1jdoR");
}

/// The legacy and segwit descriptors must be distinct script types on the right chains.
#[test]
fn descriptors_have_expected_shape() {
    let out = generate(&testnet_v3(), 1).unwrap();
    let k = out.keys.iter().find(|k| k.key_index == 9999).unwrap();
    assert!(k.legacy.descriptor.starts_with("sh(sortedmulti(2,"));
    assert!(k.legacy.descriptor.contains("/0/*"));
    assert!(k.segwit.descriptor.starts_with("sh(wsh(sortedmulti(2,"));
    assert!(k.segwit.descriptor.contains("/2/*"));
    // Chain 1 (Bitcoin Cash) must never appear.
    assert!(!k.legacy.descriptor.contains("/1/*"));
    assert!(!k.segwit.descriptor.contains("/1/*"));
}

#[test]
fn wrong_password_is_rejected() {
    let mut bd = testnet_v3();
    bd.password = Some("not-the-password".into());
    assert!(generate(&bd, 1).is_err());
}

/// Regression: a normal 24-word mnemonic pasted into an encrypted-mnemonic slot must
/// return an error, not panic with an out-of-range slice (the old v3_decrypt behavior).
#[test]
fn plain_mnemonic_in_encrypted_slot_errors_gracefully() {
    let mut bd = testnet_v3();
    let plain = "snap lyrics december view youth dynamic physical shed certain govern cigar top submit measure minute flight used glass tragic basket alarm scorpion wagon oblige".to_string();
    bd.password_encrypted_secret_mnemonic = Some(plain.clone());
    bd.encrypted_primary_mnemonic = Some(plain);
    let err = match generate(&bd, 1) {
        Ok(_) => panic!("expected an error"),
        Err(e) => e,
    };
    assert!(format!("{err:#}").contains("v3"), "unexpected error: {err:#}");
}

#[test]
fn shipped_example_file_parses_and_matches() {
    // the shipped demo (backup.example.txt) must always work
    let text = include_str!("../backup.example.txt");
    let bd = config::parse(text).unwrap();
    let out = generate(&bd, 1).unwrap();
    let k = out.keys.iter().find(|k| k.key_index == 9999).unwrap();
    assert_eq!(k.legacy.addresses[0], "2NFLXEc5m1X2Z8NB5QTVd9KJtN8bJBqz1Xp");
    assert_eq!(k.segwit.addresses[0], "2N68bVxLgfJRmPEwguJHhSMRJke8Z4RBqE6");
}

#[test]
fn config_ignores_comments_and_blank_lines() {
    let bd = config::parse(
        "# a comment\n\n version = 3 \ntestnet = true\npassword = roobsieroobs\nkey 9999 = tpubD9q6vq9zdP3gbhpjs7n2TRvT7h4PeBhxg1Kv9jEc1XAss7429VenxvQTsJaZhzTk54gnsHRpgeeNMbm1QTag4Wf1QpQ3gy221GDuUCxgfeZ\nencrypted_primary = x\npassword_encrypted_secret = y\nbackup = z",
    ).unwrap();
    assert_eq!(bd.wallet_version, 3);
    assert_eq!(bd.testnet, Some(true));
    assert_eq!(bd.blocktrail_keys.len(), 1);
    assert_eq!(bd.blocktrail_keys[0].key_index, 9999);
}

/// A testnet typo must fail loudly, never silently fall back to mainnet.
#[test]
fn unrecognized_testnet_value_is_rejected() {
    // Backup intentionally has no Debug impl (it holds secrets), so match rather than unwrap_err.
    let err = match config::parse("version = 3\ntestnet = ture\nkey 0 = x\n") {
        Ok(_) => panic!("expected an error"),
        Err(e) => e,
    };
    assert!(format!("{err:#}").contains("testnet"), "unexpected: {err:#}");
}

/// A duplicated scalar setting must be rejected, not silently last-wins.
#[test]
fn duplicate_setting_is_rejected() {
    let err = match config::parse("version = 3\npassword = a\npassword = b\nkey 0 = x\n") {
        Ok(_) => panic!("expected an error"),
        Err(e) => e,
    };
    assert!(format!("{err:#}").contains("more than once"), "unexpected: {err:#}");
}
