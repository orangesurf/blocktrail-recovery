use blocktrail_recover::{backup::Backup, generate};

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

#[test]
fn key_9999_addresses_match_sdk() {
    let out = generate(&testnet_v3(), 3).unwrap();
    let k = out.keys.iter().find(|k| k.key_index == 9999).unwrap();
    assert_eq!(k.receive[0], "2NFLXEc5m1X2Z8NB5QTVd9KJtN8bJBqz1Xp");
    assert_eq!(k.receive[1], "2N3D7TTVsjrqrkCqT1sE5rqD8fJWCe8NAGh");
    assert_eq!(k.receive[2], "2MwRLGFGu5Voip2fGZyChznVPXrnA158Pxm");
    assert_eq!(k.change[0], "2NDrc3woS2ZxhpcVTiMHuQsqSe1tmE54XGm");
}

#[test]
fn wrong_password_is_rejected() {
    let mut bd = testnet_v3();
    bd.password = Some("not-the-password".into());
    assert!(generate(&bd, 1).is_err());
}


#[test]
fn shipped_example_file_parses_and_matches() {
    // the backup.txt we ship must always work as the demo
    let text = include_str!("../backup.txt");
    let bd = blocktrail_recover::config::parse(text).unwrap();
    let out = generate(&bd, 1).unwrap();
    let k = out.keys.iter().find(|k| k.key_index == 9999).unwrap();
    assert_eq!(k.receive[0], "2NFLXEc5m1X2Z8NB5QTVd9KJtN8bJBqz1Xp");
}

#[test]
fn config_ignores_comments_and_blank_lines() {
    let bd = blocktrail_recover::config::parse(
        "# a comment\n\n version = 3 \ntestnet = true\npassword = roobsieroobs\nkey 9999 = tpubD9q6vq9zdP3gbhpjs7n2TRvT7h4PeBhxg1Kv9jEc1XAss7429VenxvQTsJaZhzTk54gnsHRpgeeNMbm1QTag4Wf1QpQ3gy221GDuUCxgfeZ\nencrypted_primary = x\npassword_encrypted_secret = y\nbackup = z",
    ).unwrap();
    assert_eq!(bd.wallet_version, 3);
    assert_eq!(bd.testnet, Some(true));
    assert_eq!(bd.blocktrail_keys.len(), 1);
    assert_eq!(bd.blocktrail_keys[0].key_index, 9999);
}
