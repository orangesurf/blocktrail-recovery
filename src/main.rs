//! blocktrail-recover — offline CLI. No network code exists in this binary.
use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::io::Read;
use zeroize::{Zeroize, Zeroizing};

use blocktrail_recover::backup::Backup;
use blocktrail_recover::{generate, Output};

#[derive(Parser)]
#[command(name = "blocktrail-recover", version, about = "Recover a BlockTrail 2-of-3 P2SH wallet, offline.")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Recover from your input file (see backup.example.txt), or --stdin. Prints the Sparrow steps.
    Recover {
        /// Path to your recovery file, e.g. backup.txt (copy of backup.example.txt; "-" reads stdin)
        file: Option<String>,
        /// Read backup JSON from stdin instead of a file
        #[arg(long)]
        stdin: bool,
        /// How many sample addresses per chain to print
        #[arg(long, default_value_t = 3)]
        addresses: u32,
        /// Emit machine-readable JSON instead of text
        #[arg(long)]
        json: bool,
        /// Write the watch-only descriptor(s) to a file to import into Sparrow (xpubs only — no private keys)
        #[arg(long, value_name = "PATH")]
        sparrow_file: Option<String>,
    },
    /// Run the built-in test vector and report pass/fail (proves this binary is correct).
    Verify,
}

fn main() -> Result<()> {
    match Cli::parse().cmd {
        Cmd::Verify => verify(),
        Cmd::Recover { file, stdin, addresses, json, sparrow_file } => {
            // The input holds the password and every mnemonic — keep it in a
            // buffer that is wiped on drop rather than a plain String.
            let data = Zeroizing::new(if stdin || file.as_deref() == Some("-") {
                let mut s = String::new();
                std::io::stdin().read_to_string(&mut s)?;
                s
            } else {
                let p = file.context("give a backup file path, or use --stdin")?;
                std::fs::read_to_string(&p).with_context(|| format!("reading {p}"))?
            });
            let bd = blocktrail_recover::config::parse(&data).context("reading recovery file")?;
            let out = generate(&bd, addresses).context("recovery failed")?;
            let written = match sparrow_file.as_deref() {
                Some(path) => write_sparrow_file(&out, path)?,
                None => vec![],
            };
            if json {
                let mut s = serde_json::to_string_pretty(&out)?;
                println!("{s}");
                s.zeroize();
            } else {
                print_human(&out);
                if !written.is_empty() {
                    println!("Watch-only descriptor(s) written (xpubs only — no private keys;");
                    println!("they reveal your addresses, so keep them private):");
                    for p in &written {
                        println!("    {p}");
                    }
                    println!();
                }
            }
            Ok(())
        }
    }
}

fn print_human(o: &Output) {
    println!("\nBlockTrail recovery  —  network: {}\n", o.network);
    println!("A BlockTrail wallet can hold coins as LEGACY (P2SH) and/or nested SEGWIT");
    println!("(P2SH-P2WSH). Wallets from before ~mid-2018 are legacy-only; later ones keep");
    println!("their main funds on the SegWit chain. Check BOTH — import whichever wallet(s)");
    println!("have addresses matching your history. Within each, receive and change share");
    println!("one address chain, so the address list covers both.\n");
    if o.keys.len() > 1 {
        println!("More than one BlockTrail key was provided. Use the key index whose");
        println!("addresses match your old wallet; ignore the others.\n");
    }
    for k in &o.keys {
        let bar = "═".repeat(74);
        println!("{bar}");
        println!("  KEY INDEX {}   ·   follow these steps in Sparrow, in order", k.key_index);
        println!("{bar}");

        for (label, script_type, w) in [
            ("LEGACY", "Legacy (HD)", &k.legacy),
            ("SEGWIT", "Nested Segwit (P2SH-P2WSH)", &k.segwit),
        ] {
            println!("\n  ── {label} WALLET ──────────────────────────────────────────────────────");
            println!("\n  CONFIGURE WALLET");
            println!("    New Wallet (give it any name). On the Settings tab, set:");
            println!("      Policy Type    Multi Signature HD");
            println!("      Script Type    {script_type}");
            println!("      Descriptor     click [Edit], select the existing text and delete it,");
            println!("                     paste the line below, click [OK]\n");
            println!("      {}\n", w.descriptor);
            println!("    First few {label} addresses (confirm one matches your history):");
            for (i, a) in w.addresses.iter().enumerate() {
                println!("      {i}: {a}");
            }
            println!();
        }

        println!("  IMPORT KEYS   (same two keys for whichever wallet you kept above)");
        println!("                                                [ SECRET — keep private ]");
        println!("    Two keystores need a private key. For EACH one:");
        println!("      [Import] → Software Wallet → Master Private Key → [Enter Private Key]");
        println!("      → paste the key → [Import] → leave the path → [Import Keystore]\n");
        println!("      Keystore {}  (primary)", o.fpr_primary);
        println!("        key    {}", o.primary_xprv);
        println!("        path   m/{}'      (leave as shown)\n", k.key_index);
        println!("      Keystore {}  (backup)", o.fpr_backup);
        println!("        key    {}", o.backup_xprv);
        println!("        path   m/{}       (leave as shown — no apostrophe)\n", k.key_index);
        println!("    Leave the third keystore ({}, BlockTrail) untouched.", k.fpr_blocktrail);
        println!("    Click [Apply].  Optionally set a password and save the descriptor PDF.\n");

        println!("  SEND");
        println!("    Once an address matches and Sparrow shows your balance, use the Send");
        println!("    page to move your funds.\n");
    }
}

/// Write the watch-only descriptors to disk, to import into Sparrow from a file.
/// One file per (key index, script type): `<stem>-key<N>-legacy<ext>` and `-segwit`.
/// Files are created 0600 — they are xpub-only, but xpubs still reveal your addresses.
fn write_sparrow_file(o: &Output, path: &str) -> Result<Vec<String>> {
    use std::path::Path;
    let p = Path::new(path);
    let stem = p.file_stem().and_then(|s| s.to_str()).unwrap_or("wallet");
    let ext = p
        .extension()
        .and_then(|s| s.to_str())
        .map(|e| format!(".{e}"))
        .unwrap_or_default();
    let dir = p.parent().filter(|d| !d.as_os_str().is_empty());

    let mut written = Vec::new();
    for k in &o.keys {
        for (kind, w) in [("legacy", &k.legacy), ("segwit", &k.segwit)] {
            let name = format!("{stem}-key{}-{kind}{ext}", k.key_index);
            let fp = match dir {
                Some(d) => d.join(&name),
                None => Path::new(&name).to_path_buf(),
            };
            std::fs::write(&fp, format!("{}\n", w.descriptor))
                .with_context(|| format!("writing {}", fp.display()))?;
            harden_perms(&fp);
            written.push(fp.display().to_string());
        }
    }
    Ok(written)
}

/// Best-effort chmod 0600. A failure here is not fatal — the descriptor is watch-only.
#[cfg(unix)]
fn harden_perms(p: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o600));
}
#[cfg(not(unix))]
fn harden_perms(_p: &std::path::Path) {}

/// (human label, closure picking the address from a key block, expected value)
type Check = (&'static str, fn(&blocktrail_recover::KeyBlock) -> &str, &'static str);

/// One self-test: derive a known wallet and compare a chain/index address to the value
/// BlockTrail's own SDK produces. `key_index` selects which key block to read.
struct Case {
    name: &'static str,
    json: &'static str,
    key_index: u32,
    checks: &'static [Check],
}

fn verify() -> Result<()> {
    // Vectors from BlockTrail's official SDK (wallet_recovery_example.js and the shipped
    // testnet demo). Covering v1, v2 (mainnet) and v3 (legacy + segwit) means a green
    // `verify` actually exercises every decryption path and both networks.
    let cases = [
        Case {
            name: "v1 testnet (48-word mnemonic)",
            json: r#"{"testnet": true, "walletVersion": 1,
                "primaryMnemonic": "plug employ detail flee ethics junior cover surround aspect slender venue faith devote ice sword camp pepper baby decrease mushroom feel endless cactus group deposit achieve cheese fire alone size enlist sail labor pulp venture wet gas object fruit dutch industry lend glad category between hidden april network",
                "primaryPassphrase": "test",
                "backupMnemonic": "disorder husband build smart also alley uncle buffalo scene club reduce fringe assault inquiry damage gravity receive champion coffee awesome conduct two mouse wisdom super lend dice toe emotion video analyst worry charge sleep bless pride motion oxygen congress jewel push bag ozone approve enroll valley picnic flight",
                "blocktrailKeys": [{"keyIndex": 9999, "pubkey": "tpubD9q6vq9zdP3gbhpjs7n2TRvT7h4PeBhxg1Kv9jEc1XAss7429VenxvQTsJaZhzTk54gnsHRpgeeNMbm1QTag4Wf1QpQ3gy221GDuUCxgfeZ"}]}"#,
            key_index: 9999,
            checks: &[("legacy /0/0", |k| k.legacy.addresses[0].as_str(), "2NEVKJeVJeNiwcXwbmSDuVNX1jkZkVbSBxP")],
        },
        Case {
            name: "v2 mainnet",
            json: r#"{"testnet": false, "walletVersion": 2,
                "encryptedPrimaryMnemonic": "fat arena brown skull echo quiz diesel beach gift olympic riot orphan sketch chief exchange height danger nasty clutch dune wing run drastic roast exist super toddler combine vault salute salad trap spider tenant draw million insane alley pelican spot alpha cheese version clog arm tomorrow slush plunge",
                "passwordEncryptedSecretMnemonic": "fat arena brown skull echo quick damage toe later above jewel life void despair outer model annual various original stool answer vessel tired fragile visa summer step dash inform unit member social liberty valve tonight ocean pretty dial ability special angry like ancient unit shiver safe hospital ocean around poet album split they random decide ginger guilt mix evolve click avoid oven sad gospel worry chaos another lonely essence lucky health view",
                "backupMnemonic": "aerobic breeze taste swear whip service bone siege tackle grow drip few tray clay crumble glass athlete bronze office roast learn tuition exist symptom",
                "password": "test",
                "blocktrailKeys": [{"keyIndex": 0, "pubkey": "xpub687DeMmb3SM2WUySJREg6F2vvRCQE1uSHcm5DY6HKyJe5oCczqavKHWUS8e5hDdx5bU4EWzFq9vSRSbi2rEYShdw6ectgbxAqmBgg8ZaqtC"}]}"#,
            key_index: 0,
            checks: &[("legacy /0/0", |k| k.legacy.addresses[0].as_str(), "342RpXeWgJdjnvCiEMGvBaSn1Yncq8qqCg")],
        },
        Case {
            name: "v3 testnet (legacy + segwit)",
            json: r#"{"testnet": true, "walletVersion": 3,
                "encryptedPrimaryMnemonic": "library fish steak unfair series jacket enhance unique witness session abandon ability hole spread black stuff gun country icon hair sugar mixture rib mansion neglect afraid unlock barrel today misery shift replace unusual ticket zone habit aspect globe glad find space tape remove priority describe smart annual sign direct regular can pear huge rather wish travel stomach mobile situate stand",
                "passwordEncryptedSecretMnemonic": "library faith derive beach blast sustain index fold actor session abandon access forest around canal theme body denial excuse believe voyage anchor state meadow assist ostrich trick lock near uniform suspect person autumn dentist rent square idle motion calm time focus help legal subject quality pupil atom weather start kite enable today primary rail flag clarify clarify syrup fee clump",
                "backupMnemonic": "snap lyrics december view youth dynamic physical shed certain govern cigar top submit measure minute flight used glass tragic basket alarm scorpion wagon oblige",
                "password": "roobsieroobs",
                "blocktrailKeys": [{"keyIndex": 9999, "pubkey": "tpubD9q6vq9zdP3gbhpjs7n2TRvT7h4PeBhxg1Kv9jEc1XAss7429VenxvQTsJaZhzTk54gnsHRpgeeNMbm1QTag4Wf1QpQ3gy221GDuUCxgfeZ"}]}"#,
            key_index: 9999,
            checks: &[
                ("legacy /0/0", |k| k.legacy.addresses[0].as_str(), "2NFLXEc5m1X2Z8NB5QTVd9KJtN8bJBqz1Xp"),
                ("segwit /2/0", |k| k.segwit.addresses[0].as_str(), "2N68bVxLgfJRmPEwguJHhSMRJke8Z4RBqE6"),
            ],
        },
    ];

    let mut ok = true;
    for case in &cases {
        let bd: Backup = serde_json::from_str(case.json)?;
        let out = generate(&bd, 1)?;
        let k = out
            .keys
            .iter()
            .find(|k| k.key_index == case.key_index)
            .expect("key index present in vector");
        for (label, pick, want) in case.checks {
            let got = pick(k);
            if got == *want {
                println!("verify: PASS  [{}] {label} = {got}", case.name);
            } else {
                eprintln!("verify: FAIL  [{}] {label}: got {got}, want {want}", case.name);
                ok = false;
            }
        }
    }
    if ok {
        println!("\nverify: all vectors passed (v1, v2, v3; legacy + segwit; testnet + mainnet).");
        Ok(())
    } else {
        std::process::exit(1);
    }
}
