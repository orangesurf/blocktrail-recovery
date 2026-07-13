//! blocktrail-recover — offline CLI. No network code exists in this binary.
use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::io::Read;

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
    /// Recover from your input file (see backup.txt), or --stdin. Prints the Sparrow steps.
    Recover {
        /// Path to your recovery file, e.g. backup.txt ("-" reads stdin)
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
        /// Write the signable descriptor(s) to a file for one-step Sparrow import (SECRET file)
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
            let data = if stdin || file.as_deref() == Some("-") {
                let mut s = String::new();
                std::io::stdin().read_to_string(&mut s)?;
                s
            } else {
                let p = file.context("give a backup.json path, or use --stdin")?;
                std::fs::read_to_string(&p).with_context(|| format!("reading {p}"))?
            };
            let bd = blocktrail_recover::config::parse(&data).context("reading recovery file")?;
            let out = generate(&bd, addresses).context("recovery failed")?;
            let written = match sparrow_file.as_deref() {
                Some(path) => write_sparrow_file(&out, path)?,
                None => vec![],
            };
            if json {
                println!("{}", serde_json::to_string_pretty(&out)?);
            } else {
                print_human(&out);
                if !written.is_empty() {
                    println!("Signable descriptor written (SECRET — import into Sparrow, then delete):");
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
    if o.keys.len() > 1 {
        println!("More than one BlockTrail key was provided. Use the block whose first");
        println!("receive address matches your old wallet; ignore the other.\n");
    }
    for k in &o.keys {
        let bar = "═".repeat(74);
        println!("{bar}");
        println!("  KEY INDEX {}   ·   follow these steps in Sparrow, in order", k.key_index);
        println!("{bar}");

        println!("\n  CONFIGURE WALLET");
        println!("    New Wallet (give it any name). On the Settings tab, set:");
        println!("      Policy Type    Multi Signature HD");
        println!("      Script Type    Legacy (HD)");
        println!("      Descriptor     click [Edit], select the existing text and delete it,");
        println!("                     paste the line below, click [OK]\n");
        println!("      {}\n", k.descriptor);

        println!("  IMPORT KEYS                                   [ SECRET — keep private ]");
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

        println!("  VERIFY ADDRESSES");
        println!("    Open the Addresses page. Confirm the first receive address is:\n");
        println!("      {}\n", k.receive[0]);

        println!("  SEND");
        println!("    Use the Send page as normal to move your funds.\n");
    }
}

/// Write the watch-only descriptor(s) to disk, to import into Sparrow from a file.
/// One key -> the given path. Multiple keys -> one file per key index (<stem>-key<N><ext>).
fn write_sparrow_file(o: &Output, path: &str) -> Result<Vec<String>> {
    use std::path::Path;
    let mut written = Vec::new();
    if o.keys.len() == 1 {
        std::fs::write(path, format!("{}\n", o.keys[0].descriptor))
            .with_context(|| format!("writing {path}"))?;
        written.push(path.to_string());
    } else {
        let p = Path::new(path);
        let stem = p.file_stem().and_then(|s| s.to_str()).unwrap_or("wallet");
        let ext = p
            .extension()
            .and_then(|s| s.to_str())
            .map(|e| format!(".{e}"))
            .unwrap_or_default();
        let dir = p.parent().filter(|d| !d.as_os_str().is_empty());
        for k in &o.keys {
            let name = format!("{stem}-key{}{ext}", k.key_index);
            let fp = match dir {
                Some(d) => d.join(&name),
                None => Path::new(&name).to_path_buf(),
            };
            std::fs::write(&fp, format!("{}\n", k.descriptor))
                .with_context(|| format!("writing {}", fp.display()))?;
            written.push(fp.display().to_string());
        }
    }
    Ok(written)
}

fn verify() -> Result<()> {
    let json = r#"{
        "testnet": true, "walletVersion": 3,
        "encryptedPrimaryMnemonic": "library fish steak unfair series jacket enhance unique witness session abandon ability hole spread black stuff gun country icon hair sugar mixture rib mansion neglect afraid unlock barrel today misery shift replace unusual ticket zone habit aspect globe glad find space tape remove priority describe smart annual sign direct regular can pear huge rather wish travel stomach mobile situate stand",
        "passwordEncryptedSecretMnemonic": "library faith derive beach blast sustain index fold actor session abandon access forest around canal theme body denial excuse believe voyage anchor state meadow assist ostrich trick lock near uniform suspect person autumn dentist rent square idle motion calm time focus help legal subject quality pupil atom weather start kite enable today primary rail flag clarify clarify syrup fee clump",
        "backupMnemonic": "snap lyrics december view youth dynamic physical shed certain govern cigar top submit measure minute flight used glass tragic basket alarm scorpion wagon oblige",
        "password": "roobsieroobs",
        "blocktrailKeys": [{"keyIndex": 9999, "pubkey": "tpubD9q6vq9zdP3gbhpjs7n2TRvT7h4PeBhxg1Kv9jEc1XAss7429VenxvQTsJaZhzTk54gnsHRpgeeNMbm1QTag4Wf1QpQ3gy221GDuUCxgfeZ"}]
    }"#;
    let bd: Backup = serde_json::from_str(json)?;
    let out = generate(&bd, 1)?;
    let got = &out.keys[0].receive[0];
    let want = "2NFLXEc5m1X2Z8NB5QTVd9KJtN8bJBqz1Xp";
    if got == want {
        println!("verify: PASS  (key 9999 receive[0] = {got})");
        Ok(())
    } else {
        eprintln!("verify: FAIL  got {got}, want {want}");
        std::process::exit(1);
    }
}
