# blocktrail-recover

Offline command-line recovery of a **BlockTrail (BTC.com) 2-of-3 P2SH** wallet.
Reconstructs your keys from your backup PDF + password and prints a
[Sparrow](https://sparrowwallet.com) **descriptor**, sample **addresses**, and the two
**signing keys** (xprvs). You then import those into Sparrow to move your coins.

No network access. Secrets are held in zeroizing buffers and wiped on exit.

## Run it

Requires a Rust toolchain (install once from [rustup.rs](https://rustup.rs)):

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh   # then restart your terminal
```

Then, in the project folder:

```bash
cargo build --release                              # compiles the tool
./target/release/blocktrail-recover verify         # should print: verify: PASS
./target/release/blocktrail-recover recover backup.txt
```

`backup.txt` ships pre-filled as a **testnet demo**, so that last command works immediately —
you should see the first receive address `2NFLXEc5m1X2Z8NB5QTVd9KJtN8bJBqz1Xp`. Once you've
seen it work, edit `backup.txt` with your own details and set `testnet = false`.

(You can also run without building: `cargo run --release -- recover backup.txt`.)

## Usage

```
blocktrail-recover recover backup.txt                 # from your input file
blocktrail-recover recover --stdin                    # read the same format from stdin
blocktrail-recover recover backup.txt --addresses 20  # print more addresses to check
blocktrail-recover recover backup.txt --json          # machine-readable output
blocktrail-recover recover backup.txt --sparrow-file wallet.txt   # save the descriptor to a file
blocktrail-recover verify                             # run the built-in test vector
```

The default output is a short, ordered guide for [Sparrow](https://sparrowwallet.com):
**Configure Wallet** (paste the descriptor), **Import Keys** (add your two private keys to the
matching keystores), **Verify Addresses**, **Send**.

> Sparrow converts a pasted private-key descriptor to watch-only, so the two private keys are
> added per keystore rather than embedded in the descriptor — that's why there's an import
> step. `--sparrow-file` just saves the (watch-only) descriptor so you can import from a file.

### The input file (`backup.txt`)

Plain `name = value`, one per line — **no quotes, no commas**. Lines starting with `#` are
comments. This avoids the usual JSON hand-editing pitfalls (smart quotes, missing commas).

```
testnet = false
version = 3
password = your wallet password
encrypted_primary = … words from your PDF (one line) …
password_encrypted_secret = … words from your PDF (one line) …
backup = … words from your PDF (one line) …
key 0 = xpub…
key 9999 = xpub…
```

For **version 1** wallets, replace the `encrypted_primary` / `password_encrypted_secret` lines
with `primary = …` and `primary_passphrase = …`. Add whichever `key <index>` lines your PDF
lists; the tool prints a block per key and you use the one whose addresses match your history.

> **Check before you spend.** Confirm a printed address matches one from your old wallet's
> history. If it matches, the recovery is correct.

## Security

- **No network.** There are no networking crates in the dependency tree
  (`cargo tree` shows none) — the binary cannot phone home. Verify with a network
  sandbox or `strace -e trace=network` if you like; it makes zero socket calls.
- **Memory hygiene.** Seeds and private keys live in `zeroize::Zeroizing` buffers and are
  wiped when dropped, rather than lingering on the heap.
- **Air-gappable.** One static binary; copy it to an offline machine and run it.
- Unofficial recovery software, provided as-is. Read the source before trusting it with funds.

## Correctness & reproducibility

- `blocktrail-recover verify` (and `cargo test`) derive a known BlockTrail **testnet** wallet
  and assert the result equals the address BlockTrail's own SDK produces
  (`2NFLXEc5m1X2Z8NB5QTVd9KJtN8bJBqz1Xp`). If that passes, the decryption and derivation are
  correct end to end.
- Dependencies are pinned by the committed **`Cargo.lock`**; `cargo build --locked` /
  `cargo test --locked` install identical versions.
- Bitcoin primitives come from [`rust-bitcoin`](https://github.com/rust-bitcoin/rust-bitcoin)
  (BIP32, secp256k1, script/address); decryption from the RustCrypto crates
  (`aes-gcm`, `cbc`, `pbkdf2`, `sha2`, `md-5`). The BlockTrail-specific logic is in
  `src/decrypt.rs` (two-layer decrypt) and `src/derive.rs` (paths + `sortedmulti` P2SH) —
  the parts to audit.

## What it does (for auditors)

1. `decrypt.rs` — undoes BlockTrail's encryption: v3 = PBKDF2-SHA512 → AES-256-GCM
   (16-byte IV, header as AAD, `0x81` padding strip); v2 = OpenSSL `EVP_BytesToKey`(MD5) →
   AES-256-CBC; v1 = standard BIP39 seed. Oversized "encrypted mnemonics" are decoded
   manually (standard BIP39 libraries reject their non-standard length).
2. `derive.rs` — BIP32 with BlockTrail's asymmetric paths (primary `m/<index>'` hardened,
   backup `m/<index>` un-hardened), then a 2-of-3 BIP67 `sortedmulti` wrapped in P2SH,
   producing the descriptor + addresses + master xprvs.

## License

MIT — see [LICENSE](LICENSE).
