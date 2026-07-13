# blocktrail-recover

Offline command-line recovery of a **BlockTrail (BTC.com) 2-of-3** wallet (v1, v2, and v3).
Reconstructs your keys from your backup PDF + password and prints
[Sparrow](https://sparrowwallet.com) **descriptors**, sample **addresses**, and the two
**signing keys** (xprvs). You then import those into Sparrow to move your coins.

A BlockTrail wallet can hold coins under two script types — **legacy P2SH** and **nested
SegWit (P2SH-P2WSH)** — so the tool emits *both* descriptors per key index; you import
whichever one has addresses matching your history (wallets from before ~mid-2018 are
legacy-only, later ones keep their main funds on the SegWit chain).

No network access.

## Run it

Requires a Rust toolchain (install once from [rustup.rs](https://rustup.rs)):

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh   # then restart your terminal
```

Then, in the project folder:

```bash
cargo build --release                                    # compiles the tool
./target/release/blocktrail-recover verify               # should print: verify: PASS ...
./target/release/blocktrail-recover recover backup.example.txt
```

`backup.example.txt` is a **testnet demo**, so that last command works immediately — you
should see the first legacy receive address `2NFLXEc5m1X2Z8NB5QTVd9KJtN8bJBqz1Xp` and the
first SegWit address `2N68bVxLgfJRmPEwguJHhSMRJke8Z4RBqE6`.

To recover **your** wallet, copy the demo and edit the copy (never put your real seed in the
tracked example file):

```bash
cp backup.example.txt backup.txt     # backup.txt is git-ignored
# ...edit backup.txt with your PDF values, set  testnet = false ...
./target/release/blocktrail-recover recover backup.txt
```

(You can also run without building: `cargo run --release -- recover backup.txt`.)

## Usage

```
blocktrail-recover recover backup.txt                 # from your input file
blocktrail-recover recover --stdin                    # read the same format from stdin
blocktrail-recover recover backup.txt --addresses 20  # print more addresses to check
blocktrail-recover recover backup.txt --json          # machine-readable output
blocktrail-recover recover backup.txt --sparrow-file wallet.txt   # save descriptors to files
blocktrail-recover verify                             # run the built-in SDK test vectors
```

The default output is a short, ordered guide for [Sparrow](https://sparrowwallet.com), one
block per key index, with a **LEGACY** and a **SegWit** wallet inside each: **Configure
Wallet** (paste the descriptor), **Import Keys** (add your two private keys to the matching
keystores), and **Send**. Import whichever wallet(s) show addresses matching your history.

> Within each wallet, receive and change share one address chain (BlockTrail did not use a
> separate change branch), so the printed address list covers both — scan far enough in
> Sparrow and it finds every address the wallet used.

> Sparrow converts a pasted private-key descriptor to watch-only, so the two private keys are
> added per keystore rather than embedded in the descriptor — that's why there's an import
> step. `--sparrow-file` just saves the watch-only descriptors (xpubs only, one file per key
> index per script type) so you can import from a file.

### The input file (`backup.txt`)

Plain `name = value`, one per line — **no quotes, no commas**. A line whose first character
is `#` is a comment (whole-line only; a `#` later in a line is part of the value, since a
password may contain one). Everything after the first `=` is the literal value. This avoids
the usual JSON hand-editing pitfalls (smart quotes, missing commas).

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
with `primary = …` and `primary_passphrase = …` (v1 primary/backup phrases are often 48 words —
that's expected and handled). Add whichever `key <index>` lines your PDF lists; the tool prints
a block per key and you use the one whose addresses match your history.

> **Check before you spend.** Confirm a printed address matches one from your old wallet's
> history — check both the legacy and SegWit lists. If one matches, that wallet's recovery is
> correct. If none matches, do **not** send; re-check your password and keys first.

## Security

- **No network.** There are no networking crates in the dependency tree
  (`cargo tree` shows none) — the binary cannot phone home. Verify with a network
  sandbox or `strace -e trace=network` if you like; it makes zero socket calls.
- **Memory hygiene.** The input file, the decrypted seeds, and the intermediate key
  material are held in `zeroize::Zeroizing` buffers and wiped when dropped, and the exported
  xprvs are zeroized on exit. This is best-effort, not a guarantee: the tool's whole job is
  to **print** your descriptors and private keys, so once shown they live in your terminal
  scrollback — clear it, and prefer an ephemeral/air-gapped shell.
- **`backup.txt` is git-ignored.** Your real recovery input goes in `backup.txt`, which is
  excluded from git; only the testnet `backup.example.txt` is tracked. Never paste a real
  seed into the example file.
- **Air-gappable.** One static binary; copy it to an offline machine and run it.
- Unofficial recovery software, provided as-is. Read the source before trusting it with funds.

## Correctness & reproducibility

- `blocktrail-recover verify` (and `cargo test`) derive known BlockTrail wallets and assert
  the results equal the addresses (and master xprvs) BlockTrail's own SDK produces. The
  vectors cover **v1** (48-word mnemonic, testnet), **v2** (mainnet), and **v3** (testnet,
  both the legacy `2NFLXEc5m1X2Z8NB5QTVd9KJtN8bJBqz1Xp` and SegWit
  `2N68bVxLgfJRmPEwguJHhSMRJke8Z4RBqE6` chains) — i.e. every decryption path, both networks,
  and both script types. Vectors come from the official SDK's `wallet_recovery_example.js`.
- Dependencies are pinned by the committed **`Cargo.lock`**; `cargo build --locked` /
  `cargo test --locked` install identical versions.
- Bitcoin primitives come from [`rust-bitcoin`](https://github.com/rust-bitcoin/rust-bitcoin)
  (BIP32, secp256k1, script/address); decryption from the RustCrypto crates
  (`aes-gcm`, `cbc`, `pbkdf2`, `sha2`, `md-5`). The BlockTrail-specific logic is in
  `src/decrypt.rs` (two-layer decrypt) and `src/derive.rs` (paths + `sortedmulti` scripts) —
  the parts to audit.

## What it does (for auditors)

1. `decrypt.rs` — undoes BlockTrail's encryption: v3 = PBKDF2-SHA512 → AES-256-GCM
   (16-byte IV, header as AAD, `0x81` padding strip); v2 = OpenSSL `EVP_BytesToKey`(MD5) →
   AES-256-CBC; v1 = BIP39 seed (including BlockTrail's 512-bit / 48-word mnemonics, which the
   standard BIP39 parser rejects). Oversized "encrypted mnemonics" are decoded manually
   (standard BIP39 libraries reject their non-standard length).
2. `derive.rs` — BIP32 with BlockTrail's asymmetric paths (primary `m/<index>'` hardened,
   backup `m/<index>` un-hardened), then a 2-of-3 BIP67 `sortedmulti`. The path's *chain*
   element is a script/coin selector, **not** a receive/change split: `0` = legacy P2SH,
   `2` = nested SegWit (P2SH-P2WSH), `1` = Bitcoin Cash (never emitted). BlockTrail's change
   goes to the next index on the same chain, so one descriptor per script type (chains `0`
   and `2`) covers all funds. Output = both descriptors + addresses + master xprvs.

## License

MIT — see [LICENSE](LICENSE).
