//! BlockTrail 2-of-3 P2SH wallet recovery — core library.
//! Ports the verified JS reference; crypto from rust-bitcoin + RustCrypto.
pub mod backup;
pub mod decrypt;
pub mod config;
pub mod derive;
pub use derive::{generate, KeyBlock, Output, WalletKind};
