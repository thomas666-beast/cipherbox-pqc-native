//! Native binding for `cipherbox-pqc-core`.
//!
//! All cryptographic logic lives in `cipherbox-pqc-core`. This crate is a
//! re-export plus the CLI binaries under `src/bin/` and the small helpers
//! in [`cli`] they share.

pub use cipherbox_pqc_core::*;

pub mod cli;
