//! Data embedded at build time: chains, official Safe contracts, tokens and
//! function signatures. Each file in `data/` records its upstream source and
//! commit. Nothing is ever fetched at run time (ADR 0002).

mod chains;

use thiserror::Error;

pub use chains::{Chain, ChainTable, chains};

/// Embedded data failed to load. This is a build defect, not an input error.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("internal error: embedded data file {file} is invalid: {reason}")]
pub struct RegistryError {
    /// The `data/` file concerned.
    pub file: &'static str,
    /// What is wrong with it.
    pub reason: String,
}

impl RegistryError {
    fn new(file: &'static str, reason: String) -> Self {
        RegistryError { file, reason }
    }
}
