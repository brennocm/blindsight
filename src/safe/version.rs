//! Supported Safe contract versions.

use std::fmt;
use std::str::FromStr;

use thiserror::Error;

/// A Safe contract version that blindsight can hash for.
///
/// Only versions with an official deployment in `safe-deployments` are listed.
/// Unreleased or never-deployed tags (0.1.0, 1.1.0, 1.4.0) are rejected: they
/// have no real transaction to test against. See `docs/adr/0005-dual-hashing-and-supported-versions.md`.
///
/// The variants are declared in release order, so `<` and `>=` compare
/// versions (`#[derive(PartialOrd, Ord)]` orders enum variants by position).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SafeVersion {
    /// `GnosisSafe` 1.0.0.
    V1_0_0,
    /// `GnosisSafe` 1.1.1.
    V1_1_1,
    /// `GnosisSafe` 1.2.0.
    V1_2_0,
    /// `GnosisSafe` 1.3.0 (and its L2 variant).
    V1_3_0,
    /// `Safe` 1.4.1 (and its L2 variant).
    V1_4_1,
    /// `Safe` 1.5.0 (and its L2 variant).
    V1_5_0,
}

impl SafeVersion {
    /// Every supported version, oldest first.
    pub const ALL: [SafeVersion; 6] = [
        SafeVersion::V1_0_0,
        SafeVersion::V1_1_1,
        SafeVersion::V1_2_0,
        SafeVersion::V1_3_0,
        SafeVersion::V1_4_1,
        SafeVersion::V1_5_0,
    ];

    /// The version as the contract's `VERSION()` returns it, e.g. `"1.4.1"`.
    pub fn as_str(self) -> &'static str {
        match self {
            SafeVersion::V1_0_0 => "1.0.0",
            SafeVersion::V1_1_1 => "1.1.1",
            SafeVersion::V1_2_0 => "1.2.0",
            SafeVersion::V1_3_0 => "1.3.0",
            SafeVersion::V1_4_1 => "1.4.1",
            SafeVersion::V1_5_0 => "1.5.0",
        }
    }

    /// Whether the EIP-712 domain includes `chainId`.
    ///
    /// From 1.3.0 on the domain is `EIP712Domain(uint256 chainId,address
    /// verifyingContract)`; before, only `verifyingContract`, so a signature is
    /// valid on every chain where the same Safe address has the same nonce.
    pub fn domain_has_chain_id(self) -> bool {
        self >= SafeVersion::V1_3_0
    }
}

impl fmt::Display for SafeVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The text given as a Safe version is not a supported version.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error(
    "unsupported Safe version {input:?}: supported versions are 1.0.0, 1.1.1, 1.2.0, 1.3.0, 1.4.1, 1.5.0"
)]
pub struct UnsupportedVersion {
    /// The text that was given.
    pub input: String,
}

impl FromStr for SafeVersion {
    type Err = UnsupportedVersion;

    /// Parses `"1.4.1"`. Also accepts a leading `v` (`"v1.4.1"`) and the
    /// `+L2` suffix the Safe interface shows for L2 singletons
    /// (`"1.3.0+L2"`): L2 singletons hash exactly like the base ones.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let trimmed = s.trim();
        let without_v = trimmed
            .strip_prefix('v')
            .or_else(|| trimmed.strip_prefix('V'))
            .unwrap_or(trimmed);
        let core = without_v
            .strip_suffix("+L2")
            .or_else(|| without_v.strip_suffix("+l2"))
            .unwrap_or(without_v);
        SafeVersion::ALL
            .into_iter()
            .find(|v| v.as_str() == core)
            .ok_or_else(|| UnsupportedVersion {
                input: s.to_string(),
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_every_supported_version_and_round_trips() {
        for v in SafeVersion::ALL {
            assert_eq!(v.as_str().parse::<SafeVersion>(), Ok(v));
            assert_eq!(v.to_string(), v.as_str());
        }
    }

    #[test]
    fn accepts_v_prefix_l2_suffix_and_whitespace() {
        assert_eq!("v1.4.1".parse(), Ok(SafeVersion::V1_4_1));
        assert_eq!("1.3.0+L2".parse(), Ok(SafeVersion::V1_3_0));
        assert_eq!(" 1.5.0 ".parse(), Ok(SafeVersion::V1_5_0));
    }

    #[test]
    fn rejects_unsupported_versions() {
        for s in [
            "0.1.0", "1.1.0", "1.4.0", "1.6.0", "1.3", "", "latest", "1.3.0+L3",
        ] {
            let err = s.parse::<SafeVersion>().unwrap_err();
            assert_eq!(err.input, s);
        }
    }

    #[test]
    fn chain_id_is_in_the_domain_from_1_3_0() {
        let with: Vec<_> = SafeVersion::ALL
            .into_iter()
            .filter(|v| v.domain_has_chain_id())
            .collect();
        assert_eq!(
            with,
            [
                SafeVersion::V1_3_0,
                SafeVersion::V1_4_1,
                SafeVersion::V1_5_0
            ]
        );
    }

    #[test]
    fn all_is_sorted_oldest_first() {
        assert!(SafeVersion::ALL.windows(2).all(|w| w[0] < w[1]));
    }
}
