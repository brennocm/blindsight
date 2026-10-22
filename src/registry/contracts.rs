//! Official Safe contracts per chain, from `data/safe_deployments.json`
//! (generated from `safe-global/safe-deployments`).

use std::collections::BTreeMap;
use std::sync::LazyLock;

use alloy_primitives::Address;
use serde::Deserialize;

use super::{RegistryError, parse_checksummed};

const DEPLOYMENTS_JSON: &str = include_str!("../../data/safe_deployments.json");

/// What an official contract is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Role {
    /// Safe implementation (`GnosisSafe` / `Safe`).
    Singleton,
    /// L2 implementation (`GnosisSafeL2` / `SafeL2`), emits extra events.
    SingletonL2,
    /// Proxy factory.
    ProxyFactory,
    /// Fallback handler (`CompatibilityFallbackHandler` and others).
    FallbackHandler,
    /// `MultiSend`: batches calls and delegatecalls.
    MultiSend,
    /// `MultiSendCallOnly`: batches calls, reverts on delegatecall items.
    MultiSendCallOnly,
    /// `SignMessageLib`: marks off-chain messages as signed.
    SignMessageLib,
    /// `CreateCall`: deploys contracts from the Safe.
    CreateCall,
    /// `SafeMigration` / `SafeToL2Migration`: replace the implementation.
    Migration,
    /// `SafeToL2Setup`: switches to the L2 implementation during setup.
    L2Setup,
    /// `SimulateTxAccessor`: used for gas estimation.
    SimulateTxAccessor,
    /// `CreateAndAddModules` (1.1.1): enables modules during setup.
    CreateAndAddModules,
}

impl Role {
    /// Whether a delegatecall to a contract with this role is expected.
    ///
    /// These are the helper libraries the Safe interface delegatecalls
    /// (`docs/detectors/CATALOG.md`, "trusted helpers"). Singletons, proxy
    /// factories, fallback handlers and the simulation accessor are official
    /// too, but a delegatecall into them is not a normal operation.
    pub fn is_trusted_delegatecall_target(self) -> bool {
        matches!(
            self,
            Role::MultiSend
                | Role::MultiSendCallOnly
                | Role::SignMessageLib
                | Role::CreateCall
                | Role::Migration
                | Role::L2Setup
        )
    }

    fn from_data(s: &str) -> Option<Role> {
        Some(match s {
            "singleton" => Role::Singleton,
            "singleton_l2" => Role::SingletonL2,
            "proxy_factory" => Role::ProxyFactory,
            "fallback_handler" => Role::FallbackHandler,
            "multi_send" => Role::MultiSend,
            "multi_send_call_only" => Role::MultiSendCallOnly,
            "sign_message_lib" => Role::SignMessageLib,
            "create_call" => Role::CreateCall,
            "migration" => Role::Migration,
            "l2_setup" => Role::L2Setup,
            "simulate_tx_accessor" => Role::SimulateTxAccessor,
            "create_and_add_modules" => Role::CreateAndAddModules,
            _ => return None,
        })
    }
}

/// One official contract deployment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OfficialContract {
    /// Contract name, e.g. `MultiSendCallOnly`.
    pub name: String,
    /// Safe release it belongs to, e.g. `1.4.1`.
    pub version: String,
    /// What it is for.
    pub role: Role,
}

/// All official contracts, indexed by `(chain id, address)`.
#[derive(Debug)]
pub struct SafeContracts {
    /// Upstream commit the data was generated from.
    pub source_commit: String,
    by_location: BTreeMap<(u64, Address), Vec<OfficialContract>>,
    chain_ids: Vec<u64>,
}

impl SafeContracts {
    /// The official contracts at `address` on `chain_id` (usually zero or one).
    pub fn at(&self, chain_id: u64, address: Address) -> &[OfficialContract] {
        self.by_location
            .get(&(chain_id, address))
            .map_or(&[], Vec::as_slice)
    }

    /// Every chain id with at least one deployment, ascending.
    pub fn chain_ids(&self) -> &[u64] {
        &self.chain_ids
    }

    /// Number of `(chain, address, contract)` entries.
    pub fn len(&self) -> usize {
        self.by_location.values().map(Vec::len).sum()
    }

    /// Whether there are no entries (never, for the embedded data).
    pub fn is_empty(&self) -> bool {
        self.by_location.is_empty()
    }

    /// Iterates over every `(chain id, address, contract)`.
    pub fn iter(&self) -> impl Iterator<Item = (u64, Address, &OfficialContract)> {
        self.by_location
            .iter()
            .flat_map(|((chain, addr), list)| list.iter().map(move |c| (*chain, *addr, c)))
    }
}

#[derive(Deserialize)]
struct DeploymentsFile {
    commit: String,
    contracts: Vec<ContractEntry>,
}

#[derive(Deserialize)]
struct ContractEntry {
    name: String,
    version: String,
    role: String,
    released: bool,
    /// Deployment type (`canonical`, `eip155`, `zksync`) → address.
    deployments: BTreeMap<String, String>,
    /// Chain id → deployment types present on that chain.
    chains: BTreeMap<String, Vec<String>>,
}

const FILE: &str = "safe_deployments.json";

fn parse(json: &str) -> Result<SafeContracts, RegistryError> {
    let file: DeploymentsFile =
        serde_json::from_str(json).map_err(|e| RegistryError::new(FILE, e.to_string()))?;
    let mut by_location: BTreeMap<(u64, Address), Vec<OfficialContract>> = BTreeMap::new();
    let mut chain_ids = Vec::new();
    for entry in file.contracts {
        if !entry.released {
            // Unreleased deployments are not official yet.
            continue;
        }
        let role = Role::from_data(&entry.role)
            .ok_or_else(|| RegistryError::new(FILE, format!("unknown role {}", entry.role)))?;
        let mut addresses = BTreeMap::new();
        for (kind, text) in &entry.deployments {
            addresses.insert(kind.as_str(), parse_checksummed(FILE, text)?);
        }
        for (chain, kinds) in &entry.chains {
            let chain_id: u64 = chain
                .parse()
                .map_err(|_| RegistryError::new(FILE, format!("bad chain id {chain}")))?;
            chain_ids.push(chain_id);
            for kind in kinds {
                let address = addresses.get(kind.as_str()).ok_or_else(|| {
                    RegistryError::new(
                        FILE,
                        format!("{} {}: no {kind} address", entry.name, entry.version),
                    )
                })?;
                by_location
                    .entry((chain_id, *address))
                    .or_default()
                    .push(OfficialContract {
                        name: entry.name.clone(),
                        version: entry.version.clone(),
                        role,
                    });
            }
        }
    }
    chain_ids.sort_unstable();
    chain_ids.dedup();
    Ok(SafeContracts {
        source_commit: file.commit,
        by_location,
        chain_ids,
    })
}

static CONTRACTS: LazyLock<Result<SafeContracts, RegistryError>> =
    LazyLock::new(|| parse(DEPLOYMENTS_JSON));

/// The embedded official contracts, parsed on first use.
///
/// # Errors
///
/// Only if the embedded data is corrupt, which the tests rule out.
pub fn safe_contracts() -> Result<&'static SafeContracts, RegistryError> {
    CONTRACTS.as_ref().map_err(Clone::clone)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::chains;

    fn addr(s: &str) -> Address {
        s.parse().unwrap()
    }

    #[test]
    fn embedded_data_is_valid_and_consistent_with_the_chain_table() {
        let contracts = safe_contracts().unwrap();
        assert_eq!(
            contracts.source_commit,
            "e9cc9798ab834e7fe515d361566eb4a28c65387f"
        );
        assert!(contracts.len() > 5000);
        let table = chains().unwrap();
        for id in contracts.chain_ids() {
            assert!(
                table.get(*id).is_some(),
                "chain {id} missing from chains.json"
            );
        }
        assert_eq!(contracts.chain_ids().len(), table.len());
    }

    /// Addresses cross-checked with the table in `docs/research.md` §3,
    /// itself read from the safe-deployments repository.
    #[test]
    fn known_helpers_are_found_where_the_research_says() {
        let c = safe_contracts().unwrap();
        let cases = [
            (
                1,
                "0x8D29bE29923b68abfDD21e541b9374737B49cdAD",
                "MultiSend",
                "1.1.1",
            ),
            (
                1,
                "0xA238CBeb142c10Ef7Ad8442C6D1f9E89e07e7761",
                "MultiSend",
                "1.3.0",
            ),
            (
                56,
                "0xA238CBeb142c10Ef7Ad8442C6D1f9E89e07e7761",
                "MultiSend",
                "1.3.0",
            ),
            (
                8453,
                "0x38869bf66a61cF6bDB996A6aE40D5853Fd43B526",
                "MultiSend",
                "1.4.1",
            ),
            (
                1,
                "0x40A2aCCbd92BCA938b02010E17A5b8929b49130D",
                "MultiSendCallOnly",
                "1.3.0",
            ),
            (
                42161,
                "0x9641d764fc13c8B624c04430C7356C1C7C8102e2",
                "MultiSendCallOnly",
                "1.4.1",
            ),
            (
                100,
                "0xd53cd0aB83D845Ac265BE939c57F53AD838012c9",
                "SignMessageLib",
                "1.4.1",
            ),
            (
                1,
                "0x526643F69b81B008F46d95CD5ced5eC0edFFDaC6",
                "SafeMigration",
                "1.4.1",
            ),
            (
                1,
                "0x34CfAC646f301356fAa8B21e94227e3583Fe3F5F",
                "GnosisSafe",
                "1.1.1",
            ),
            (
                1,
                "0xd9Db270c1B5E3Bd161E8c8503c55cEABeE709552",
                "GnosisSafe",
                "1.3.0",
            ),
        ];
        for (chain, address, name, version) in cases {
            let found = c.at(chain, addr(address));
            assert!(
                found.iter().any(|o| o.name == name && o.version == version),
                "{name} {version} not at {address} on {chain}: {found:?}"
            );
        }
    }

    #[test]
    fn the_bybit_and_wazirx_targets_are_not_official() {
        let c = safe_contracts().unwrap();
        assert!(
            c.at(1, addr("0x96221423681A6d52E184D440a8eFCEbB105C7242"))
                .is_empty()
        );
        assert!(
            c.at(1, addr("0xfbfFEF83b1C172fE3BC86C1CCB036AB9F3efCAF2"))
                .is_empty()
        );
    }

    #[test]
    fn lookup_is_per_chain() {
        let c = safe_contracts().unwrap();
        // MultiSend 1.1.1 was only deployed on a few early chains.
        let ms111 = addr("0x8D29bE29923b68abfDD21e541b9374737B49cdAD");
        assert!(!c.at(1, ms111).is_empty());
        assert!(c.at(8453, ms111).is_empty());
    }

    #[test]
    fn trusted_delegatecall_roles() {
        let trusted: Vec<Role> = [
            Role::Singleton,
            Role::SingletonL2,
            Role::ProxyFactory,
            Role::FallbackHandler,
            Role::MultiSend,
            Role::MultiSendCallOnly,
            Role::SignMessageLib,
            Role::CreateCall,
            Role::Migration,
            Role::L2Setup,
            Role::SimulateTxAccessor,
            Role::CreateAndAddModules,
        ]
        .into_iter()
        .filter(|r| r.is_trusted_delegatecall_target())
        .collect();
        assert_eq!(
            trusted,
            [
                Role::MultiSend,
                Role::MultiSendCallOnly,
                Role::SignMessageLib,
                Role::CreateCall,
                Role::Migration,
                Role::L2Setup
            ]
        );
    }
}
