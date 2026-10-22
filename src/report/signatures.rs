//! Classifying the signatures in `execTransaction` calldata.
//!
//! Each signature is 65 bytes, `r ‖ s ‖ v`, and `v` says what kind it is
//! (`checkSignatures` in the Safe contracts):
//!
//! | `v`      | kind |
//! |----------|------|
//! | 0        | contract signature (EIP-1271); `r` holds the signer address, `s` an offset to its data |
//! | 1        | pre-approved hash; `r` holds the owner that called `approveHash` |
//! | 27, 28   | ECDSA over the EIP-712 hash (typed-data signing) |
//! | 31, 32   | ECDSA over the hash as a personal message (`eth_sign`) |
//!
//! `eth_sign` means the signer's device was asked to sign a bare 32-byte
//! hash: it could not show the transaction. All three Bybit signatures were
//! of this kind. Signers of ECDSA signatures are not recovered (that needs
//! elliptic-curve code blindsight does not include).

use alloy_primitives::{Address, U256};

/// What a signature is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureKind {
    /// EIP-1271 contract signature, by the given contract.
    Contract(Address),
    /// Hash approved on chain by the given owner (`approveHash`).
    ApprovedHash(Address),
    /// ECDSA over the EIP-712 hash.
    TypedData,
    /// ECDSA over the hash as a personal message (`eth_sign`).
    EthSign,
    /// A `v` value the Safe does not accept.
    Invalid,
}

/// One signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignatureInfo {
    /// Position (0-based).
    pub index: usize,
    /// The `v` byte.
    pub v: u8,
    /// What it is.
    pub kind: SignatureKind,
}

/// Splits the `signatures` bytes into 65-byte signatures and classifies
/// them. Contract signatures carry an offset to dynamic data placed after
/// the fixed-size part; parsing stops where that data begins.
pub fn parse_signatures(signatures: &[u8]) -> Vec<SignatureInfo> {
    let mut out = Vec::new();
    // End of the fixed-size part: shrinks as contract-signature offsets are seen.
    let mut fixed_end = signatures.len();
    let mut index = 0;
    while let Some(chunk) = signatures.get(index * 65..(index + 1) * 65) {
        if (index + 1) * 65 > fixed_end {
            break;
        }
        let r = chunk.get(..32).unwrap_or_default();
        let s = chunk.get(32..64).unwrap_or_default();
        let v = chunk.get(64).copied().unwrap_or_default();
        // The signer address is the low 20 bytes of `r`.
        let signer = Address::from_slice(r.get(12..32).unwrap_or(&[0; 20]));
        let kind = match v {
            0 => {
                let offset = U256::from_be_slice(s);
                if let Ok(offset) = usize::try_from(offset) {
                    fixed_end = fixed_end.min(offset);
                }
                SignatureKind::Contract(signer)
            }
            1 => SignatureKind::ApprovedHash(signer),
            27 | 28 => SignatureKind::TypedData,
            31 | 32 => SignatureKind::EthSign,
            _ => SignatureKind::Invalid,
        };
        out.push(SignatureInfo { index, v, kind });
        index += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sig(r_last: u8, s: u64, v: u8) -> Vec<u8> {
        let mut out = vec![0; 65];
        out[31] = r_last;
        out[32..64].copy_from_slice(&U256::from(s).to_be_bytes::<32>());
        out[64] = v;
        out
    }

    #[test]
    fn classifies_by_v() {
        let mut all = Vec::new();
        for v in [27, 28, 31, 32, 1, 5] {
            all.extend(sig(7, 0, v));
        }
        let kinds: Vec<SignatureKind> = parse_signatures(&all).iter().map(|s| s.kind).collect();
        let owner = Address::with_last_byte(7);
        assert_eq!(
            kinds,
            [
                SignatureKind::TypedData,
                SignatureKind::TypedData,
                SignatureKind::EthSign,
                SignatureKind::EthSign,
                SignatureKind::ApprovedHash(owner),
                SignatureKind::Invalid,
            ]
        );
    }

    #[test]
    fn stops_at_contract_signature_data() {
        // One contract signature whose data starts at byte 130, after two
        // fixed-size signatures.
        let mut all = sig(9, 130, 0);
        all.extend(sig(0, 0, 27));
        all.extend(vec![0xff; 40]); // dynamic data
        let parsed = parse_signatures(&all);
        assert_eq!(parsed.len(), 2);
        assert_eq!(
            parsed[0].kind,
            SignatureKind::Contract(Address::with_last_byte(9))
        );
    }

    #[test]
    fn ignores_trailing_bytes_and_empty_input() {
        assert!(parse_signatures(&[]).is_empty());
        let mut one = sig(0, 0, 31);
        one.extend([0; 10]);
        assert_eq!(parse_signatures(&one).len(), 1);
    }
}
