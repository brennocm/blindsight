//! Exact formatting of integer amounts with decimals (wei → ETH, token
//! base units → tokens). No floating point: every digit is kept.

use alloy_primitives::U256;

/// Largest decimals value where `10^decimals` fits in a `U256`.
const MAX_DECIMALS: u8 = 77;

/// Formats `amount` base units with `decimals` decimals, exactly.
///
/// `format_units(1_500_000, 6) == "1.5"`. Trailing zeros of the fraction are
/// dropped; the integer part is never shortened. Returns `None` if
/// `decimals` is too large to represent (above 77).
pub fn format_units(amount: U256, decimals: u8) -> Option<String> {
    if decimals > MAX_DECIMALS {
        return None;
    }
    if decimals == 0 {
        return Some(amount.to_string());
    }
    let scale = U256::from(10u8).pow(U256::from(decimals));
    let whole = amount / scale;
    let fraction = amount % scale;
    if fraction.is_zero() {
        return Some(whole.to_string());
    }
    let width = usize::from(decimals);
    let digits = format!("{fraction:0>width$}");
    Some(format!("{whole}.{}", digits.trim_end_matches('0')))
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    fn u(n: u128) -> U256 {
        U256::from(n)
    }

    #[test]
    fn formats_exactly() {
        let cases: &[(U256, u8, &str)] = &[
            (u(0), 18, "0"),
            (u(1), 18, "0.000000000000000001"),
            (u(1_500_000), 6, "1.5"),
            (u(1_000_000), 6, "1"),
            (u(123), 0, "123"),
            (u(60_000) * u(10u128.pow(18)), 18, "60000"),
            (u(10u128.pow(18) + 1), 18, "1.000000000000000001"),
            (
                U256::MAX,
                18,
                "115792089237316195423570985008687907853269984665640564039457.584007913129639935",
            ),
            (
                U256::MAX,
                77,
                "1.15792089237316195423570985008687907853269984665640564039457584007913129639935",
            ),
        ];
        for (amount, decimals, expected) in cases {
            assert_eq!(
                format_units(*amount, *decimals).as_deref(),
                Some(*expected),
                "{amount} / 10^{decimals}"
            );
        }
        assert_eq!(format_units(u(1), 78), None);
    }

    proptest! {
        /// Removing the dot and padding the fraction gives back the amount.
        #[test]
        fn round_trips(raw in any::<[u8; 32]>(), decimals in 0u8..=77) {
            let amount = U256::from_be_bytes(raw);
            let text = format_units(amount, decimals).unwrap();
            let (whole, fraction) = text.split_once('.').unwrap_or((&text, ""));
            let padded = format!("{whole}{fraction:0<width$}", width = usize::from(decimals));
            prop_assert_eq!(padded.parse::<U256>().unwrap(), amount);
        }
    }
}
