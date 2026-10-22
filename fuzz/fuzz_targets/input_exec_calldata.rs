//! `execTransaction` calldata: no panic on any bytes, with or without the
//! right selector.
#![no_main]

use blindsight::input::exec::{EXEC_TRANSACTION_SELECTOR, parse_exec_calldata};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = parse_exec_calldata(data);
    let mut with_selector = EXEC_TRANSACTION_SELECTOR.to_vec();
    with_selector.extend_from_slice(data);
    if let Ok(partial) = parse_exec_calldata(&with_selector) {
        assert!(partial.to.is_some() && partial.signatures.is_some());
    }
});
