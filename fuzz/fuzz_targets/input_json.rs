//! JSON input: no panic on any text; anything accepted yields a transaction
//! whose hash can be computed.
#![no_main]

use blindsight::input::json::parse_json;
use blindsight::safe::compute_hashes;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|text: &str| {
    if let Ok(partial) = parse_json(text) {
        if let Ok(input) = partial.finish(true) {
            assert!(compute_hashes(&input.account, &input.tx).is_ok());
        }
    }
});
