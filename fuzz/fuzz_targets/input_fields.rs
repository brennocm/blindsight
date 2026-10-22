//! Field parsers: no panic on any text, and error messages never contain
//! raw control characters.
#![no_main]

use blindsight::input::Field;
use blindsight::input::fields::{
    parse_address, parse_bytes, parse_hash, parse_operation, parse_u64, parse_uint, parse_version,
};
use libfuzzer_sys::fuzz_target;

fn clean(message: String) {
    assert!(!message.chars().any(|c| c.is_control()), "{message:?}");
}

fuzz_target!(|text: &str| {
    if let Err(e) = parse_uint(Field::Value, text) {
        clean(e.to_string());
    }
    if let Err(e) = parse_u64(Field::ChainId, text) {
        clean(e.to_string());
    }
    if let Err(e) = parse_address(Field::To, text) {
        clean(e.to_string());
    }
    if let Err(e) = parse_bytes(Field::Data, text) {
        clean(e.to_string());
    }
    if let Err(e) = parse_hash(Field::ExpectSafeTxHash, text) {
        clean(e.to_string());
    }
    if let Err(e) = parse_operation(Field::Operation, text) {
        clean(e.to_string());
    }
    if let Err(e) = parse_version(Field::SafeVersion, text) {
        clean(e.to_string());
    }
});
