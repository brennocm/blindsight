//! MultiSend unpacking: no panic on any bytes, and whatever unpacks packs
//! back to the same bytes.
#![no_main]

use blindsight::decode::multisend::{pack, unpack};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(entries) = unpack(data) {
        assert_eq!(pack(&entries), data);
    }
});
