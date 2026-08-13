#![no_main]

use libfuzzer_sys::fuzz_target;
use sayeh_core::container::SealedContainer;

fuzz_target!(|data: &[u8]| {
    let _ = SealedContainer::parse(data);
});
