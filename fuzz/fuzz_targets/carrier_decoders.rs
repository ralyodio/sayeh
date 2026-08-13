#![no_main]

use libfuzzer_sys::fuzz_target;
use sayeh_core::carrier::{Carrier, CarrierKind};
use sayeh_core::pipeline::scan;

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    for carrier in CarrierKind::ALL {
        let _ = carrier.decode(&text);
    }
    let _ = scan(&text);
});
