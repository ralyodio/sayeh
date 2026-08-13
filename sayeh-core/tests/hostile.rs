use proptest::prelude::*;
use sayeh_core::carrier::{Carrier, CarrierKind};
use sayeh_core::container::SealedContainer;
use sayeh_core::pipeline::scan;

proptest! {
    #[test]
    fn container_parser_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..65_536)) {
        let _ = SealedContainer::parse(&bytes);
    }

    #[test]
    fn carrier_decoders_never_panic(text in ".{0,8192}") {
        for carrier in CarrierKind::ALL {
            let _ = carrier.decode(&text);
        }
        let _ = scan(&text);
    }
}
