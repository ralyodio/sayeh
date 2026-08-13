use criterion::{Criterion, criterion_group, criterion_main};
use sayeh_core::crypto::{Argon2Params, derive_password_key};

fn argon2id_mobile_profile(criterion: &mut Criterion) {
    let salt = [0x5au8; 16];
    criterion.bench_function("argon2id-64m-t3-p1", |bencher| {
        bencher.iter(|| derive_password_key(b"calibration password", &salt, Argon2Params::DEFAULT));
    });
}

criterion_group!(benches, argon2id_mobile_profile);
criterion_main!(benches);
