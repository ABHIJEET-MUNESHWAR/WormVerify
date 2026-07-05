//! Benchmarks for the VAA hot paths: parsing and quorum verification.

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use libsecp256k1::{sign, Message, PublicKey, SecretKey};
use wormverify_types::{GuardianAddress, GuardianSignature, Vaa, VaaBody, SUPPORTED_VERSION};

fn guardian(seed: u8) -> (SecretKey, GuardianAddress) {
    let sk = SecretKey::parse(&[seed.max(1); 32]).unwrap();
    let pk = PublicKey::from_secret_key(&sk);
    let mut pubkey64 = [0u8; 64];
    pubkey64.copy_from_slice(&pk.serialize()[1..]);
    (sk, GuardianAddress::from_pubkey(&pubkey64))
}

fn build_vaa(n: usize) -> (Vaa, Vec<GuardianAddress>) {
    let guardians: Vec<_> = (0..n).map(|i| guardian(i as u8 + 1)).collect();
    let addresses: Vec<_> = guardians.iter().map(|(_, a)| *a).collect();
    let body = VaaBody {
        timestamp: 1,
        nonce: 2,
        emitter_chain: 1,
        emitter_address: [7u8; 32],
        sequence: 3,
        consistency_level: 1,
        payload: vec![0xAB; 256],
    };
    let digest = body.digest();
    let quorum = (n * 2) / 3 + 1;
    let signatures = (0..quorum)
        .map(|i| {
            let (sig, rid) = sign(&Message::parse(&digest), &guardians[i].0);
            GuardianSignature {
                guardian_index: i as u8,
                rs: sig.serialize(),
                recovery_id: rid.serialize(),
            }
        })
        .collect();
    (
        Vaa {
            version: SUPPORTED_VERSION,
            guardian_set_index: 0,
            signatures,
            body,
        },
        addresses,
    )
}

fn bench_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("vaa_verify");
    for &n in &[7usize, 13, 19] {
        let (vaa, guardians) = build_vaa(n);
        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, _| {
            b.iter(|| vaa.verify(&guardians).unwrap());
        });
    }
    group.finish();
}

fn bench_parse(c: &mut Criterion) {
    let (vaa, _) = build_vaa(19);
    let bytes = vaa.encode();
    c.bench_function("vaa_parse_19", |b| {
        b.iter(|| Vaa::parse(&bytes).unwrap());
    });
}

criterion_group!(benches, bench_verify, bench_parse);
criterion_main!(benches);
