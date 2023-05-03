#![allow(unused_crate_dependencies)]
#![allow(missing_docs)]

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use hex_literal::hex;

use cretrit::aes128v1::ore;
use cretrit::SerializableCipherText;

#[inline]
fn create_ore_cipher() -> ore::Cipher<8, 256> {
    let k = hex!["adfd30251dfc5f6cfe240febf43970dd b1c8053580207d781d6d762d19177b01"];

    ore::Cipher::<8, 256>::new(black_box(&k)).unwrap()
}

#[inline]
fn encrypt_u64(c: &ore::Cipher<8, 256>, u: u64) -> ore::CipherText<8, 256> {
    c.full_encrypt(&u.try_into().unwrap()).unwrap()
}

fn serialise_ciphertext(ct: &ore::CipherText<8, 256>) -> Vec<u8> {
    ct.to_vec().unwrap()
}

fn deserialise_ciphertext(v: &[u8]) -> ore::CipherText<8, 256> {
    ore::CipherText::<8, 256>::from_slice(v).unwrap()
}

fn compare_ciphertexts(
    a: &ore::CipherText<8, 256>,
    b: &ore::CipherText<8, 256>,
) -> std::cmp::Ordering {
    a.cmp(b)
}

pub fn benchmarks(c: &mut Criterion) {
    c.bench_function("create ORE cipher", |b| b.iter(|| create_ore_cipher()));
    c.bench_function("encrypt u64", |b| {
        let c = create_ore_cipher();
        b.iter(|| encrypt_u64(&c, 42))
    });
    c.bench_function("serialise", |b| {
        let c = create_ore_cipher();
        let ct = encrypt_u64(&c, 42);
        b.iter(|| serialise_ciphertext(&ct))
    });
    c.bench_function("deserialise", |b| {
        let c = create_ore_cipher();
        let sct = serialise_ciphertext(&encrypt_u64(&c, 42));
        b.iter(|| deserialise_ciphertext(&sct))
    });
    c.bench_function("compare", |b| {
        let c = create_ore_cipher();
        let ct1 = encrypt_u64(&c, 42);
        let ct2 = encrypt_u64(&c, 420);
        b.iter(|| compare_ciphertexts(&ct1, &ct2))
    });
}

criterion_group!(benches, benchmarks);
criterion_main!(benches);
