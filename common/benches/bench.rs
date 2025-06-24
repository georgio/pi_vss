use blake3::Hasher;
use common::{error::ErrorKind::PointDecompressionError, random::random_scalar};
use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use curve25519_dalek::RistrettoPoint;
use rand::RngCore;
use zeroize::Zeroize;

fn ristretto_point_bench(c: &mut Criterion) {
    let mut rng = rand::rng();
    let x = random_scalar(&mut rng);
    let G: RistrettoPoint = RistrettoPoint::mul_base(&random_scalar(&mut rng));

    let gx = G * x;
    let gx_compressed = gx.compress();

    c.bench_function("Basepoint Multiplication", |b| {
        b.iter(|| RistrettoPoint::mul_base(&x))
    });

    c.bench_function("Random Point Multiplication", |b| b.iter(|| G * x));

    c.bench_function("Point Compression", |b| b.iter(|| gx.compress()));
    c.bench_function("Point Decompression", |b| {
        b.iter(|| gx_compressed.decompress().unwrap())
    });
    c.bench_function("Point Decompression Handled", |b| {
        b.iter(|| match gx_compressed.decompress() {
            Some(point) => Ok(point),
            None => Err(PointDecompressionError),
        })
    });
}

fn hasher_bench(c: &mut Criterion) {
    c.bench_function("Buf Zeroize", |b| {
        b.iter_batched(
            || {
                let mut rng = rand::rng();
                let mut buf: [u8; 64] = [0u8; 64];
                rng.fill_bytes(&mut buf);
                buf
            },
            |mut buf| {
                buf.zeroize();
            },
            BatchSize::PerIteration,
        )
    });
    c.bench_function("Hasher Reset", |b| {
        b.iter_batched(
            || {
                let mut rng = rand::rng();
                let mut buf: [u8; 64] = [0u8; 64];
                rng.fill_bytes(&mut buf);
                let mut hasher = Hasher::new();
                hasher.update(&buf);
                hasher.update(&buf);
                hasher.update(&buf);
                hasher.update(&buf);
                hasher.update(&buf);
                hasher
            },
            |mut hasher| {
                hasher.reset();
            },
            BatchSize::PerIteration,
        )
    });
    c.bench_function("Hasher Reset", |b| b.iter(|| Hasher::new()));
}

criterion_group!(benches, ristretto_point_bench, hasher_bench);
criterion_main!(benches);
