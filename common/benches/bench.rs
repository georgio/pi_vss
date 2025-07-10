use blake3::Hasher;
use common::{
    error::ErrorKind::PointDecompressionError,
    random::random_scalar,
    utils::{compute_lagrange_bases, compute_lagrange_basis},
};
use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use curve25519_dalek::RistrettoPoint;
use rand::RngCore;
use zeroize::Zeroize;

fn lagrange_basis_bench(c: &mut Criterion) {
    // for t in [8, 127, 255] {
    let t = 255;
    let qualified_set: Vec<usize> = (1..=(t + 1)).into_iter().map(|x| x as usize).collect();
    c.bench_function(&format!("Lagrange Basis Computation: t = {}", t), |b| {
        b.iter(|| {
            for _ in 0..(t + 1) {
                compute_lagrange_basis(1, &qualified_set);
            }
        })
    });
    c.bench_function(&format!("Lagrange Basis Computation: t = {}", t), |b| {
        b.iter(|| compute_lagrange_bases(&qualified_set))
    });
    // }
}

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

criterion_group!(
    benches,
    lagrange_basis_bench,
    ristretto_point_bench,
    hasher_bench
);
criterion_main!(benches);
