pub mod error;
pub mod polynomial;
pub mod precompute;
pub mod random;
pub mod secret_sharing;
pub mod utils;

// pub const BENCH_N_T: [(usize, usize); 9] = [
//     (16, 7),
//     (32, 15),
//     (64, 31),
//     (128, 63),
//     (256, 127),
//     (512, 255),
//     (1024, 511),
//     (2048, 1023),
//     (4096, 2047),
// ];
pub const BENCH_N_T: [(usize, usize); 2] = [
    (16, 7),
    // (32, 15),
    // (64, 31),
    // (128, 63),
    // (256, 127),
    // (512, 255),
    // (1024, 511),
    // (2048, 1023),
    (4096, 2047),
];

// pub const BENCH_K: [usize; 8] = [1, 10, 50, 100, 250, 500, 1000, 10000];
pub const BENCH_K: [usize; 3] = [1, 10, 50];
