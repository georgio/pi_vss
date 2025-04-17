use error_chain::error_chain;

error_chain! {
    errors{
        PointDecompressionError(t: String) {
            description("Unable to Decompress Compressed ristretto Point")
            display("Unable to Decompress Compressed ristretto Point: '{}'", t)
        }
        CountMismatch(c1: usize, c1_type: &'static str, c2: usize, c2_type: &'static str) {
            description("The number of {c1_type} does not match the number of {c2_type}.")
            display("The number of {c1_type} does not match the number of {c2_type}.\nHave {c1} {c1_type} but the number of {c2} is {c2_type}.")
        }
        UninitializedValue(t: &'static str) {
            description("Attempted to operate on an unititalized value")
            display("Attempted to operate on an unititalized value {}", t)
        }
        InvalidPararmeterSet(n: usize, t: isize, index: usize){
            description("Invalid Parameter Set")
            display("Invalid Parameter Set: n = {}, t = {}, index = {}.\n Valid params: n > t, index <= n, t => (n+1)/2", n, t, index)
        }
        InvalidProof(t: String) {
            description("Invalid Dealer Proof")
            display("Invalid Dealer Proof: {}", t)
        }
    }
}
