mod merkle;
mod prove;
mod verification;

fn main() {
    // prove::main().expect("Failed to prove");
    verification::main().expect("Failed to verify");
}
