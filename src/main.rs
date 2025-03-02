mod prove;
mod vc;
mod verification;

fn main() {
    prove::main().expect("Failed to prove");
    // verification::main().expect("Failed to verify");
    // vc::main().expect("Failed to verify");
}
