mod fold;
mod prove;

fn main() {
    // prove::main().expect("Failed to prove");
    fold::main().expect("Failed to verify");
}
