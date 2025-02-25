mod prove;
mod verify;

fn main() {
    prove::main().expect("Failed to prove");
    verify::main().expect("Failed to verify");
}
