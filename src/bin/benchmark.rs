mod keccak;
mod prove;

use eyre::Result;

fn main() -> Result<()> {
    println!("Running benchmarks for multiple field sizes...\n");

    // Benchmark F2 field
    println!("=== F_2 FIELD BENCHMARK ===");
    let f2_metrics = prove::prove("f2", "proof_f2.json")?;
    f2_metrics.display();
    f2_metrics.save_to_file("metrics_f2.json")?;

    // Benchmark F64 field
    println!("\n=== F_64 FIELD BENCHMARK ===");
    let f64_metrics = prove::prove("f64", "proof_f64.json")?;
    f64_metrics.display();
    f64_metrics.save_to_file("metrics_f64.json")?;

    Ok(())
}
