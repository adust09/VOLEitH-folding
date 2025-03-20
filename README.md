# Project Details
This project investigates the feasibility of on-chain verification for VOLE in the Head (VOLE itH), a publicly verifiable and efficient variant of VOLE-based zero-knowledge (ZK) proofs. While VOLE-based ZK systems significantly reduce computational complexity for provers, the challenge lies in implementing cost-effective and scalable on-chain verification.

VOLE-based ZK systems are typically designed for efficient prover but are not yet widely implemented for on-chain verification due to challenges such as proof size, communication costs, and gas costs. VOLE itH introduces public verifiability, making it a promising candidate for practical zk schemes for on-chain applications via client-side provers. However, the exact costs and technical bottlenecks of integrating VOLE itH into a public blockchain, such as Ethereum, remain unclear.

# Measurement matrix

| Metric                   | Description                                                                                 | Unit                | Example Measurement Method                                                                     |
|--------------------------|---------------------------------------------------------------------------------------------|---------------------|-----------------------------------------------------------------------------------------------|
| Proof Generation Time    | Time required for the prover to generate the proof                                         | Milliseconds (ms)   | Measure the execution time of the proof generation process                                    |
| Proof Verification Time  | Time required for the verifier to verify the proof                                         | Milliseconds (ms)   | Measure the execution time of the proof verification process                                  |
| Proof Size               | Size of the generated proof data                                                           | Bytes               | Measure the size of the proof after generation                                                |
| Prover Computation Load  | Computational cost for the prover (e.g., memory usage, CPU usage)                          | CPU Load (%), MB    | Monitor resource usage during the proof generation process                                    |
| Verifier Computation Load| Computational cost for the verifier (e.g., memory usage, CPU usage)                        | CPU Load (%), MB    | Monitor resource usage during the proof verification process                                  |
| Setup Time               | Time required for the initial system setup (if applicable)                                 | Seconds (s)         | Measure the execution time of the setup process                                               |
| Communication Overhead   | Total amount of data exchanged between prover and verifier                                 | Bytes               | Capture communication logs and measure the total data exchanged                               |
| On-Chain Verification Gas Cost| Cost of verifying the proof on-chain in gas                                           | Gas units           | Measure gas cost using a blockchain environment (e.g., Ethereum)                             |

The target of this calculation is the Proof of Hash chain.
The following two methods are used for onchain-verification.

- SNARK verification + Solidity Verifier
- Smart Contract

# Benchmark

The following benchmark results were obtained on a test machine using the VOLEitH implementation with Poseidon hash in different field sizes:

## F_2 Field Benchmark

| Metric                   | Result        | Notes                                                 |
|--------------------------|---------------|-------------------------------------------------------|
| Proof Generation Time    | 103 ms        | Time to generate proof for Poseidon hash circuit      |
| Proof Verification Time  | 49 ms         | Time to verify the generated proof                    |
| Proof Size               | 24,324 bytes  | Size of the serialized proof                          |
| Prover Computation Load  | 0.18% CPU, 0.01 MB | System resources used during proof generation    |
| Verifier Computation Load| 0.14% CPU, 0.01 MB | System resources used during proof verification  |
| Communication Overhead   | 26,054 bytes  | Total data exchanged (inputs + proof)                 |

## F_64 Field Benchmark

| Metric                   | Result        | Notes                                                 |
|--------------------------|---------------|-------------------------------------------------------|
| Proof Generation Time    | 110 ms        | Time to generate proof for Poseidon hash circuit      |
| Proof Verification Time  | 64 ms         | Time to verify the generated proof                    |
| Proof Size               | 48,269 bytes  | Size of the serialized proof                          |
| Prover Computation Load  | 0.29% CPU, 0.01 MB | System resources used during proof generation    |
| Verifier Computation Load| 0.24% CPU, 0.01 MB | System resources used during proof verification  |
| Communication Overhead   | 66,245 bytes  | Total data exchanged (inputs + proof)                 |

## Running the Benchmarks

You can run the benchmarks yourself using the following commands:

For F_2 field:
```bash
cargo run --bin vole-itH-folding -- prove --field f2
```

For F_64 field:
```bash
cargo run --bin vole-itH-folding -- prove --field f64
```

These commands will:
1. Generate proof using the specified field
2. Measure all metrics during proof generation and verification
3. Save the proof to `results/proofs/proof_[field].json` (e.g., `results/proofs/proof_f2.json`)
4. Save the metrics to `results/metrics/metrics_[field].json` (e.g., `results/metrics/metrics_f2.json`)
5. Display the measurement matrix in the console

Observations:
- The F_64 field implementation generates proofs that are approximately 2x larger than F_2
- Computation time is slightly higher for F_64 compared to F_2
- Communication overhead scales proportionally with the proof size
- CPU and memory usage remain minimal in both implementations

Note: Setup Time and On-Chain Verification Gas Cost are not included in this benchmark as they were not part of the measurement requirements.
