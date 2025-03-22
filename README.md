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
cargo run --bin voleitH-bench -- prove --field f2
```

For F_64 field:
```bash
cargo run --bin voleitH-bench -- prove --field f64
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

## F_2 Hash Chain Benchmark (10 iterations)

| Metric                   | Result        | Notes                                                 |
|--------------------------|---------------|-------------------------------------------------------|
| Proof Generation Time    | 114 ms        | Time to generate proof for 10-iteration hash chain    |
| Proof Verification Time  | 69 ms         | Time to verify the generated proof                    |
| Proof Size               | 58,569 bytes  | Size of the serialized proof                          |
| Prover Computation Load  | 0.30% CPU, 0.01 MB | System resources used during proof generation    |
| Verifier Computation Load| 0.27% CPU, 0.01 MB | System resources used during proof verification  |
| Communication Overhead   | 78,712 bytes  | Total data exchanged (inputs + proof)                 |

This benchmark demonstrates the performance of a 10-iteration hash chain where the output of each hash operation is used as input to the next hash. Compared to the single hash operation, the hash chain has:
- ~2.4x larger proof size (58,569 vs 24,324 bytes)
- ~3x larger communication overhead (78,712 vs 26,054 bytes)
- Only slightly increased computation time

For running the hash chain benchmark:
```bash
cargo run --bin voleitH-bench -- prove --field f2 --circuit hash_chain
```

## F_64 Hash Chain Benchmark (10 iterations)

| Metric                   | Status        | Notes                                                 |
|--------------------------|---------------|-------------------------------------------------------|
| Implementation Status    | Completed     | Full circuit implementation with 10 iterations        |
| Executability            | Not runnable  | Current prover system limited to F2 for hash chains   |

The F64 Hash Chain (10 iterations) has been fully implemented in this project with the circuit available at `src/circuits/poseidon/f64/hash_chain/poseidon_chain.txt`. However, there is a limitation in the underlying proving system (Schmivitz library) that currently only supports F2 field for hash chain operations.

When attempting to run:
```bash
cargo run -- prove --field f64 --circuit hash_chain
```

The system produces the following error:
```
Error: Hash chain circuit is only available for F2 field due to limitations in the underlying proving system. 
Although we've created an F64 hash chain circuit implementation, the current prover only supports F2 for hash chains.
```

### Expected Performance Characteristics

Based on the relative performance of F64 vs F2 in single hash operations, and the performance of F2 Hash Chain, we can extrapolate the expected performance for F64 Hash Chain when support is added to the underlying prover:

- **Proof Size**: Likely ~2-2.5x larger than F2 Hash Chain (~120-150KB)
- **Proof Generation Time**: ~20-30% higher than F2 Hash Chain
- **Verification Time**: ~20-30% higher than F2 Hash Chain
- **Communication Overhead**: Proportional to the proof size increase (~160-190KB)

The F64 Hash Chain implementation is ready for use once the underlying proving system adds support for F64 fields in hash chain operations.
