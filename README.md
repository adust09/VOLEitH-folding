# Project Details

This project investigates the feasibility of on-chain verification for VOLE in the Head (VOLE itH), a publicly verifiable and efficient variant of VOLE-based zero-knowledge (ZK) proofs. While VOLE-based ZK systems significantly reduce computational complexity for provers, the challenge lies in implementing cost-effective and scalable on-chain verification.

VOLE-based ZK systems are typically designed for efficient prover but are not yet widely implemented for on-chain verification due to challenges such as proof size, communication costs, and gas costs. VOLE itH introduces public verifiability, making it a promising candidate for practical zk schemes for on-chain applications via client-side provers. However, the exact costs and technical bottlenecks of integrating VOLE itH into a public blockchain, such as Ethereum, remain unclear.

## Measurement matrix

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

## Benchmark

The following benchmark results were obtained on a test machine using the VOLEitH implementation with `Poseidon hash`.

- Apple M1 with 16GB memory
- [VOLE itH Parameters](https://github.com/adust09/swanky/blob/dev/schmivitz/src/parameters.rs)
- Hash Chain (10 iterations) values are both the average of 10 runs

| Metric                    | F2 Single Hash         | F2 Hash Chain (10 iters) | F64 Single Hash        | F64 Hash Chain (10 iters) |
|---------------------------|------------------------|---------------------------|------------------------|----------------------------|
| **Proof Generation Time** | 537.012 µs             | 1.699533 ms               | 336.628 µs             | 1.700849 ms                |
| **Proof Verification Time** | 214.07 µs            | 1.061466 ms               | 457.029 µs             | 1.154495 ms                |
| **Proof Size**            | 24,312 bytes           | 58,618 bytes              | 48,271 bytes           | 100,445 bytes              |
| **Communication Overhead**| 24,377 bytes           | 58,738 bytes              | 48,397 bytes           | 100,578 bytes              |
| **Prover CPU Usage**      | 0.10%                  | 0.19%                     | 0.11%                  | 0.08%                      |
| **Prover Memory Usage**   | 11.66 MB               | 15.28 MB                  | 11.94 MB               | 15.88 MB                   |
| **Verifier CPU Usage**    | 0.12%                  | 0.13%                     | 0.11%                  | 0.07%                      |
| **Verifier Memory Usage** | 13.97 MB               | 16.89 MB                  | 14.33 MB               | 16.97 MB                   |

You can run the benchmarks yourself using the following scripts:

```bash
cargo bench
```
