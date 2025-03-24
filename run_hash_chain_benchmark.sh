#!/bin/bash

# Create directory for benchmark results
mkdir -p benchmark_results_chain

# Number of runs
RUNS=20

# Metrics to track
proof_gen_times=()
proof_ver_times=()
proof_sizes=()
prover_cpu_usages=()
prover_memory_usages=()
verifier_cpu_usages=()
verifier_memory_usages=()
communication_overheads=()

echo "Running F2 Hash Chain (10 iterations) benchmark $RUNS times..."
for i in $(seq 1 $RUNS); do
    echo "Run $i of $RUNS"
    
    # Run the benchmark
    output=$(cargo run -- prove --field f2 --circuit hash_chain_10 2>&1)
    
    # Extract metrics
    # Proof Generation Time
    proof_gen_time=$(echo "$output" | grep "Proof Generation Time:" | awk '{print $4}')
    proof_gen_times+=($proof_gen_time)
    
    # Proof Verification Time
    proof_ver_time=$(echo "$output" | grep "Proof Verification Time:" | awk '{print $4}')
    proof_ver_times+=($proof_ver_time)
    
    # Proof Size
    proof_size=$(echo "$output" | grep "Proof Size:" | awk '{print $3}')
    proof_sizes+=($proof_size)
    
    # Prover Computation Load
    prover_cpu=$(echo "$output" | grep "Prover Computation Load:" | awk '{print $4}' | sed 's/%//')
    prover_cpu_usages+=($prover_cpu)
    
    prover_memory=$(echo "$output" | grep "Prover Computation Load:" | awk '{print $6}')
    prover_memory_usages+=($prover_memory)
    
    # Verifier Computation Load
    verifier_cpu=$(echo "$output" | grep "Verifier Computation Load:" | awk '{print $4}' | sed 's/%//')
    verifier_cpu_usages+=($verifier_cpu)
    
    verifier_memory=$(echo "$output" | grep "Verifier Computation Load:" | awk '{print $6}')
    verifier_memory_usages+=($verifier_memory)
    
    # Communication Overhead
    comm_overhead=$(echo "$output" | grep "Communication Overhead:" | awk '{print $3}')
    communication_overheads+=($comm_overhead)
    
    # Save JSON metrics to benchmark results
    cp results/metrics/f2_hash_chain_10.json "benchmark_results_chain/run_${i}_metrics.json"
    
    echo "Completed run $i"
    echo "---------------------------------------------"
done

# Calculate averages
calc_avg() {
    local sum=0
    local count=0
    for val in "$@"; do
        sum=$(echo "$sum + $val" | bc -l)
        count=$((count + 1))
    done
    echo "scale=2; $sum / $count" | bc -l
}

# Calculate average metrics
avg_proof_gen_time=$(calc_avg "${proof_gen_times[@]}")
avg_proof_ver_time=$(calc_avg "${proof_ver_times[@]}")
avg_proof_size=$(calc_avg "${proof_sizes[@]}" | xargs printf "%.0f")
avg_prover_cpu=$(calc_avg "${prover_cpu_usages[@]}")
avg_prover_memory=$(calc_avg "${prover_memory_usages[@]}")
avg_verifier_cpu=$(calc_avg "${verifier_cpu_usages[@]}")
avg_verifier_memory=$(calc_avg "${verifier_memory_usages[@]}")
avg_comm_overhead=$(calc_avg "${communication_overheads[@]}" | xargs printf "%.0f")

# Print average metrics
echo "====== AVERAGE METRICS (20 runs) ======"
echo "Proof Generation Time: $avg_proof_gen_time ms"
echo "Proof Verification Time: $avg_proof_ver_time ms"
echo "Proof Size: $avg_proof_size bytes"
echo "Prover Computation Load: $avg_prover_cpu% CPU, $avg_prover_memory MB"
echo "Verifier Computation Load: $avg_verifier_cpu% CPU, $avg_verifier_memory MB"
echo "Communication Overhead: $avg_comm_overhead bytes"
echo "======================================="

# Save average metrics to a file
cat > benchmark_results_chain/avg_metrics.txt << EOF
====== AVERAGE METRICS (20 runs) ======
Proof Generation Time: $avg_proof_gen_time ms
Proof Verification Time: $avg_proof_ver_time ms
Proof Size: $avg_proof_size bytes
Prover Computation Load: $avg_prover_cpu% CPU, $avg_prover_memory MB
Verifier Computation Load: $avg_verifier_cpu% CPU, $avg_verifier_memory MB
Communication Overhead: $avg_comm_overhead bytes
=======================================
EOF

echo "Benchmark complete. Results saved to benchmark_results_chain/"
