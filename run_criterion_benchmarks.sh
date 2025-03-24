#!/bin/bash

# Create directory for benchmark results
mkdir -p benchmark_results

# Run criterion benchmarks
echo "Running poseidon_f2 benchmarks..."
cargo bench --bench poseidon_f2_benches

# Check if benchmark was successful
if [ $? -eq 0 ]; then
    echo "Benchmarks completed successfully!"
    echo "Detailed results have been saved to benchmark_results/ directory"
    echo ""
    echo "You can view HTML reports at target/criterion/report/index.html"
    
    # Display the JSON metrics if they exist
    if [ -f "benchmark_results/F2_Single_Hash_metrics.json" ]; then
        echo "=== F2 Single Hash Metrics ==="
        cat benchmark_results/F2_Single_Hash_metrics.json
        echo ""
    fi
    
    if [ -f "benchmark_results/F2_Hash_Chain_10_metrics.json" ]; then
        echo "=== F2 Hash Chain 10 Metrics ==="
        cat benchmark_results/F2_Hash_Chain_10_metrics.json
        echo ""
    fi
else
    echo "Benchmark execution failed."
fi
