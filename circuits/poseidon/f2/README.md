# Poseidon Hash Function Implementation

This directory contains implementations of the Poseidon hash function for different field sizes.

## Directory Structure

- `f2/`: Implementation for the binary field F_2
  - `circuit.txt`: Circuit definition for F_2
  - `private.txt`: Private inputs for F_2 circuit
  - `public.txt`: Public inputs for F_2 circuit

## F2 to F64b Conversion

The schmivitz library has been modified to work with F64b instead of F2. Private inputs are now automatically converted from F2 to F64b before circuit evaluation. This means:

1. All `private.txt` files use `@type field 2` and contain only binary values (0 or 1)
2. During circuit evaluation, these values are converted to F64b
3. The circuit itself operates in the specified field (F_2, F_128, or Fp)

For example, in the private input files:

- A value of `<0>` remains 0 in F64b
- A value of `<1>` is converted to 1 in F64b
- For MDS matrix coefficients, we use binary patterns that will be converted to the appropriate values in F64b

## F_2 Implementation

The F_2 implementation operates on the binary field where addition is XOR and multiplication is AND.

### Structure

1. **State Initialization**:
   - Three private inputs are read
   - Initial state of three variables is created using XOR operations

2. **Round Constants Addition**:
   - Three private inputs are read as round constants
   - Constants are added to the state using XOR operations

3. **Full Round 1**:
   - **Non-linear Layer (S-box)**: AND operations between state elements
   - **Linear Layer**: XOR operations to mix the state

4. **Full Round 2**:
   - Similar structure to Full Round 1

5. **Partial Round**:
   - **Simplified Non-linear Layer**: S-box applied only to first state element
   - **Linear Layer**: XOR operations to mix the state

6. **Final Round**:
   - Full non-linear layer and linear layer

7. **Output Calculation**:
   - XOR of a value with itself (which equals 0 in F_2)

### Deviations from Theoretical Design

The F_2 implementation deviates from the theoretical Poseidon design in several ways:

1. **Field Choice**: Uses F_2 instead of large prime fields
2. **S-box Function**: Uses simple AND operations instead of power functions
3. **Linear Layer**: Uses a simplified mixing pattern with XOR operations
4. **Round Structure**: Uses fewer rounds than recommended
5. **Deterministic Output**: The final operation always results in 0
