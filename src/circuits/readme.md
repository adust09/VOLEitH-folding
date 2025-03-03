# Poseidon Hash Function Implementation

This directory contains implementations of the Poseidon hash function for different field sizes.

## Directory Structure

- `f2/`: Implementation for the binary field F_2
  - `poseidon.txt`: Circuit definition for F_2
  - `poseidon_private.txt`: Private inputs for F_2 circuit
  - `poseidon_public.txt`: Public inputs for F_2 circuit

- `f128/`: Implementation for the field F_128
  - `poseidon.txt`: Circuit definition for F_128
  - `poseidon_private.txt`: Private inputs (in F_2, converted to F64b)
  - `poseidon_public.txt`: Public inputs for F_128 circuit

- `fp/`: Implementation for the prime field Fp (p = 2305843009213693951)
  - `poseidon.txt`: Circuit definition for Fp
  - `poseidon_private.txt`: Private inputs (in F_2, converted to F64b)
  - `poseidon_public.txt`: Public inputs for Fp circuit

## F2 to F64b Conversion

The schmivitz library has been modified to work with F64b instead of F2. Private inputs are now automatically converted from F2 to F64b before circuit evaluation. This means:

1. All `poseidon_private.txt` files use `@type field 2` and contain only binary values (0 or 1)
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

## F_128 Implementation

The F_128 implementation operates on a 128-bit field, providing a middle ground between F_2 and the large prime field.

### Structure

1. **State Initialization**:
   - Three private inputs are read
   - Initial state is set to the input values

2. **Round Constants Addition**:
   - Three private inputs are read as round constants
   - Constants are added to the state

3. **Full Rounds (First Set)**:
   - 3 full rounds where S-box (x^3) is applied to all state elements
   - MDS matrix multiplication for diffusion

4. **Partial Rounds**:
   - 4 partial rounds where S-box is applied only to the first state element
   - MDS matrix multiplication for diffusion

5. **Full Rounds (Final Set)**:
   - 3 full rounds where S-box is applied to all state elements
   - MDS matrix multiplication for diffusion

6. **Output Calculation**:
   - First element of the final state is used as the hash output

### Alignment with Theoretical Design

The F_128 implementation is closer to the theoretical Poseidon design than the F_2 version:

1. **Field Choice**: Uses a larger field allowing for more complex operations
2. **S-box Function**: Implements x^3 power mapping (simpler than x^5 but still non-linear)
3. **Linear Layer**: Uses a simple MDS matrix for diffusion
4. **Round Structure**: Follows the recommended pattern of full and partial rounds
5. **Output**: Produces different outputs for different inputs

## Fp Implementation

The Fp implementation operates on a large prime field (p = 2305843009213693951) and is the most faithful to the theoretical Poseidon design.

### Structure

1. **State Initialization**:
   - Three private inputs are read
   - Initial state is set to the input values

2. **Round Constants Addition**:
   - Three private inputs are read as round constants
   - Constants are added to the state

3. **Full Rounds (First Set)**:
   - 4 full rounds where S-box (x^5) is applied to all state elements
   - MDS matrix multiplication for diffusion

4. **Partial Rounds**:
   - 2 partial rounds where S-box is applied only to the first state element
   - MDS matrix multiplication for diffusion

5. **Full Rounds (Final Set)**:
   - 2 full rounds where S-box applied to all state elements
   - MDS matrix multiplication for diffusion

6. **Output Calculation**:
   - First element of the final state is used as the hash output

### Alignment with Theoretical Design

The Fp implementation aligns most closely with the theoretical Poseidon design:

1. **Field Choice**: Uses a large prime field as specified in the Poseidon paper
2. **S-box Function**: Implements the proper x^5 power mapping
3. **Linear Layer**: Uses an MDS matrix for optimal diffusion
4. **Round Structure**: Follows the recommended pattern of full and partial rounds
5. **Output**: Produces different outputs for different inputs

## Usage

The implementation can be used with the schmivitz library for VOLE-in-the-Head proofs. The field size is determined by the FIELD_SIZE parameter in the schmivitz library.

To generate and verify proofs:

```rust
// For F_2 implementation (FIELD_SIZE = 2)
generate_and_verify_proof_f2();

// For F_128 implementation (FIELD_SIZE = 128)
generate_and_verify_proof_f128();

// For Fp implementation (FIELD_SIZE = 2305843009213693951)
generate_and_verify_proof_fp();
```

## Security Considerations

- The F_2 implementation is primarily for demonstration purposes and has limited security properties
- The F_128 implementation provides better security than F_2, but still less than the theoretical design
- The Fp implementation provides the strongest security guarantees, closest to the theoretical Poseidon design
- For production use, the Fp implementation is recommended, with proper security analysis
