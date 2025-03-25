# Poseidon Hash Function for F64 Field

This directory contains implementations of the Poseidon hash function for the 64-bit field (F_{2^64}).

## Directory Structure

- `single/`: Implementation for a single Poseidon hash in F_{2^64}
  - `circuit.txt`: Circuit definition for the F_{2^64} Poseidon hash
  - `private.txt`: Private inputs for the F_{2^64} circuit
  - `public.txt`: Public inputs for the F_{2^64} circuit
- `hash_chain_10/`: Implementation for a chain of 10 Poseidon hashes

## F_{2^64} Implementation

The F_{2^64} implementation operates in the finite field of size 2^64 (18446744073709551616).

### Circuit Structure

1. **Field Definition**:
   - Uses the field of size 2^64: `@type field 18446744073709551616`

2. **State Initialization**:
   - Takes 3 private inputs to initialize a state of size t=3
   - Uses `@add` with zero for initialization

3. **Round Structure**:
   - **Full Rounds (first set)**: 4 complete rounds where all state elements are processed through the S-box
   - **Partial Rounds**: Only the first state element goes through the S-box
   - **Full Rounds (last set)**: 2 complete rounds at the end

4. **S-box Implementation**:
   - Uses x^5 as the S-box function
   - Computed as a sequence of multiplications:
     ```
     x^2 = x * x
     x^4 = x^2 * x^2
     x^5 = x^4 * x
     ```

5. **Linear Layer (MDS Matrix)**:
   - Uses a 3×3 MDS matrix with the following structure:
     ```
     [ 2 3 1 ]
     [ 1 2 3 ]
     [ 3 1 2 ]
     ```
   - Implemented through a series of multiplications and additions

6. **Round Constants**:
   - Each round adds specific constants to the state
   - Constants are provided as private inputs

7. **Output Calculation**:
   - The first element of the final state is used as the hash output

### Performance Characteristics

The F_{2^64} implementation is optimized for:

1. **Security**: The implementation provides preimage and collision resistance through the one-way property of the Poseidon permutation.

2. **Efficiency**:
   - The use of partial rounds (where only one element goes through the S-box) significantly reduces the number of multiplications
   - The MDS matrix is designed for efficient implementation

3. **Field Operations**:
   - Addition and multiplication in F_{2^64} are efficiently implemented
   - The circuit minimizes the number of expensive operations (multiplications)

### Circuit Components Breakdown

| Component | Description | Operations |
|-----------|-------------|------------|
| State Initialization | Setup initial state with inputs | 3 additions |
| Full Rounds (first) | 4 rounds with complete S-box | 60 multiplications, 36 additions |
| Partial Rounds | 2 rounds with partial S-box | 6 multiplications, 18 additions |
| Full Rounds (last) | 2 rounds with complete S-box | 30 multiplications, 18 additions |
| Output Extraction | Get hash result from state | 1 addition |

### Hash Chain Implementation

The `hash_chain_10` directory contains an implementation of a chain of 10 sequential Poseidon hashes, where the output of each hash operation is used as input to the next one. This creates a longer computation history that demonstrates the composability of the hash function.

## Incomplete Parts in the Implementation

### 1. Zero Round Constants

All round constants are set to zeros:
```
$9 <- @private(0);  // Round constant 0
$10 <- @private(0);  // Round constant 1
$11 <- @private(0);  // Round constant 2
```
This is a critical security flaw. In a proper Poseidon implementation, round constants should be carefully selected cryptographically generated values, not zeros. Using zeros significantly weakens the hash function's security properties.

### 2. Insufficient Number of Partial Rounds

The implementation only includes 2 partial rounds:
```
// ===== PARTIAL ROUNDS =====
// Typically Poseidon uses around 30 partial rounds for t=3
// We'll implement a few for demonstration
```
According to the comment in the code itself, Poseidon should use around 30 partial rounds for t=3. The README confirms only 2 partial rounds are implemented, which is insufficient for security.

### 3. Missing Public Output Declaration

The hash output is computed but not properly marked as a public output:
```
// Output the first element of the state as the hash result
// Replace direct copy with add zero
$215 <- @add(0: $206, $3);  // Add zero to copy the output
```
There's no `@public` annotation to expose this value as the circuit's output.

### 4. Simplified MDS Matrix

The MDS matrix used is very simple:
```
[ 2 3 1 ]
[ 1 2 3 ]
[ 3 1 2 ]
```
While functional, standard Poseidon implementations typically use carefully constructed MDS matrices with specific properties to ensure optimal diffusion. There's no verification that this matrix is actually MDS (Maximum Distance Separable).

### 5. Hardcoded Parameters

The implementation uses hardcoded parameters:
- t=3 (state size)
- 4 initial full rounds
- 2 partial rounds
- 2 final full rounds

There's no explanation for why these specific parameters were chosen or how they relate to the security level.

### 6. MDS Coefficients as Private Inputs

The MDS matrix coefficients are provided as private inputs:
```
$24 <- @private(0);  // Coefficient 2
$25 <- @private(0);  // Coefficient 3
```
These should typically be hardcoded constants, not private inputs that could potentially be manipulated.
