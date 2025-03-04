## All-but-One Vector Commitment Folding Program Design

### 1. Overview

This document outlines the design of a folding program for the reconstruct and verify functions of the All-but-One Vector Commitment (Tree-PRG Vector Commitments) scheme. The goal is to reduce the computational complexity of these functions, making them more efficient to execute within a zkSNARK circuit, particularly for Ethereum smart contract verification.

### 2. Background

The All-but-One Vector Commitment scheme involves committing to a vector of values using a GGM tree and a hash function (Blake3). The reconstruct function reconstructs all the leaf nodes except for one, and the verify function checks if the reconstructed commitment matches the original commitment. The implementation uses AES-ECB as a PRG and Blake3 as a hash function.

### 3. Folding Approach

We will use the Nova folding scheme to compress the computation of the reconstruct and verify functions. The main idea is to represent the state of the computation as a vector and iteratively fold the computation steps into this state.

### 4. State Representation

The state of the folding program will consist of the following elements:

*   `h`: The original commitment (H1 hash - two `U8x16` values).
*   `pdecom`: The partial decommitment (vector of sibling node keys - `Key` which is `U8x16`).
*   `index_bits`: The bit representation of the index of the unopened leaf node (vector of booleans).
*   `iv`: The initialization vector for the hash function (`IV` which is `U8x16`).
*   `current_level`: The current level in the GGM tree being processed (usize).
*   `current_node_keys_left`: The left keys of the nodes at the current level (vector of `Key` which is `U8x16`).
*   `current_node_keys_right`: The right keys of the nodes at the current level (vector of `Key` which is `U8x16`).
*   `current_coms`: The commitments of the nodes at the current level (vector of `Com` which is a tuple of two `U8x16`).
*   `reconstructed_coms`: Vector of reconstructed commitments.
*   `h_computed`: The computed H1 hash (two `U8x16` values).

### 5. Folding Steps

The folding program will iterate through the levels of the GGM tree, performing the following steps in each iteration:

1.  **Reconstruct Node Keys:**
    *   At each level `i`, reconstruct the node keys based on `index_bits[i]` and `pdecom[i]`.
    *   If `index_bits[i]` is 0, the left key is from `pdecom` and the right key is derived from the parent.
    *   If `index_bits[i]` is 1, the right key is from `pdecom` and the left key is derived from the parent.
    *   Use the AES-ECB PRG to derive the child keys from the parent key.
2.  **Hash Leaf Nodes (if applicable):**
    *   If the current level is the leaf level (i.e., `current_level == depth`), hash the reconstructed node keys to obtain the seeds and commitments using Blake3.
    *   Store the resulting commitments in `current_coms`.
3.  **Update Commitment:**
    *   After processing all leaf nodes, compute the H1 hash by concatenating all commitments in `current_coms` and hashing the result using Blake3.
    *   Store the result in `h_computed`.
4.  **Update State:**
    *   Increment `current_level`.
    *   Update `current_node_keys_left` and `current_node_keys_right` with the newly computed keys.

### 6. Verify Function Folding

The verify function will be folded by incorporating the commitment check (`h == h_computed`) into the folding process. The state will include the original commitment `h`, and the folding program will compute the reconstructed commitment `h_computed`. After folding all the levels, the program will check if `h == h_computed`.

### 7. Circuit Design

The folding program will be implemented as a zkSNARK circuit. The circuit will take the initial state as input and iteratively fold the computation steps into the state. The circuit will also enforce the following constraints:

*   **PRG Constraint (AES-ECB):**
    *   Ensure that the AES-ECB encryption is performed correctly. This might involve using lookup tables or other techniques to efficiently implement AES within the circuit.
    *   Verify that the correct keys are used for the AES-ECB encryption.
*   **Hash Function Constraint (Blake3):**
    *   Ensure that the Blake3 hashing is performed correctly. This might involve using a pre-existing Blake3 implementation within the circuit or implementing a custom version.
    *   Verify that the correct inputs are used for the Blake3 hashing.
*   **Commitment Check Constraint (`h == h_computed`):**
    *   Ensure that the computed H1 hash (`h_computed`) matches the original commitment `h`.
    *   This involves comparing the two `U8x16` values that make up the H1 hash.
*   **Key Reconstruction Constraint:**
    *   Verify that the keys are reconstructed correctly based on the `index_bits` and `pdecom`.
    *   If `index_bits[i]` is 0, ensure that `current_node_keys_left[i]` is equal to `pdecom[i]` and that `current_node_keys_right[i]` is derived correctly from the parent.
    *   If `index_bits[i]` is 1, ensure that `current_node_keys_right[i]` is equal to `pdecom[i]` and that `current_node_keys_left[i]` is derived correctly from the parent.

### 8. Implementation Details

*   **Folding Scheme:** Nova
*   **Hash Function:** Blake3 (arkworks)
*   **PRG:** AES-ECB (vectoreyes crate)
*   **Circuit Framework:** Use a suitable circuit framework (e.g., Circom, SnarkyJS) to implement the zkSNARK circuit.

### 9. Next Steps

1.  Examine the folding implementation in `/Users/ts21/dev/sonobe` (Nova) to understand how folding works.
2.  Implement the folding program as a zkSNARK circuit.
3.  Test the folding program to ensure that it correctly folds the reconstruct and verify functions.
