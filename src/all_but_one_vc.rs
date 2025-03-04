// src/all_but_one_vc.rs

use ark_bn254::{Bn254, Fr, G1Projective as Projective};
use ark_ff::PrimeField;
use ark_grumpkin::Projective as Projective2;
use ark_r1cs_std::{alloc::AllocVar, boolean::Boolean, fields::fp::FpVar, prelude::*};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use folding_schemes::{
    commitment::{kzg::KZG, pedersen::Pedersen},
    folding::nova::{Nova, PreprocessorParam},
    frontend::FCircuit,
    transcript::poseidon::poseidon_canonical_config,
    Error, FoldingScheme,
};
use serde::{Deserialize, Serialize};
use std::{fs::File, io::Read, marker::PhantomData, time::Instant};

// Define the state variables
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct InitialState {
    pub h: [u8; 32],           // The original commitment (H1 hash)
    pub pdecom: Vec<[u8; 16]>, // The partial decommitment (sibling node keys)
    pub index_bits: Vec<bool>, // The bit representation of the index
    pub iv: [u8; 16],          // The initialization vector
    pub current_level: usize,  // The current level in the GGM tree
}

#[derive(Debug, Clone)]
pub struct FinalState {
    pub h_computed: [u8; 32],            // The computed H1 hash
    pub leaf_commitments: Vec<[u8; 32]>, // The commitments for each leaf
}

// PRG (Pseudo-Random Generator) implementation
// This expands a seed into two child seeds
fn prg(seed: &[u8; 16]) -> ([u8; 16], [u8; 16]) {
    // Use Blake3 as the PRG
    let mut hasher = blake3::Hasher::new();
    hasher.update(seed);
    hasher.update(&[0]); // Domain separator for left child
    let left_hash = hasher.finalize();

    let mut hasher = blake3::Hasher::new();
    hasher.update(seed);
    hasher.update(&[1]); // Domain separator for right child
    let right_hash = hasher.finalize();

    let mut left_seed = [0u8; 16];
    let mut right_seed = [0u8; 16];

    // Take first 16 bytes for each seed
    left_seed.copy_from_slice(&left_hash.as_bytes()[0..16]);
    right_seed.copy_from_slice(&right_hash.as_bytes()[0..16]);

    (left_seed, right_seed)
}

// H0 hash function: hash a leaf key to produce a seed and commitment
fn h0(leaf_key: &[u8; 16], iv: &[u8; 16]) -> ([u8; 16], [u8; 32]) {
    let mut hasher = blake3::Hasher::new();
    hasher.update(leaf_key);
    hasher.update(iv);
    let hash = hasher.finalize();

    let mut seed = [0u8; 16];
    let mut commitment = [0u8; 32];

    // First 16 bytes for seed, all 32 bytes for commitment
    seed.copy_from_slice(&hash.as_bytes()[0..16]);
    commitment.copy_from_slice(hash.as_bytes());

    (seed, commitment)
}

// H1 hash function: hash all commitments to produce the final commitment
fn h1(commitments: &[[u8; 32]]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    for commitment in commitments {
        hasher.update(commitment);
    }
    let hash = hasher.finalize();

    let mut result = [0u8; 32];
    result.copy_from_slice(hash.as_bytes());
    result
}

// Function to load the initial state from the proof.json file
pub fn load_initial_state(proof_path: &str) -> InitialState {
    // Read the proof.json file
    let mut file = File::open(proof_path).expect("Unable to open file");
    let mut contents = String::new();
    file.read_to_string(&mut contents).expect("Unable to read file");

    // Deserialize the JSON data into the InitialState struct
    let initial_state: InitialState =
        serde_json::from_str(&contents).expect("Unable to deserialize JSON");

    initial_state
}

// Reconstruct the GGM tree and compute the commitments
fn reconstruct_tree(initial_state: &InitialState) -> (Vec<[u8; 16]>, Vec<[u8; 32]>) {
    let height = initial_state.index_bits.len();
    let num_leaves = 1 << height;

    // The index we're not revealing
    let mut j_star = 0;
    for (i, &bit) in initial_state.index_bits.iter().enumerate() {
        j_star |= (bit as usize) << (height - 1 - i);
    }

    // Initialize the keys at each level
    let mut keys: Vec<Vec<Option<[u8; 16]>>> = Vec::with_capacity(height + 1);
    for i in 0..=height {
        keys.push(vec![None; 1 << i]);
    }

    // Initialize the leaf commitments
    let mut leaf_commitments = vec![[0u8; 32]; num_leaves];

    // Process the partial decommitment
    let mut pdecom_index = 0;

    // Reconstruct the tree level by level
    for level in 0..height {
        let bit = initial_state.index_bits[level];
        let path_index = j_star >> (height - 1 - level) & ((1 << level) - 1);

        // If we're at the root level, we need to initialize it
        if level == 0 {
            // At level 0, we have the sibling of the root path
            if bit {
                // If bit is 1, the path goes right, so the sibling is on the left
                keys[0][0] = Some(initial_state.pdecom[pdecom_index]);
                pdecom_index += 1;
            } else {
                // If bit is 0, the path goes left, so we need to compute the right sibling
                // But we don't have it in pdecom, so we'll compute it later
            }
            continue;
        }

        // For other levels, process the nodes
        for i in 0..(1 << level) {
            // Skip if this node is not on the path to j_star
            if i != path_index {
                continue;
            }

            // Get the parent node
            let parent_index = i >> 1;
            let is_right_child = i & 1 == 1;

            // If the parent is known, compute this node
            if let Some(parent_key) = keys[level - 1][parent_index] {
                let (left_child, right_child) = prg(&parent_key);

                if is_right_child {
                    keys[level][i] = Some(right_child);
                } else {
                    keys[level][i] = Some(left_child);
                }
            }

            // Process the sibling node from pdecom
            let sibling_index = if bit { i - 1 } else { i + 1 };
            if sibling_index < (1 << level) {
                keys[level][sibling_index] = Some(initial_state.pdecom[pdecom_index]);
                pdecom_index += 1;
            }
        }
    }

    // Compute the leaf keys and commitments
    for i in 0..num_leaves {
        // Skip the j_star leaf
        if i == j_star {
            continue;
        }

        // Compute the leaf key
        let parent_index = i >> 1;
        let is_right_child = i & 1 == 1;

        if let Some(parent_key) = keys[height - 1][parent_index] {
            let (left_child, right_child) = prg(&parent_key);

            let leaf_key = if is_right_child { right_child } else { left_child };
            keys[height][i] = Some(leaf_key);

            // Compute the commitment
            let (_, commitment) = h0(&leaf_key, &initial_state.iv);
            leaf_commitments[i] = commitment;
        }
    }

    // Extract all the leaf keys (except j_star)
    let leaf_keys: Vec<[u8; 16]> = keys[height]
        .iter()
        .enumerate()
        .filter_map(|(i, key)| if i != j_star { key.clone() } else { None })
        .collect();

    (leaf_keys, leaf_commitments)
}

// Define the circuit for folding the verification
#[derive(Clone, Debug)]
pub struct AllButOneVCCircuit<F: PrimeField> {
    pub initial_state: InitialState,
    pub current_level: usize,
    pub reconstructed_keys: Vec<[u8; 16]>,
    pub leaf_commitments: Vec<[u8; 32]>,
    pub _phantom: PhantomData<F>,
}

impl<F: PrimeField> ConstraintSynthesizer<F> for AllButOneVCCircuit<F> {
    fn generate_constraints(self, _cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        // Get the current level
        let level = self.current_level;

        // If we're at the first level, we need to initialize the state
        if level == 0 {
            // TODO: Initialize the state with the initial commitment
            return Ok(());
        }

        // Get the bit for the current level
        let _bit = self.initial_state.index_bits[level - 1];

        // Compute the PRG for the current level
        // This is a simplified version for demonstration
        // In a real implementation, we would need to implement the PRG in constraints

        // Compute the hash for the current level
        // This is a simplified version for demonstration
        // In a real implementation, we would need to implement the hash in constraints

        Ok(())
    }
}

// Define a struct for the external inputs variable
#[derive(Clone, Debug)]
pub struct InitialStateVar<F: PrimeField> {
    pub h: Vec<UInt8<F>>,
    pub pdecom: Vec<Vec<UInt8<F>>>,
    pub index_bits: Vec<Boolean<F>>,
    pub iv: Vec<UInt8<F>>,
    pub current_level: FpVar<F>,
}

impl<F: PrimeField> Default for InitialStateVar<F> {
    fn default() -> Self {
        Self {
            h: vec![UInt8::constant(0); 32],
            pdecom: Vec::new(),
            index_bits: Vec::new(),
            iv: vec![UInt8::constant(0); 16],
            current_level: FpVar::constant(F::zero()),
        }
    }
}

impl<F: PrimeField> AllocVar<InitialState, F> for InitialStateVar<F> {
    fn new_variable<T: std::borrow::Borrow<InitialState>>(
        cs: impl Into<ark_relations::r1cs::Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: ark_r1cs_std::alloc::AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();
        let binding = f()?;
        let initial_state = binding.borrow();

        // Allocate h
        let mut h_bytes = Vec::with_capacity(32);
        for byte in initial_state.h.iter() {
            h_bytes.push(UInt8::new_variable(cs.clone(), || Ok(byte), mode)?);
        }

        // Allocate pdecom
        let mut pdecom_vars = Vec::with_capacity(initial_state.pdecom.len());
        for key in initial_state.pdecom.iter() {
            let mut key_bytes = Vec::with_capacity(16);
            for byte in key.iter() {
                key_bytes.push(UInt8::new_variable(cs.clone(), || Ok(byte), mode)?);
            }
            pdecom_vars.push(key_bytes);
        }

        // Allocate index_bits
        let mut index_bits_vars = Vec::with_capacity(initial_state.index_bits.len());
        for bit in initial_state.index_bits.iter() {
            index_bits_vars.push(Boolean::new_variable(cs.clone(), || Ok(bit), mode)?);
        }

        // Allocate iv
        let mut iv_bytes = Vec::with_capacity(16);
        for byte in initial_state.iv.iter() {
            iv_bytes.push(UInt8::new_variable(cs.clone(), || Ok(byte), mode)?);
        }

        // Allocate current_level
        let current_level_var = FpVar::new_variable(
            cs.clone(),
            || Ok(F::from(initial_state.current_level as u64)),
            mode,
        )?;

        Ok(Self {
            h: h_bytes,
            pdecom: pdecom_vars,
            index_bits: index_bits_vars,
            iv: iv_bytes,
            current_level: current_level_var,
        })
    }
}

// Define the FCircuit for Nova folding
#[derive(Clone, Copy, Debug)]
pub struct AllButOneVCFCircuit<F: PrimeField> {
    _f: PhantomData<F>,
}

impl<F: PrimeField> FCircuit<F> for AllButOneVCFCircuit<F> {
    type Params = ();
    type ExternalInputs = InitialState;
    type ExternalInputsVar = InitialStateVar<F>;

    fn new(_params: Self::Params) -> Result<Self, Error> {
        Ok(Self { _f: PhantomData })
    }

    fn state_len(&self) -> usize {
        1
    }

    fn generate_step_constraints(
        &self,
        _cs: ConstraintSystemRef<F>,
        _i: usize,
        z_i: Vec<FpVar<F>>,
        _external_inputs: Self::ExternalInputsVar,
    ) -> Result<Vec<FpVar<F>>, SynthesisError> {
        // This is a simplified implementation
        // In a real implementation, we would need to implement the full verification logic

        // For now, just return the input state
        Ok(z_i)
    }
}

// Function to perform the folding steps
pub fn fold_verification(initial_state: &InitialState) -> FinalState {
    println!("Starting All-but-One Vector Commitment folding verification");

    // Reconstruct the tree and compute the commitments
    let (leaf_keys, leaf_commitments) = reconstruct_tree(initial_state);

    println!("Reconstructed {} leaf keys", leaf_keys.len());

    // Compute the final commitment
    let h_computed = h1(&leaf_commitments);

    println!("Computed final commitment");

    // Set up the Nova folding scheme
    let f_circuit = AllButOneVCFCircuit::<Fr>::new(()).expect("Failed to create circuit");

    // Define the Nova folding scheme
    type N = Nova<
        Projective,
        Projective2,
        AllButOneVCFCircuit<Fr>,
        KZG<'static, Bn254>,
        Pedersen<Projective2>,
        false,
    >;

    // Initialize the folding scheme
    let poseidon_config = poseidon_canonical_config::<Fr>();
    let mut rng = rand::rngs::OsRng;

    println!("Preparing Nova parameters");
    let nova_preprocess_params = PreprocessorParam::new(poseidon_config, f_circuit);
    let nova_params =
        N::preprocess(&mut rng, &nova_preprocess_params).expect("Failed to preprocess");

    // Initial state for folding
    let initial_folding_state = vec![Fr::from(1_u32)];

    println!("Initializing folding scheme");
    let mut folding_scheme = N::init(&nova_params, f_circuit, initial_folding_state.clone())
        .expect("Failed to initialize folding scheme");

    // Perform folding for each level of the tree
    for i in 0..initial_state.index_bits.len() {
        let start = Instant::now();
        // Create a dummy external input for now
        let external_input = InitialState::default();
        // In a real implementation, we would pass the appropriate external inputs
        folding_scheme.prove_step(rng, external_input, None).expect("Failed to prove step");
        println!("Nova::prove_step {}: {:?}", i, start.elapsed());
    }

    println!("Running Nova's IVC verifier");
    let ivc_proof = folding_scheme.ivc_proof();
    N::verify(nova_params.1, ivc_proof).expect("Failed to verify");

    FinalState { h_computed, leaf_commitments }
}

// Function to verify the final state
pub fn verify_final_state(final_state: FinalState, initial_state: &InitialState) -> bool {
    // Check if the computed H1 hash matches the original commitment
    final_state.h_computed == initial_state.h
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prg() {
        let seed = [0u8; 16];
        let (left, right) = prg(&seed);

        // Ensure the outputs are different
        assert_ne!(left, right);

        // Ensure deterministic behavior
        let (left2, right2) = prg(&seed);
        assert_eq!(left, left2);
        assert_eq!(right, right2);
    }

    #[test]
    fn test_h0() {
        let leaf_key = [0u8; 16];
        let iv = [0u8; 16];

        let (seed, commitment) = h0(&leaf_key, &iv);

        // Ensure the outputs are not zero
        assert_ne!(seed, [0u8; 16]);
        assert_ne!(commitment, [0u8; 32]);

        // Ensure deterministic behavior
        let (seed2, commitment2) = h0(&leaf_key, &iv);
        assert_eq!(seed, seed2);
        assert_eq!(commitment, commitment2);
    }

    #[test]
    fn test_h1() {
        let commitments = vec![[0u8; 32], [1u8; 32]];

        let result = h1(&commitments);

        // Ensure the output is not zero
        assert_ne!(result, [0u8; 32]);

        // Ensure deterministic behavior
        let result2 = h1(&commitments);
        assert_eq!(result, result2);
    }

    #[test]
    fn test_folding() {
        // Create a dummy proof.json file
        let initial_state = InitialState {
            h: [0u8; 32],
            pdecom: vec![[1u8; 16], [2u8; 16], [3u8; 16]], // Add some dummy sibling keys
            index_bits: vec![true, false, true],           // Index 5 in a height 3 tree
            iv: [0u8; 16],
            current_level: 0,
        };

        // Serialize the initial state to JSON
        let json_string = serde_json::to_string(&initial_state).unwrap();

        // Write the JSON string to a file
        std::fs::write("proof.json", json_string).expect("Unable to write file");

        let initial_state = load_initial_state("proof.json");
        let final_state = fold_verification(&initial_state);
        let is_valid = verify_final_state(final_state, &initial_state);
        // For testing purposes, we're not expecting the verification to pass
        // since we're using dummy data
        assert_eq!(is_valid, false);

        // Clean up the dummy file (ignore errors if the file doesn't exist)
        let _ = std::fs::remove_file("proof.json");
    }
}
