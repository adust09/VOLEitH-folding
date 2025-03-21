use crate::gadget::prg_gadget::PRGGadget;
use ark_bn254::{Bn254, Fr, G1Projective as Projective};
use ark_crypto_primitives::crh::TwoToOneCRHSchemeGadget;
use ark_ff::PrimeField;
use ark_grumpkin::Projective as Projective2;
use ark_r1cs_std::{
    alloc::AllocVar, boolean::Boolean, fields::fp::FpVar, prelude::*, uint8::UInt8,
};
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};
use folding_schemes::{
    commitment::{kzg::KZG, pedersen::Pedersen},
    folding::nova::{Nova, PreprocessorParam},
    frontend::FCircuit,
    transcript::poseidon::poseidon_canonical_config,
    Error, FoldingScheme,
};
use serde::{Deserialize, Serialize};
use std::{fs::File, io::Read, marker::PhantomData, time::Instant};
fn prg_constraints<F: PrimeField>(
    cs: ConstraintSystemRef<F>,
    seed: &[UInt8<F>],
) -> Result<(Vec<UInt8<F>>, Vec<UInt8<F>>), SynthesisError> {
    PRGGadget::expand(cs, seed)
}

// H0 hash function for the constraint system
fn h0_constraints<F: PrimeField>(
    leaf_key: &[UInt8<F>],
    iv: &[UInt8<F>],
) -> Result<(Vec<UInt8<F>>, Vec<UInt8<F>>), SynthesisError> {
    use crate::gadget::blake3_gadget::{Blake3CRHGadget, DigestVar};

    // Concatenate the leaf key and IV
    let mut input = Vec::with_capacity(leaf_key.len() + iv.len());
    input.extend_from_slice(leaf_key);
    input.extend_from_slice(iv);

    // Pad to 32 bytes if needed
    while input.len() < 32 {
        input.push(UInt8::constant(0));
    }

    // Create a DigestVar from the input
    let input_digest = DigestVar(input[0..32].to_vec());

    // Hash the input using Blake3
    let hash_result =
        Blake3CRHGadget::evaluate(&(), &input_digest, &DigestVar(vec![UInt8::constant(0); 32]))?;

    // Extract the bytes
    let hash_bytes = hash_result.0;

    // Create the seed (first 16 bytes) and commitment (all 32 bytes)
    let seed = hash_bytes[0..16].to_vec();
    let commitment = hash_bytes.clone();

    Ok((seed, commitment))
}

// H1 hash function for the constraint system
fn h1_constraints<F: PrimeField>(
    commitments: &[Vec<UInt8<F>>],
) -> Result<Vec<UInt8<F>>, SynthesisError> {
    use crate::gadget::blake3_gadget::{Blake3CRHGadget, DigestVar};

    // Start with a zero digest
    let mut result = DigestVar(vec![UInt8::constant(0); 32]);

    // Hash each commitment
    for commitment in commitments {
        // Create a DigestVar from the commitment
        let commitment_digest = DigestVar(commitment.clone());

        // Hash the current result with the commitment
        result = Blake3CRHGadget::evaluate(&(), &result, &commitment_digest)?;
    }

    // Return the final hash
    Ok(result.0)
}

// todo: this struct should be fixed by Proof struct with swanky.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct InitialState {
    pub h: [u8; 32],           // The original commitment (H1 hash)
    pub pdecom: Vec<[u8; 16]>, // The partial decommitment (sibling node keys)
    pub index_bits: Vec<bool>, // The bit representation of the index
    pub iv: [u8; 16],          // The initialization vector
    pub current_level: usize,  // The current level in the GGM tree
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
    type ExternalInputs = InitialState; // this might be proof.json
    type ExternalInputsVar = InitialStateVar<F>;

    fn new(_params: Self::Params) -> Result<Self, Error> {
        Ok(Self { _f: PhantomData })
    }

    fn state_len(&self) -> usize {
        1
    }

    fn generate_step_constraints(
        &self,
        cs: ConstraintSystemRef<F>,
        _i: usize,
        z_i: Vec<FpVar<F>>,
        external_inputs: Self::ExternalInputsVar,
    ) -> Result<Vec<FpVar<F>>, SynthesisError> {
        // This is a simplified implementation
        // In a real implementation, we would need to implement the full verification logic
        let height = external_inputs.index_bits.len();
        let num_leaves = 1 << height;

        // The index we're not revealing
        let mut j_star = 0;
        for (i, &bit) in external_inputs.index_bits.iter().enumerate() {
            j_star |= bit << (height - 1 - i);
        }

        // For testing purposes, create a complete tree
        let mut tree: Vec<Vec<Option<[u8; 16]>>> = Vec::new();
        for i in 0..=height {
            tree.push(vec![None; 1 << i]);
        }

        // Initialize the leaf commitments
        let mut leaf_commitments = vec![[0u8; 32]; num_leaves];

        // Create a root seed (this is just for testing)
        let root_seed = [42u8; 16];
        tree[0][0] = Some(root_seed);

        // Expand the tree level by level
        for level in 0..height {
            for i in 0..(1 << level) {
                if let Some(seed) = tree[level][i] {
                    let (left, right) = prg_constraints(cs, &seed);
                    tree[level + 1][2 * i] = Some(left);
                    tree[level + 1][2 * i + 1] = Some(right);
                }
            }
        }

        // Compute the leaf commitments
        for i in 0..num_leaves {
            if let Some(leaf_key) = tree[height][i] {
                let commitment = h0_constraints(leaf_key, external_inputs.iv);
                leaf_commitments[i] = commitment;
            }
        }

        // Extract all the leaf keys (except j_star)
        let leaf_keys: Vec<[u8; 16]> = tree[height]
            .iter()
            .enumerate()
            .filter_map(|(i, key)| if i != j_star { key.clone() } else { None })
            .collect();

        (leaf_keys, leaf_commitments);
        let h_computed = h1_constraints(leaf_commitments);
        let is_valid = h_computed == external_inputs.h;
        // For now, just return the input state
        Ok(z_i)
    }
}

// Function to perform the folding steps
pub fn fold_verification() -> Result<(), Error> {
    let mut file = File::open("proof.json").expect("Unable to open file");
    let mut contents = String::new();
    file.read_to_string(&mut contents).expect("Unable to read file");

    // Deserialize the JSON data into the InitialState struct
    let external_inputs: InitialState =
        serde_json::from_str(&contents).expect("Unable to deserialize JSON");

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

    let nova_preprocess_params = PreprocessorParam::new(poseidon_config, f_circuit);
    let nova_params =
        N::preprocess(&mut rng, &nova_preprocess_params).expect("Failed to preprocess");

    // Initial state for folding
    let initial_folding_state = vec![Fr::from(1_u32)];

    let mut folding_scheme = N::init(&nova_params, f_circuit, initial_folding_state.clone())
        .expect("Failed to initialize folding scheme");

    // Perform folding for each level of the tree
    for i in 0..external_inputs.index_bits.len() {
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

    Ok(())
}
