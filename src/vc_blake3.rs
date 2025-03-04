// This is an implementation of the Nova folding scheme to prove a Merkle proof using blake3.
// Based on the SHA-256 implementation in vc.rs
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(clippy::upper_case_acronyms)]

use ark_bn254::{Bn254, Fr, G1Projective as Projective};
use ark_crypto_primitives::crh::TwoToOneCRHSchemeGadget;
use ark_ff::PrimeField;
use ark_grumpkin::Projective as Projective2;
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::{
    boolean::Boolean, convert::ToConstraintFieldGadget, fields::fp::FpVar, prelude::*,
};

use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};
use core::marker::PhantomData;
use folding_schemes::{
    commitment::{kzg::KZG, pedersen::Pedersen},
    folding::nova::PreprocessorParam,
    frontend::FCircuit,
    transcript::poseidon::poseidon_canonical_config,
    FoldingScheme,
};
use folding_schemes::{folding::nova::Nova, Error};
use std::{borrow::Borrow, time::Instant};

// Import the Blake3 gadget implementation
use crate::blake3_gadget::{Blake3CRHGadget, DigestVar};

// Define the MerkleProofStep struct and its variable representation
#[derive(Clone, Debug, Default)]
pub struct MerkleProofStep {
    pub sibling: [u8; 32],
    pub is_left: bool,
}

impl<F: PrimeField> Default for MerkleProofStepVar<F> {
    fn default() -> Self {
        Self { sibling: FpVar::Constant(F::zero()), is_left: Boolean::Constant(false) }
    }
}

impl<F: PrimeField> AllocVar<MerkleProofStep, F> for MerkleProofStepVar<F> {
    fn new_variable<T: Borrow<MerkleProofStep>>(
        cs: impl Into<ark_relations::r1cs::Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: ark_r1cs_std::alloc::AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();
        let binding = f()?;
        let proof_step = binding.borrow();

        let sibling = FpVar::new_variable(
            cs.clone(),
            || Ok(F::from_le_bytes_mod_order(&proof_step.sibling)),
            mode,
        )?;
        let is_left = Boolean::new_variable(cs, || Ok(proof_step.is_left), mode)?;

        Ok(Self { sibling, is_left })
    }
}

#[derive(Clone, Debug)]
pub struct MerkleProofStepVar<F: PrimeField> {
    pub sibling: FpVar<F>,
    pub is_left: Boolean<F>,
}

#[derive(Clone, Copy, Debug)]
pub struct MerkleProofFCircuit<F: PrimeField> {
    _f: PhantomData<F>,
}

impl<F: PrimeField> FCircuit<F> for MerkleProofFCircuit<F> {
    type Params = ();
    type ExternalInputs = MerkleProofStep;
    type ExternalInputsVar = MerkleProofStepVar<F>;

    fn new(_params: Self::Params) -> Result<Self, Error> {
        Ok(Self { _f: PhantomData })
    }

    fn state_len(&self) -> usize {
        1
    }
    /// Generates constraints for the next state z_{i+1} using the current state z_i and external inputs (one step of proof).
    /// In the proof step, the input order of the hash changes depending on the value of is_left.
    fn generate_step_constraints(
        &self,
        _cs: ConstraintSystemRef<F>,
        _i: usize,
        z_i: Vec<FpVar<F>>,
        ext: Self::ExternalInputsVar,
    ) -> Result<Vec<FpVar<F>>, SynthesisError> {
        let z_bytes = z_i[0].to_bytes_le()?;
        let sibling_bytes = ext.sibling.to_bytes_le()?;

        // Convert bytes to DigestVar for the TwoToOneCRHScheme
        // We need to ensure we have exactly 32 bytes for each input
        let mut z_uint8 = Vec::new();
        let mut sibling_uint8 = Vec::new();

        // Pad or truncate to 32 bytes
        for i in 0..32 {
            if i < z_bytes.len() {
                z_uint8.push(z_bytes[i].clone());
            } else {
                z_uint8.push(UInt8::constant(0));
            }

            if i < sibling_bytes.len() {
                sibling_uint8.push(sibling_bytes[i].clone());
            } else {
                sibling_uint8.push(UInt8::constant(0));
            }
        }

        let z_digest = DigestVar(z_uint8);
        let sibling_digest = DigestVar(sibling_uint8);

        // Use TwoToOneCRHScheme to compute the hash
        // The order of inputs depends on whether the current node is the left or right child
        let hash_result = DigestVar::conditionally_select(
            &ext.is_left,
            // If is_left is true, the sibling is on the left, current node on the right
            &Blake3CRHGadget::evaluate(&(), &sibling_digest, &z_digest)?,
            // If is_left is false, the current node is on the left, sibling on the right
            &Blake3CRHGadget::evaluate(&(), &z_digest, &sibling_digest)?,
        )?;

        // Convert the DigestVar to a field element
        let hash_bytes = hash_result.to_bytes_le()?;
        let hash_field = hash_bytes.to_constraint_field()?;

        Ok(vec![hash_field[0].clone()])
    }
}

pub fn main() -> Result<(), Error> {
    let num_steps = 3;
    let initial_state = vec![Fr::from(1_u32)];

    let external_inputs = vec![MerkleProofStep { sibling: [0u8; 32], is_left: true }];

    let F_circuit = MerkleProofFCircuit::<Fr>::new(())?;

    type N = Nova<
        Projective,
        Projective2,
        MerkleProofFCircuit<Fr>,
        KZG<'static, Bn254>,
        Pedersen<Projective2>,
        false,
    >;
    let poseidon_config = poseidon_canonical_config::<Fr>();
    let mut rng = rand::rngs::OsRng;

    let nova_preprocessor_params = PreprocessorParam::new(poseidon_config, F_circuit);
    let nova_params = N::preprocess(&mut rng, &nova_preprocessor_params)?;

    let mut folding_scheme = N::init(&nova_params, F_circuit, initial_state.clone())?;
    for (_i, external_inputs_at_step) in external_inputs.iter().enumerate() {
        let start = Instant::now();
        folding_scheme.prove_step(rng, external_inputs_at_step.clone(), None)?;
        println!("Nova::prove_step time: {:?}", start.elapsed());
    }
    println!("state at last step (after {} iterations): {:?}", num_steps, folding_scheme.state());

    println!("Run the Nova's IVC verifier");
    let ivc_proof = folding_scheme.ivc_proof();
    N::verify(nova_params.1, ivc_proof)?;
    Ok(())
}
