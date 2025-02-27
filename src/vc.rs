// This is a simple example of how to use the Nova folding scheme to prove a Merkle proof.
// The Tree-PRG VC using keccak as a hash function, but this example uses SHA-256 for simplicity.
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(clippy::upper_case_acronyms)]

use ark_bn254::{Bn254, Fr, G1Projective as Projective};
use ark_crypto_primitives::crh::{
    sha256::constraints::{Sha256Gadget, UnitVar},
    CRHSchemeGadget, TwoToOneCRHScheme,
};
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

        let mut input_left = sibling_bytes.clone();
        input_left.extend(z_bytes.clone());
        let mut input_right = z_bytes;
        input_right.extend(sibling_bytes);

        let unit_var = UnitVar::default();
        let out_left = Sha256Gadget::evaluate(&unit_var, &input_left)?;
        let out_right = Sha256Gadget::evaluate(&unit_var, &input_right)?;

        let out_left_field = out_left.0.to_constraint_field()?;
        let out_right_field = out_right.0.to_constraint_field()?;
        let selected = ext
            .is_left
            .select(&out_left_field[0], &out_right_field[0])
            .map_err(|e| SynthesisError::from(e))?;
        Ok(vec![selected])
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
