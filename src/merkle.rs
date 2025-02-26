use ark_crypto_primitives::crh::{
    sha256::constraints::{Sha256Gadget, UnitVar},
    CRHSchemeGadget,
};
use ark_ff::PrimeField;
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::{
    boolean::Boolean, convert::ToConstraintFieldGadget, fields::fp::FpVar, prelude::*,
};
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};
use core::marker::PhantomData;
use folding_schemes::frontend::FCircuit;
use folding_schemes::Error;
use std::borrow::Borrow;

#[derive(Clone, Debug, Default)]
pub struct MerkleProofStep {
    pub sibling: [u8; 32],
    pub is_left: bool,
}

#[derive(Clone, Debug)]
pub struct MerkleProofStepVar<F: PrimeField> {
    pub sibling: FpVar<F>,
    pub is_left: Boolean<F>,
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
        cs: ConstraintSystemRef<F>,
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

        let selected = ext.is_left.select(&out_left_field[0], &out_right_field[0])?;
        Ok(vec![selected])
    }
}
