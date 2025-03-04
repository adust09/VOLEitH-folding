// This is a simple example of how to use the Nova folding scheme to prove a Merkle proof.
// The Tree-PRG VC using keccak as a hash function, but this example uses SHA-256 for simplicity.
// schmivitz using blake3
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(clippy::upper_case_acronyms)]

use ark_bn254::{Bn254, Fr, G1Projective as Projective};
use ark_crypto_primitives::crh::{
    sha256::{
        constraints::{Sha256Gadget, UnitVar},
        Sha256,
    },
    CRHScheme, TwoToOneCRHScheme, TwoToOneCRHSchemeGadget,
};
use ark_ff::PrimeField;
use ark_grumpkin::Projective as Projective2;
use ark_r1cs_std::{
    alloc::AllocVar, boolean::Boolean, convert::ToConstraintFieldGadget, fields::fp::FpVar,
    prelude::*,
};
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};
use core::marker::PhantomData;
use folding_schemes::{
    commitment::{kzg::KZG, pedersen::Pedersen},
    folding::nova::{Nova, PreprocessorParam},
    frontend::FCircuit,
    transcript::poseidon::poseidon_canonical_config,
    Error, FoldingScheme,
};
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
// Define a concrete implementation of TwoToOneCRHScheme using Sha256
#[derive(Clone, Debug)]
pub struct MerkleCRH;

impl TwoToOneCRHScheme for MerkleCRH {
    type Parameters = ();
    type Input = [u8; 32];
    type Output = [u8; 32];

    fn setup<R: rand::Rng>(_rng: &mut R) -> Result<Self::Parameters, ark_crypto_primitives::Error> {
        Ok(())
    }

    fn evaluate<T: Borrow<Self::Input>>(
        _parameters: &Self::Parameters,
        left_input: T,
        right_input: T,
    ) -> Result<Self::Output, ark_crypto_primitives::Error> {
        let left = left_input.borrow();
        let right = right_input.borrow();

        let mut input = left.to_vec();
        input.extend_from_slice(right);

        let digest_vec = <Sha256 as CRHScheme>::evaluate(&(), input.as_slice())?;

        // Convert Vec<u8> to [u8; 32]
        let mut digest = [0u8; 32];
        for (i, byte) in digest_vec.iter().enumerate().take(32) {
            digest[i] = *byte;
        }

        Ok(digest)
    }

    fn compress<T: Borrow<Self::Output>>(
        parameters: &Self::Parameters,
        left_input: T,
        right_input: T,
    ) -> Result<Self::Output, ark_crypto_primitives::Error> {
        Self::evaluate(parameters, left_input, right_input)
    }
}

// Define a custom type for the output of MerkleCRHGadget
#[derive(Clone, Debug)]
pub struct DigestVar<F: PrimeField>(pub Vec<UInt8<F>>);

impl<F: PrimeField> AllocVar<[u8; 32], F> for DigestVar<F> {
    fn new_variable<T: Borrow<[u8; 32]>>(
        cs: impl Into<ark_relations::r1cs::Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: ark_r1cs_std::alloc::AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();
        let bytes = f()?;
        let bytes_as_vec = bytes.borrow().to_vec();

        let mut byte_vars = Vec::with_capacity(32);
        for byte in bytes_as_vec.iter() {
            byte_vars.push(UInt8::new_variable(cs.clone(), || Ok(byte), mode)?);
        }

        Ok(DigestVar(byte_vars))
    }
}

impl<F: PrimeField> EqGadget<F> for DigestVar<F> {
    fn is_eq(&self, other: &Self) -> Result<Boolean<F>, SynthesisError> {
        // Check if all bytes are equal
        let mut eq_checks = Vec::new();
        for (a, b) in self.0.iter().zip(other.0.iter()) {
            eq_checks.push(a.is_eq(b)?);
        }

        // Use Boolean::kary_and to combine all equality checks
        Boolean::kary_and(&eq_checks)
    }
}

impl<F: PrimeField> R1CSVar<F> for DigestVar<F> {
    type Value = [u8; 32];

    fn cs(&self) -> ark_relations::r1cs::ConstraintSystemRef<F> {
        self.0[0].cs()
    }

    fn value(&self) -> Result<Self::Value, SynthesisError> {
        let mut result = [0u8; 32];
        for (i, byte) in self.0.iter().enumerate().take(32) {
            result[i] = byte.value()?;
        }
        Ok(result)
    }
}

impl<F: PrimeField> ToBytesGadget<F> for DigestVar<F> {
    fn to_bytes_le(&self) -> Result<Vec<UInt8<F>>, SynthesisError> {
        Ok(self.0.clone())
    }
}

impl<F: PrimeField> CondSelectGadget<F> for DigestVar<F> {
    fn conditionally_select(
        cond: &Boolean<F>,
        true_value: &Self,
        false_value: &Self,
    ) -> Result<Self, SynthesisError> {
        let mut result = Vec::with_capacity(32);
        for (a, b) in true_value.0.iter().zip(false_value.0.iter()) {
            result.push(UInt8::conditionally_select(cond, a, b)?);
        }
        Ok(DigestVar(result))
    }
}

// Define the corresponding gadget for MerkleCRH
#[derive(Clone, Debug)]
pub struct MerkleCRHGadget;

impl<F: PrimeField> TwoToOneCRHSchemeGadget<MerkleCRH, F> for MerkleCRHGadget {
    type InputVar = DigestVar<F>;
    type OutputVar = DigestVar<F>;
    type ParametersVar = ();

    fn evaluate(
        _parameters: &Self::ParametersVar,
        left_input: &Self::InputVar,
        right_input: &Self::InputVar,
    ) -> Result<Self::OutputVar, SynthesisError> {
        let mut input = left_input.0.clone();
        input.extend_from_slice(&right_input.0);

        let unit_var = UnitVar::default();
        let digest =
            <Sha256Gadget<F> as ark_crypto_primitives::crh::CRHSchemeGadget<Sha256, F>>::evaluate(
                &unit_var, &input,
            )?;

        Ok(DigestVar(digest.0))
    }

    fn compress(
        parameters: &Self::ParametersVar,
        left_input: &Self::OutputVar,
        right_input: &Self::OutputVar,
    ) -> Result<Self::OutputVar, SynthesisError> {
        Self::evaluate(parameters, left_input, right_input)
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
            &MerkleCRHGadget::evaluate(&(), &sibling_digest, &z_digest)?,
            // If is_left is false, the current node is on the left, sibling on the right
            &MerkleCRHGadget::evaluate(&(), &z_digest, &sibling_digest)?,
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

#[cfg(test)]
mod tests {
    use super::*;
    use rand::Rng;

    #[test]
    fn test_merkle_proof_fcircuit() {
        use ark_bn254::Fr;
        use ark_r1cs_std::{alloc::AllocVar, fields::fp::FpVar};
        use ark_relations::r1cs::ConstraintSystem;

        let cs = ConstraintSystem::<Fr>::new_ref();

        let initial_state_value = Fr::from(1_u32);
        let initial_state = FpVar::new_witness(cs.clone(), || Ok(initial_state_value)).unwrap();

        let mut proof_step_value = MerkleProofStep { sibling: [0u8; 32], is_left: true };
        rand::thread_rng().fill(&mut proof_step_value.sibling);
        let proof_step =
            MerkleProofStepVar::new_witness(cs.clone(), || Ok(proof_step_value)).unwrap();

        let circuit = MerkleProofFCircuit::<Fr>::new(()).unwrap();

        let next_state = circuit
            .generate_step_constraints(cs.clone(), 0, vec![initial_state], proof_step)
            .unwrap();

        assert!(cs.is_satisfied().unwrap());
        assert_eq!(next_state.len(), 1);
    }
}
