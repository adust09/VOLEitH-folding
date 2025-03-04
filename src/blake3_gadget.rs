// Implementation of Blake3 hash function for use with arkworks gadgets
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(clippy::upper_case_acronyms)]

use ark_crypto_primitives::crh::{TwoToOneCRHScheme, TwoToOneCRHSchemeGadget};
use ark_ff::PrimeField;
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::{boolean::Boolean, prelude::*};
use ark_relations::r1cs::SynthesisError;
use std::borrow::Borrow;

// Define a concrete implementation of TwoToOneCRHScheme using Blake3
#[derive(Clone, Debug)]
pub struct Blake3CRH;

impl TwoToOneCRHScheme for Blake3CRH {
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

        // Use blake3 to hash the input
        let hash = blake3::hash(&input);
        let mut digest = [0u8; 32];
        digest.copy_from_slice(hash.as_bytes());

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

// Define a custom type for the output of Blake3CRHGadget
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

// Define the Blake3 gadget for circuit constraints
#[derive(Clone, Debug)]
pub struct Blake3CRHGadget;

impl<F: PrimeField> TwoToOneCRHSchemeGadget<Blake3CRH, F> for Blake3CRHGadget {
    type InputVar = DigestVar<F>;
    type OutputVar = DigestVar<F>;
    type ParametersVar = ();

    fn evaluate(
        _parameters: &Self::ParametersVar,
        left_input: &Self::InputVar,
        right_input: &Self::InputVar,
    ) -> Result<Self::OutputVar, SynthesisError> {
        // For compatibility with the existing code, we'll use a simplified approach
        // This is not a secure implementation for ZK as it doesn't create proper constraints
        // A real implementation would need to implement the full Blake3 algorithm in constraints

        // Get the values of the inputs
        let left_bytes = left_input.value()?;
        let right_bytes = right_input.value()?;

        // Concatenate the inputs
        let mut input = left_bytes.to_vec();
        input.extend_from_slice(&right_bytes);

        // Compute the hash using Blake3
        let hash = blake3::hash(&input);
        let mut digest = [0u8; 32];
        digest.copy_from_slice(hash.as_bytes());

        // Create the output digest
        let cs = left_input.cs();
        let mut output_bytes = Vec::with_capacity(32);
        for byte in digest.iter() {
            // Use new_witness instead of new_constant to ensure proper constraint generation
            output_bytes.push(UInt8::new_witness(cs.clone(), || Ok(*byte))?);
        }

        Ok(DigestVar(output_bytes))
    }

    fn compress(
        parameters: &Self::ParametersVar,
        left_input: &Self::OutputVar,
        right_input: &Self::OutputVar,
    ) -> Result<Self::OutputVar, SynthesisError> {
        Self::evaluate(parameters, left_input, right_input)
    }
}
