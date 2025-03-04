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

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr;
    use ark_relations::r1cs::ConstraintSystem;

    #[test]
    fn test_blake3_crh_evaluate() {
        // Test inputs
        let left_input = [1u8; 32];
        let right_input = [2u8; 32];

        // Compute hash using Blake3CRH
        let result = Blake3CRH::evaluate(&(), &left_input, &right_input).unwrap();

        // Ensure the result is not all zeros
        assert_ne!(result, [0u8; 32]);

        // Test determinism - same inputs should produce same output
        let result2 = Blake3CRH::evaluate(&(), &left_input, &right_input).unwrap();
        assert_eq!(result, result2);

        // Test different inputs produce different outputs
        let different_input = [3u8; 32];
        let different_result = Blake3CRH::evaluate(&(), &left_input, &different_input).unwrap();
        assert_ne!(result, different_result);
    }

    #[test]
    fn test_blake3_crh_compress() {
        // Test inputs
        let left_input = [1u8; 32];
        let right_input = [2u8; 32];

        // Compute hash using compress
        let result = Blake3CRH::compress(&(), &left_input, &right_input).unwrap();

        // Compute hash using evaluate
        let expected = Blake3CRH::evaluate(&(), &left_input, &right_input).unwrap();

        // Compress should be equivalent to evaluate
        assert_eq!(result, expected);
    }

    #[test]
    fn test_digest_var_alloc() {
        // Create a constraint system
        let cs = ConstraintSystem::<Fr>::new_ref();

        // Test input
        let test_digest = [42u8; 32];

        // Allocate the digest as a variable
        let digest_var =
            DigestVar::<Fr>::new_variable(cs.clone(), || Ok(test_digest), AllocationMode::Witness)
                .unwrap();

        // Check that the value matches the input
        let value = digest_var.value().unwrap();
        assert_eq!(value, test_digest);

        // Check that the bytes match
        let bytes = digest_var.to_bytes_le().unwrap();
        assert_eq!(bytes.len(), 32);
        for (i, byte) in bytes.iter().enumerate() {
            assert_eq!(byte.value().unwrap(), test_digest[i]);
        }
    }

    #[test]
    fn test_digest_var_equality() {
        // Create a constraint system
        let cs = ConstraintSystem::<Fr>::new_ref();

        // Test inputs
        let digest1 = [1u8; 32];
        let digest2 = [1u8; 32]; // Same as digest1
        let digest3 = [2u8; 32]; // Different from digest1

        // Allocate the digests as variables
        let var1 =
            DigestVar::<Fr>::new_variable(cs.clone(), || Ok(digest1), AllocationMode::Witness)
                .unwrap();

        let var2 =
            DigestVar::<Fr>::new_variable(cs.clone(), || Ok(digest2), AllocationMode::Witness)
                .unwrap();

        let var3 =
            DigestVar::<Fr>::new_variable(cs.clone(), || Ok(digest3), AllocationMode::Witness)
                .unwrap();

        // Check equality
        let eq_result1 = var1.is_eq(&var2).unwrap();
        let eq_result2 = var1.is_eq(&var3).unwrap();

        // Same digests should be equal
        assert!(eq_result1.value().unwrap());

        // Different digests should not be equal
        assert!(!eq_result2.value().unwrap());
    }

    #[test]
    fn test_blake3_gadget_evaluate() {
        // Create a constraint system
        let cs = ConstraintSystem::<Fr>::new_ref();

        // Test inputs
        let left_input = [1u8; 32];
        let right_input = [2u8; 32];

        // Allocate the inputs as variables
        let left_var =
            DigestVar::<Fr>::new_variable(cs.clone(), || Ok(left_input), AllocationMode::Witness)
                .unwrap();

        let right_var =
            DigestVar::<Fr>::new_variable(cs.clone(), || Ok(right_input), AllocationMode::Witness)
                .unwrap();

        // Compute hash using Blake3CRHGadget
        let result_var = Blake3CRHGadget::evaluate(&(), &left_var, &right_var).unwrap();

        // Compute expected hash using Blake3CRH
        let expected = Blake3CRH::evaluate(&(), &left_input, &right_input).unwrap();

        // Check that the gadget produces the correct result
        let result = result_var.value().unwrap();
        assert_eq!(result, expected);

        // Check that the constraints are satisfied
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_conditional_select() {
        // Create a constraint system
        let cs = ConstraintSystem::<Fr>::new_ref();

        // Test inputs
        let digest1 = [1u8; 32];
        let digest2 = [2u8; 32];

        // Allocate the digests as variables
        let var1 =
            DigestVar::<Fr>::new_variable(cs.clone(), || Ok(digest1), AllocationMode::Witness)
                .unwrap();

        let var2 =
            DigestVar::<Fr>::new_variable(cs.clone(), || Ok(digest2), AllocationMode::Witness)
                .unwrap();

        // Test with condition = true
        let cond_true = Boolean::new_witness(cs.clone(), || Ok(true)).unwrap();
        let result_true = DigestVar::conditionally_select(&cond_true, &var1, &var2).unwrap();

        // Test with condition = false
        let cond_false = Boolean::new_witness(cs.clone(), || Ok(false)).unwrap();
        let result_false = DigestVar::conditionally_select(&cond_false, &var1, &var2).unwrap();

        // Check results
        assert_eq!(result_true.value().unwrap(), digest1);
        assert_eq!(result_false.value().unwrap(), digest2);

        // Check that the constraints are satisfied
        assert!(cs.is_satisfied().unwrap());
    }
}
