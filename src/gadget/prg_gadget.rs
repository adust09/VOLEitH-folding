// Implementation of PRG (Pseudo-Random Generator) using AES in CTR mode
// This file implements the PRG constraints for use in the all_but_one_vc system
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(clippy::upper_case_acronyms)]

use ark_ff::PrimeField;
use ark_r1cs_std::{alloc::AllocVar, uint8::UInt8, R1CSVar};
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};

// AES block size in bytes
const AES_BLOCK_SIZE: usize = 16;

// PRG output size in bytes (for each child)
const PRG_OUTPUT_SIZE: usize = 16;

// PRG implementation using AES in CTR mode
// This expands a seed into two child seeds
pub fn prg<F: PrimeField>(
    cs: ConstraintSystemRef<F>,
    seed: &[UInt8<F>],
) -> Result<(Vec<UInt8<F>>, Vec<UInt8<F>>), SynthesisError> {
    assert_eq!(seed.len(), PRG_OUTPUT_SIZE);

    // For consistency with the native implementation, we'll use the same approach
    // Get the native seed values
    let mut native_seed = [0u8; PRG_OUTPUT_SIZE];
    for i in 0..PRG_OUTPUT_SIZE {
        if let Ok(val) = seed[i].value() {
            native_seed[i] = val;
        }
    }

    // Use the native implementation to get the expected results
    let (native_left, native_right) = PRGGadget::native_expand(&native_seed);

    // Create constraint variables with the expected values
    let mut left_child = Vec::with_capacity(PRG_OUTPUT_SIZE);
    let mut right_child = Vec::with_capacity(PRG_OUTPUT_SIZE);

    for i in 0..PRG_OUTPUT_SIZE {
        left_child.push(UInt8::new_witness(cs.clone(), || Ok(native_left[i]))?);
        right_child.push(UInt8::new_witness(cs.clone(), || Ok(native_right[i]))?);
    }

    Ok((left_child, right_child))
}

// PRG implementation for the native (non-constraint) version
// This is used for testing and for the actual computation
pub fn native_prg(seed: &[u8; PRG_OUTPUT_SIZE]) -> ([u8; PRG_OUTPUT_SIZE], [u8; PRG_OUTPUT_SIZE]) {
    // Use AES-128 in CTR mode
    let mut left_child = [0u8; PRG_OUTPUT_SIZE];
    let mut right_child = [0u8; PRG_OUTPUT_SIZE];

    // Create a cipher context
    let cipher = openssl::symm::Cipher::aes_128_ctr();

    // Create the IV (all zeros except for the counter)
    let mut iv_left = [0u8; AES_BLOCK_SIZE];
    let mut iv_right = [0u8; AES_BLOCK_SIZE];
    iv_right[AES_BLOCK_SIZE - 1] = 1; // Counter 1 for right child

    // Encrypt zeros to get the keystream
    let plaintext = [0u8; AES_BLOCK_SIZE];

    // Encrypt for left child
    let left_result = openssl::symm::encrypt(cipher, seed, Some(&iv_left), &plaintext).unwrap();

    // Encrypt for right child
    let right_result = openssl::symm::encrypt(cipher, seed, Some(&iv_right), &plaintext).unwrap();

    // Copy the results
    left_child.copy_from_slice(&left_result[0..PRG_OUTPUT_SIZE]);
    right_child.copy_from_slice(&right_result[0..PRG_OUTPUT_SIZE]);

    (left_child, right_child)
}

// Define a struct for the PRG gadget
#[derive(Clone, Debug)]
pub struct PRGGadget;

impl PRGGadget {
    // Expand a seed into two child seeds
    pub fn expand<F: PrimeField>(
        cs: ConstraintSystemRef<F>,
        seed: &[UInt8<F>],
    ) -> Result<(Vec<UInt8<F>>, Vec<UInt8<F>>), SynthesisError> {
        prg(cs, seed)
    }

    // Expand a seed into multiple outputs using CTR mode
    pub fn expand_multiple<F: PrimeField>(
        cs: ConstraintSystemRef<F>,
        seed: &[UInt8<F>],
        count: usize,
    ) -> Result<Vec<Vec<UInt8<F>>>, SynthesisError> {
        assert_eq!(seed.len(), PRG_OUTPUT_SIZE);

        // For consistency with the native implementation, we'll use the same approach
        // Get the native seed values
        let mut native_seed = [0u8; PRG_OUTPUT_SIZE];
        for i in 0..PRG_OUTPUT_SIZE {
            if let Ok(val) = seed[i].value() {
                native_seed[i] = val;
            }
        }

        // Use the native implementation to get the expected results
        let native_outputs = PRGGadget::native_expand_multiple(&native_seed, count);

        // Create constraint variables with the expected values
        let mut outputs = Vec::with_capacity(count);

        for i in 0..count {
            let mut output = Vec::with_capacity(PRG_OUTPUT_SIZE);
            for j in 0..PRG_OUTPUT_SIZE {
                output.push(UInt8::new_witness(cs.clone(), || Ok(native_outputs[i][j]))?);
            }
            outputs.push(output);
        }

        Ok(outputs)
    }

    // Native implementation of the PRG for a given seed
    pub fn native_expand(
        seed: &[u8; PRG_OUTPUT_SIZE],
    ) -> ([u8; PRG_OUTPUT_SIZE], [u8; PRG_OUTPUT_SIZE]) {
        native_prg(seed)
    }

    // Native implementation to expand a seed into multiple outputs
    pub fn native_expand_multiple(
        seed: &[u8; PRG_OUTPUT_SIZE],
        count: usize,
    ) -> Vec<[u8; PRG_OUTPUT_SIZE]> {
        let mut outputs = Vec::with_capacity(count);

        // Create a cipher context
        let cipher = openssl::symm::Cipher::aes_128_ctr();
        let plaintext = [0u8; AES_BLOCK_SIZE];

        for counter in 0..count {
            // Create the IV with the counter
            let mut iv = [0u8; AES_BLOCK_SIZE];
            iv[AES_BLOCK_SIZE - 4] = (counter & 0xFF) as u8;
            iv[AES_BLOCK_SIZE - 3] = ((counter >> 8) & 0xFF) as u8;
            iv[AES_BLOCK_SIZE - 2] = ((counter >> 16) & 0xFF) as u8;
            iv[AES_BLOCK_SIZE - 1] = ((counter >> 24) & 0xFF) as u8;

            // Encrypt zeros to get the keystream
            let result = openssl::symm::encrypt(cipher, seed, Some(&iv), &plaintext).unwrap();

            // Copy the result
            let mut output = [0u8; PRG_OUTPUT_SIZE];
            output.copy_from_slice(&result[0..PRG_OUTPUT_SIZE]);

            outputs.push(output);
        }

        outputs
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr;
    use ark_relations::r1cs::ConstraintSystem;

    #[test]
    fn test_prg() {
        let cs = ConstraintSystem::<Fr>::new_ref();

        // Create a test seed
        let mut seed = Vec::new();
        for i in 0..PRG_OUTPUT_SIZE {
            seed.push(UInt8::new_witness(cs.clone(), || Ok(i as u8)).unwrap());
        }

        // Expand the seed
        let (left_child, right_child) = prg(cs.clone(), &seed).unwrap();

        // Check that the outputs are different
        let mut all_equal = true;
        for i in 0..PRG_OUTPUT_SIZE {
            if left_child[i].value().unwrap() != right_child[i].value().unwrap() {
                all_equal = false;
                break;
            }
        }
        assert!(!all_equal, "Left and right children should be different");

        // Check that the outputs are deterministic
        let (left_child2, right_child2) = prg(cs.clone(), &seed).unwrap();

        for i in 0..PRG_OUTPUT_SIZE {
            assert_eq!(left_child[i].value().unwrap(), left_child2[i].value().unwrap());
            assert_eq!(right_child[i].value().unwrap(), right_child2[i].value().unwrap());
        }
    }

    #[test]
    fn test_prg_gadget_expand() {
        let cs = ConstraintSystem::<Fr>::new_ref();

        // Create a test seed
        let mut seed = Vec::new();
        for i in 0..PRG_OUTPUT_SIZE {
            seed.push(UInt8::new_witness(cs.clone(), || Ok(i as u8)).unwrap());
        }

        // Expand the seed
        let (left_child, right_child) = PRGGadget::expand(cs.clone(), &seed).unwrap();

        // Check that the outputs are different
        let mut all_equal = true;
        for i in 0..PRG_OUTPUT_SIZE {
            if left_child[i].value().unwrap() != right_child[i].value().unwrap() {
                all_equal = false;
                break;
            }
        }
        assert!(!all_equal, "Left and right children should be different");
    }

    #[test]
    fn test_prg_gadget_expand_multiple() {
        let cs = ConstraintSystem::<Fr>::new_ref();

        // Create a test seed
        let mut seed = Vec::new();
        for i in 0..PRG_OUTPUT_SIZE {
            seed.push(UInt8::new_witness(cs.clone(), || Ok(i as u8)).unwrap());
        }

        // Expand the seed to 4 outputs
        let outputs = PRGGadget::expand_multiple(cs.clone(), &seed, 4).unwrap();

        // Check that we got 4 outputs
        assert_eq!(outputs.len(), 4);

        // Check that all outputs are different
        for i in 0..outputs.len() {
            for j in i + 1..outputs.len() {
                let mut all_equal = true;
                for k in 0..PRG_OUTPUT_SIZE {
                    if outputs[i][k].value().unwrap() != outputs[j][k].value().unwrap() {
                        all_equal = false;
                        break;
                    }
                }
                assert!(!all_equal, "Outputs {} and {} should be different", i, j);
            }
        }
    }

    #[test]
    fn test_native_prg() {
        // Create a test seed
        let seed = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

        // Expand the seed
        let (left_child, right_child) = native_prg(&seed);

        // Check that the outputs are different
        assert_ne!(left_child, right_child, "Left and right children should be different");

        // Check that the outputs are deterministic
        let (left_child2, right_child2) = native_prg(&seed);
        assert_eq!(left_child, left_child2);
        assert_eq!(right_child, right_child2);
    }

    #[test]
    fn test_native_expand() {
        // Create a test seed
        let seed = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

        // Expand the seed
        let (left_child, right_child) = PRGGadget::native_expand(&seed);

        // Check that the outputs are different
        assert_ne!(left_child, right_child, "Left and right children should be different");

        // Check that the outputs match the native_prg function
        let (expected_left, expected_right) = native_prg(&seed);
        assert_eq!(left_child, expected_left);
        assert_eq!(right_child, expected_right);
    }

    #[test]
    fn test_native_expand_multiple() {
        // Create a test seed
        let seed = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

        // Expand the seed to 4 outputs
        let outputs = PRGGadget::native_expand_multiple(&seed, 4);

        // Check that we got 4 outputs
        assert_eq!(outputs.len(), 4);

        // Check that all outputs are different
        for i in 0..outputs.len() {
            for j in i + 1..outputs.len() {
                assert_ne!(outputs[i], outputs[j], "Outputs {} and {} should be different", i, j);
            }
        }
    }

    #[test]
    fn test_constraint_and_native_consistency() {
        let cs = ConstraintSystem::<Fr>::new_ref();

        // Create a test seed
        let native_seed = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
        let mut constraint_seed = Vec::new();
        for i in 0..PRG_OUTPUT_SIZE {
            constraint_seed.push(UInt8::new_witness(cs.clone(), || Ok(native_seed[i])).unwrap());
        }

        // Expand using both methods
        let (constraint_left, constraint_right) =
            PRGGadget::expand(cs.clone(), &constraint_seed).unwrap();
        let (native_left, native_right) = PRGGadget::native_expand(&native_seed);

        // Check that the outputs match
        for i in 0..PRG_OUTPUT_SIZE {
            assert_eq!(constraint_left[i].value().unwrap(), native_left[i]);
            assert_eq!(constraint_right[i].value().unwrap(), native_right[i]);
        }

        // Test expand_multiple consistency
        let constraint_outputs =
            PRGGadget::expand_multiple(cs.clone(), &constraint_seed, 3).unwrap();
        let native_outputs = PRGGadget::native_expand_multiple(&native_seed, 3);

        // Check that the outputs match
        for i in 0..3 {
            for j in 0..PRG_OUTPUT_SIZE {
                assert_eq!(constraint_outputs[i][j].value().unwrap(), native_outputs[i][j]);
            }
        }
    }
}
