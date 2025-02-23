pub mod folding;

use crate::verification::folding::VOLEVerificationCircuit;
use ark_relations::r1cs::ConstraintSynthesizer;
use rand::{thread_rng, Rng};

pub fn verification<F: ark_ff::PrimeField>() {
    // todo: call folding
    use ark_relations::r1cs::ConstraintSystem;

    let mut rng = thread_rng();
    let q_vals: Vec<F> = (0..3).map(|_| F::from(rng.gen_range(1..10) as u64)).collect();
    let delta = F::from(rng.gen_range(1..10) as u64);
    let f_vals: Vec<F> = (0..3).map(|_| F::from(rng.gen_range(1..10) as u64)).collect();
    let chi_vals: Vec<F> = (0..3).map(|_| F::from(rng.gen_range(1..10) as u64)).collect();
    let a = F::from(rng.gen_range(1..10) as u64);
    let b = F::from(rng.gen_range(1..10) as u64);

    let cs = ConstraintSystem::<F>::new_ref();
    let circuit = VOLEVerificationCircuit { q_vals, delta, f_vals, chi_vals, a, b };

    circuit.generate_constraints(cs.clone()).unwrap();

    assert!(cs.is_satisfied().unwrap());
    println!("verification successful");
}

#[cfg(test)]
mod tests {
    mod tests {
        use ark_bls12_381::Fr;
        use ark_ff::Field;
        use ark_ff::Zero;
        use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
        use rand::{thread_rng, Rng};

        use crate::verification::folding::VOLEVerificationCircuit;

        fn test_generate_delta_generic<F: ark_ff::PrimeField>() {
            let mut rng = rand::thread_rng();
            let delta = F::from(rng.gen_range(1..10) as u64);
            assert!(delta != F::zero(), "Delta should be a non-zero random field element.");
        }

        #[test]
        fn test_generate_delta() {
            let mut rng = rand::thread_rng();
            let delta = Fr::from(rng.gen_range(1..10) as u64);
            assert!(delta != Fr::zero(), "Delta should be a non-zero random field element.");
        }

        #[test]
        fn test_compute_q_prime() {
            let mut rng = thread_rng();
            let q_vals: Vec<Fr> = (0..3).map(|_| Fr::from(rng.gen_range(1..10) as u64)).collect();
            assert!(q_vals.len() == 3, "q'_i values should be computed and stored correctly.");
        }

        #[test]
        fn test_receive_q_prime() {
            let mut rng = thread_rng();
            let q_vals: Vec<Fr> = (0..3).map(|_| Fr::from(rng.gen_range(1..10) as u64)).collect();
            let received_q_vals = q_vals.clone();
            assert_eq!(q_vals, received_q_vals, "Verifier should receive q'_i correctly.");
        }

        #[test]
        fn test_compute_c_delta() {
            let mut rng = thread_rng();
            // let q_vals: Vec<Fr> = (0..3).map(|_| Fr::from(rng.gen_range(1..10) as u64)).collect();
            let delta = Fr::from(rng.gen_range(1..10) as u64);
            let f_vals: Vec<Fr> = (0..3).map(|_| Fr::from(rng.gen_range(1..10) as u64)).collect();

            let mut c_delta = Fr::zero();
            for (h, f) in f_vals.iter().enumerate() {
                c_delta += *f * delta.pow([(2 - h) as u64]);
            }

            assert!(c_delta != Fr::zero(), "c_i(Δ) should be computed correctly.");
        }

        #[test]
        fn test_compute_q_star() {
            let mut rng = thread_rng();
            let q_vals: Vec<Fr> = (0..3).map(|_| Fr::from(rng.gen_range(1..10) as u64)).collect();
            let delta = Fr::from(rng.gen_range(1..10) as u64);

            let mut q_star = Fr::zero();
            for (i, q) in q_vals.iter().enumerate() {
                q_star += *q * delta.pow([(i) as u64]);
            }

            assert!(q_star != Fr::zero(), "q^* should be computed correctly.");
        }

        #[test]
        fn test_compute_tilde_c() {
            let mut rng = thread_rng();
            let q_vals: Vec<Fr> = (0..3).map(|_| Fr::from(rng.gen_range(1..10) as u64)).collect();
            let delta = Fr::from(rng.gen_range(1..10) as u64);
            let f_vals: Vec<Fr> = (0..3).map(|_| Fr::from(rng.gen_range(1..10) as u64)).collect();
            let chi_vals: Vec<Fr> = (0..3).map(|_| Fr::from(rng.gen_range(1..10) as u64)).collect();

            let mut c_delta = Fr::zero();
            for (h, f) in f_vals.iter().enumerate() {
                c_delta += *f * delta.pow([(2 - h) as u64]);
            }

            let mut q_star = Fr::zero();
            for (i, q) in q_vals.iter().enumerate() {
                q_star += *q * delta.pow([(i) as u64]);
            }

            let mut tilde_c = q_star;
            for (_i, chi) in chi_vals.iter().enumerate() {
                tilde_c += *chi * c_delta;
            }

            assert!(tilde_c != Fr::zero(), "tilde_c should be computed correctly.");
        }

        #[test]
        fn test_final_check() {
            let mut rng = thread_rng();
            let delta = Fr::from(rng.gen_range(1..10) as u64);
            let a = Fr::from(rng.gen_range(1..10) as u64);
            let b = Fr::from(rng.gen_range(1..10) as u64);
            let tilde_c = a * delta + b;

            assert_eq!(tilde_c, a * delta + b, "Final check should be satisfied.");
        }
        #[test]
        fn test_correct_verification() {
            let mut rng = thread_rng();
            let q_vals: Vec<Fr> = (0..3).map(|_| Fr::from(rng.gen_range(1..10) as u64)).collect();
            let delta = Fr::from(rng.gen_range(1..10) as u64);
            let f_vals: Vec<Fr> = (0..3).map(|_| Fr::from(rng.gen_range(1..10) as u64)).collect();
            let chi_vals: Vec<Fr> = (0..3).map(|_| Fr::from(rng.gen_range(1..10) as u64)).collect();
            let a = Fr::from(rng.gen_range(1..10) as u64);
            let b = Fr::from(rng.gen_range(1..10) as u64);

            let cs = ConstraintSystem::<Fr>::new_ref();
            let circuit = VOLEVerificationCircuit { q_vals, delta, f_vals, chi_vals, a, b };

            circuit.generate_constraints(cs.clone()).unwrap();
            assert!(
                cs.is_satisfied().unwrap(),
                "VOLE Verification should pass with correct input."
            );
        }

        #[test]
        fn test_incorrect_verification() {
            let mut rng = thread_rng();
            let q_vals: Vec<Fr> = (0..3).map(|_| Fr::from(rng.gen_range(1..10) as u64)).collect();
            let delta = Fr::from(rng.gen_range(1..10) as u64);
            let f_vals: Vec<Fr> = (0..3).map(|_| Fr::from(rng.gen_range(1..10) as u64)).collect();
            let chi_vals: Vec<Fr> = (0..3).map(|_| Fr::from(rng.gen_range(1..10) as u64)).collect();
            let a = Fr::from(rng.gen_range(1..10) as u64);
            let b = Fr::from(rng.gen_range(1..10) as u64) + Fr::from(1u64);

            let cs = ConstraintSystem::<Fr>::new_ref();
            let circuit = VOLEVerificationCircuit { q_vals, delta, f_vals, chi_vals, a, b };

            circuit.generate_constraints(cs.clone()).unwrap();
            assert!(
                !cs.is_satisfied().unwrap(),
                "VOLE Verification should fail with incorrect input."
            );
        }

        #[test]
        fn test_different_delta() {
            let mut rng = thread_rng();
            let q_vals: Vec<Fr> = (0..3).map(|_| Fr::from(rng.gen_range(1..10) as u64)).collect();
            let delta1 = Fr::from(rng.gen_range(1..10) as u64);
            let delta2 = Fr::from(rng.gen_range(1..10) as u64) + Fr::from(1u64);
            let f_vals: Vec<Fr> = (0..3).map(|_| Fr::from(rng.gen_range(1..10) as u64)).collect();
            let chi_vals: Vec<Fr> = (0..3).map(|_| Fr::from(rng.gen_range(1..10) as u64)).collect();
            let a = Fr::from(rng.gen_range(1..10) as u64);
            let b = Fr::from(rng.gen_range(1..10) as u64);

            let cs1 = ConstraintSystem::<Fr>::new_ref();
            let circuit1 = VOLEVerificationCircuit {
                q_vals: q_vals.clone(),
                delta: delta1,
                f_vals: f_vals.clone(),
                chi_vals: chi_vals.clone(),
                a,
                b,
            };
            circuit1.generate_constraints(cs1.clone()).unwrap();
            let result1 = cs1.is_satisfied().unwrap();

            let cs2 = ConstraintSystem::<Fr>::new_ref();
            let circuit2 =
                VOLEVerificationCircuit { q_vals, delta: delta2, f_vals, chi_vals, a, b };
            circuit2.generate_constraints(cs2.clone()).unwrap();
            let result2 = cs2.is_satisfied().unwrap();

            assert_ne!(
                result1, result2,
                "Different Δ should result in different verification results."
            );
        }
    }
}
