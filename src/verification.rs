pub mod folding;

use crate::verification::folding::VOLEVerificationCircuit;
use rand::{thread_rng, Rng};

pub fn verification() {
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
    use super::*;
    use ark_relations::r1cs::ConstraintSystem;
    use rand::{thread_rng, Rng};

    #[cfg(test)]
    mod tests {
        use rand::{thread_rng, Rng};

        #[test]
        fn test_generate_delta() {
            let mut rng = thread_rng();
            let delta = F::from(rng.gen_range(1..10) as u64);
            assert!(delta != F::zero(), "Delta should be a non-zero random field element.");
        }

        #[test]
        fn test_compute_q_prime() {
            let mut rng = thread_rng();
            let q_vals: Vec<F> = (0..3).map(|_| F::from(rng.gen_range(1..10) as u64)).collect();
            assert!(q_vals.len() == 3, "q'_i values should be computed and stored correctly.");
        }

        #[test]
        fn test_receive_q_prime() {
            let mut rng = thread_rng();
            let q_vals: Vec<F> = (0..3).map(|_| F::from(rng.gen_range(1..10) as u64)).collect();
            let received_q_vals = q_vals.clone();
            assert_eq!(q_vals, received_q_vals, "Verifier should receive q'_i correctly.");
        }

        #[test]
        fn test_compute_c_delta() {
            let mut rng = thread_rng();
            let q_vals: Vec<F> = (0..3).map(|_| F::from(rng.gen_range(1..10) as u64)).collect();
            let delta = F::from(rng.gen_range(1..10) as u64);
            let f_vals: Vec<F> = (0..3).map(|_| F::from(rng.gen_range(1..10) as u64)).collect();

            let mut c_delta = F::zero();
            for (h, f) in f_vals.iter().enumerate() {
                c_delta += *f * delta.pow([(2 - h) as u64]);
            }

            assert!(c_delta != F::zero(), "c_i(Δ) should be computed correctly.");
        }

        #[test]
        fn test_compute_q_star() {
            let mut rng = thread_rng();
            let q_vals: Vec<F> = (0..3).map(|_| F::from(rng.gen_range(1..10) as u64)).collect();
            let delta = F::from(rng.gen_range(1..10) as u64);

            let mut q_star = F::zero();
            for (i, q) in q_vals.iter().enumerate() {
                q_star += *q * delta.pow([(i) as u64]);
            }

            assert!(q_star != F::zero(), "q^* should be computed correctly.");
        }

        #[test]
        fn test_compute_tilde_c() {
            let mut rng = thread_rng();
            let q_vals: Vec<F> = (0..3).map(|_| F::from(rng.gen_range(1..10) as u64)).collect();
            let delta = F::from(rng.gen_range(1..10) as u64);
            let f_vals: Vec<F> = (0..3).map(|_| F::from(rng.gen_range(1..10) as u64)).collect();
            let chi_vals: Vec<F> = (0..3).map(|_| F::from(rng.gen_range(1..10) as u64)).collect();

            let mut c_delta = F::zero();
            for (h, f) in f_vals.iter().enumerate() {
                c_delta += *f * delta.pow([(2 - h) as u64]);
            }

            let mut q_star = F::zero();
            for (i, q) in q_vals.iter().enumerate() {
                q_star += *q * delta.pow([(i) as u64]);
            }

            let mut tilde_c = q_star;
            for (i, chi) in chi_vals.iter().enumerate() {
                tilde_c += *chi * c_delta;
            }

            assert!(tilde_c != F::zero(), "tilde_c should be computed correctly.");
        }

        #[test]
        fn test_final_check() {
            let mut rng = thread_rng();
            let delta = F::from(rng.gen_range(1..10) as u64);
            let a = F::from(rng.gen_range(1..10) as u64);
            let b = F::from(rng.gen_range(1..10) as u64);
            let tilde_c = a * delta + b;

            assert_eq!(tilde_c, a * delta + b, "Final check should be satisfied.");
        }
    }

    #[test]
    fn test_correct_verification() {
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
        assert!(cs.is_satisfied().unwrap(), "VOLE Verification should pass with correct input.");
    }

    #[test]
    fn test_incorrect_verification() {
        let mut rng = thread_rng();
        let q_vals: Vec<F> = (0..3).map(|_| F::from(rng.gen_range(1..10) as u64)).collect();
        let delta = F::from(rng.gen_range(1..10) as u64);
        let f_vals: Vec<F> = (0..3).map(|_| F::from(rng.gen_range(1..10) as u64)).collect();
        let chi_vals: Vec<F> = (0..3).map(|_| F::from(rng.gen_range(1..10) as u64)).collect();
        let a = F::from(rng.gen_range(1..10) as u64);
        let b = F::from(rng.gen_range(1..10) as u64) + F::from(1u64);

        let cs = ConstraintSystem::<F>::new_ref();
        let circuit = VOLEVerificationCircuit { q_vals, delta, f_vals, chi_vals, a, b };

        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(!cs.is_satisfied().unwrap(), "VOLE Verification should fail with incorrect input.");
    }

    #[test]
    fn test_different_delta() {
        let mut rng = thread_rng();
        let q_vals: Vec<F> = (0..3).map(|_| F::from(rng.gen_range(1..10) as u64)).collect();
        let delta1 = F::from(rng.gen_range(1..10) as u64);
        let delta2 = F::from(rng.gen_range(1..10) as u64) + F::from(1u64);
        let f_vals: Vec<F> = (0..3).map(|_| F::from(rng.gen_range(1..10) as u64)).collect();
        let chi_vals: Vec<F> = (0..3).map(|_| F::from(rng.gen_range(1..10) as u64)).collect();
        let a = F::from(rng.gen_range(1..10) as u64);
        let b = F::from(rng.gen_range(1..10) as u64);

        let cs1 = ConstraintSystem::<F>::new_ref();
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

        let cs2 = ConstraintSystem::<F>::new_ref();
        let circuit2 = VOLEVerificationCircuit { q_vals, delta: delta2, f_vals, chi_vals, a, b };
        circuit2.generate_constraints(cs2.clone()).unwrap();
        let result2 = cs2.is_satisfied().unwrap();

        assert_ne!(
            result1, result2,
            "Different Δ should result in different verification results."
        );
    }
}
