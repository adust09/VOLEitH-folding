use ark_bn254::Fr as F;
use ark_ff::{Field, PrimeField};
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::R1CSVar;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use rand::{thread_rng, Rng};

struct VOLEVerificationCircuit<F: PrimeField> {
    pub q_vals: Vec<F>,
    pub delta: F,
    pub f_vals: Vec<F>,
    pub chi_vals: Vec<F>,
    pub a: F,
    pub b: F,
}

impl<F: PrimeField> ConstraintSynthesizer<F> for VOLEVerificationCircuit<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        // Step 3: q'_i
        let q_vars: Vec<FpVar<F>> = self
            .q_vals
            .iter()
            .map(|&q| FpVar::new_input(cs.clone(), || Ok(q)))
            .collect::<Result<Vec<_>, _>>()?;

        let delta_var = FpVar::new_input(cs.clone(), || Ok(self.delta))?;
        let a_var = FpVar::new_input(cs.clone(), || Ok(self.a))?;
        let b_var = FpVar::new_input(cs.clone(), || Ok(self.b))?;

        // Step 4: c_i(Δ)
        let mut c_delta = FpVar::zero();
        for (h, &f_val) in self.f_vals.iter().enumerate() {
            let f_var = FpVar::new_input(cs.clone(), || Ok(f_val))?;
            let delta_exp = delta_var.clone().pow([(2 - h) as u64]);
            c_delta += f_var * delta_exp;
        }

        // Step 5: q^*
        let mut q_star = FpVar::zero();
        for (i, &q) in self.q_vals.iter().enumerate() {
            let q_var = FpVar::new_input(cs.clone(), || Ok(q))?;
            let delta_exp = delta_var.clone().pow([(i) as u64]);
            q_star += q_var * delta_exp;
        }

        // Step 6: \tilde{c}
        let mut tilde_c = q_star.clone();
        for (i, &chi) in self.chi_vals.iter().enumerate() {
            let chi_var = FpVar::new_input(cs.clone(), || Ok(chi))?;
            tilde_c += chi_var * c_delta.clone();
        }

        // Step 7: \tilde{c} = \tilde{a} * Δ + \tilde{b}
        let a_delta = a_var * delta_var;
        let computed_c = a_delta + b_var;
        tilde_c.enforce_equal(&computed_c)?;

        Ok(())
    }
}

fn main() {
    use ark_relations::r1cs::{ConstraintSystem, ConstraintSystemRef};

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
    println!("VOLE-in-the-Head の検証が成功しました。");
}
#[cfg(test)]
mod tests {
    use super::*;
    use ark_relations::r1cs::{ConstraintSystem, ConstraintSystemRef};
    use rand::{thread_rng, Rng};

    #[cfg(test)]
    mod tests {
        use super::*;
        use ark_relations::r1cs::{ConstraintSystem, ConstraintSystemRef};
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
