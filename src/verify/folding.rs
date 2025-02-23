use ark_ff::PrimeField;
use ark_r1cs_std::{
    alloc::AllocVar,
    eq::EqGadget,
    fields::{fp::FpVar, FieldVar},
};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

pub struct VOLEVerificationCircuit<F: PrimeField> {
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
            let delta_exp = delta_var.clone().pow_by_constant([(2 - h) as u64])?;
            c_delta += f_var * delta_exp;
        }

        // Step 5: q^*
        let mut q_star = FpVar::zero();
        for (i, &q) in self.q_vals.iter().enumerate() {
            let q_var = FpVar::new_input(cs.clone(), || Ok(q))?;
            let delta_exp = delta_var.clone().pow_by_constant([(i) as u64])?;
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
