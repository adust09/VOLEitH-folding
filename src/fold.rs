#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(clippy::upper_case_acronyms)]

use ark_bn254::{Bn254, Fr, G1Projective as Projective};
use ark_ff::PrimeField;
use ark_grumpkin::Projective as Projective2;
use ark_r1cs_std::{
    alloc::AllocVar,
    eq::EqGadget,
    fields::{fp::FpVar, FieldVar},
};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use folding_schemes::FoldingScheme;
use folding_schemes::{
    commitment::{kzg::KZG, pedersen::Pedersen},
    folding::nova::{Nova, PreprocessorParam},
    frontend::FCircuit,
    transcript::poseidon::poseidon_canonical_config,
    Error,
};
use std::{marker::PhantomData, time::Instant};

#[derive(Clone, Copy, Debug)]
pub struct VerificationFCircuit<F: PrimeField> {
    _f: PhantomData<F>,
}

impl<F: PrimeField> FCircuit<F> for VerificationFCircuit<F> {
    type Params = ();
    type ExternalInputs = ();
    type ExternalInputsVar = ();

    fn new(_params: Self::Params) -> Result<Self, Error> {
        Ok(Self { _f: PhantomData })
    }
    fn state_len(&self) -> usize {
        1
    }
    fn generate_step_constraints(
        // this method uses self, so that each FCircuit implementation (and different frontends)
        // can hold a state if needed to store data to generate the constraints.
        &self,
        _cs: ConstraintSystemRef<F>,
        _i: usize,
        _z_i: Vec<FpVar<F>>,
        _external_inputs: Self::ExternalInputsVar, // inputs that are not part of the state
    ) -> Result<Vec<FpVar<F>>, SynthesisError> {
        let circuit = VerificationCircuit {
            q_vals: vec![],
            delta: F::zero(),
            f_vals: vec![],
            chi_vals: vec![],
            a: F::zero(),
            b: F::zero(),
        };
        let out = circuit.evaluate();
        Ok(vec![out])
    }
}
pub struct VerificationCircuit<F: PrimeField> {
    pub q_vals: Vec<F>,
    pub delta: F,
    pub f_vals: Vec<F>,
    pub chi_vals: Vec<F>,
    pub a: F,
    pub b: F,
}

impl<F: PrimeField> VerificationCircuit<F> {
    pub fn evaluate(&self) -> FpVar<F> {
        use ark_relations::r1cs::ConstraintSystem;

        let cs = ConstraintSystem::<F>::new_ref();
        let circuit = VerificationCircuit {
            delta: self.delta, //step.1
            q_vals: self.q_vals.clone(),
            f_vals: self.f_vals.clone(),
            chi_vals: self.chi_vals.clone(),
            a: self.a,
            b: self.b,
        };

        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(cs.is_satisfied().unwrap());
        println!("verification successful");

        let delta_var = FpVar::new_input(cs.clone(), || Ok(self.delta)).unwrap();
        let a_var = FpVar::new_input(cs.clone(), || Ok(self.a)).unwrap();
        let b_var = FpVar::new_input(cs.clone(), || Ok(self.b)).unwrap();
        a_var * delta_var + b_var
    }
}

impl<F: PrimeField> ConstraintSynthesizer<F> for VerificationCircuit<F> {
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
        let t = self.f_vals.len();
        let mut c_vals = Vec::with_capacity(t);
        for i in 0..t {
            let mut c_i = FpVar::zero();
            for h in 0..3 {
                let f_val = self.f_vals[i * 3 + h];
                let f_var = FpVar::new_input(cs.clone(), || Ok(f_val))?;
                let exp = (2 - h) as u64;
                let delta_exp = delta_var.clone().pow_by_constant(&[exp])?;
                c_i += f_var * delta_exp;
            }
            c_vals.push(c_i);
        }

        // Step 5: q^*
        let mut q_star = FpVar::zero();
        for (j, q_var) in q_vars.iter().enumerate() {
            let exp = j as u64;
            let delta_exp = delta_var.clone().pow_by_constant(&[exp])?;
            q_star += q_var.clone() * delta_exp;
        }

        // Step 6: \tilde{c}
        let mut tilde_c = q_star.clone();
        for (i, &chi) in self.chi_vals.iter().enumerate() {
            let chi_var = FpVar::new_input(cs.clone(), || Ok(chi))?;
            tilde_c += chi_var * c_vals[i].clone();
        }

        // Step 7: \tilde{c} = \tilde{a} * Δ + \tilde{b}
        let a_delta = a_var * delta_var;
        let computed_c = a_delta + b_var;
        tilde_c.enforce_equal(&computed_c)?;

        Ok(())
    }
}

pub fn main() -> Result<(), Error> {
    let num_steps = 10;
    let initial_state = vec![Fr::from(1_u32)];

    let F_circuit = VerificationFCircuit::<Fr>::new(())?;

    /// The idea here is that eventually we could replace the next line chunk that defines the
    /// `type N = Nova<...>` by using another folding scheme that fulfills the `FoldingScheme`
    /// trait, and the rest of our code would be working without needing to be updated.
    type N = Nova<
        Projective,
        Projective2,
        VerificationFCircuit<Fr>,
        KZG<'static, Bn254>,
        Pedersen<Projective2>,
        false,
    >;

    let poseidon_config = poseidon_canonical_config::<Fr>();
    let mut rng = rand::rngs::OsRng;

    println!("Prepare Nova ProverParams & VerifierParams");
    let nova_preprocess_params = PreprocessorParam::new(poseidon_config, F_circuit);
    let nova_params = N::preprocess(&mut rng, &nova_preprocess_params)?;

    println!("Initialize FoldingScheme");
    let mut folding_scheme = N::init(&nova_params, F_circuit, initial_state.clone())?;
    // compute a step of the IVC
    for i in 0..num_steps {
        let start = Instant::now();
        folding_scheme.prove_step(rng, (), None)?;
        println!("Nova::prove_step {}: {:?}", i, start.elapsed());
    }

    println!("Run the Nova's IVC verifier");
    let ivc_proof = folding_scheme.ivc_proof();
    N::verify(
        nova_params.1, // Nova's verifier params
        ivc_proof,
    )?;
    Ok(())
}
