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
use folding_schemes::{
    commitment::{kzg::KZG, pedersen::Pedersen},
    folding::nova::{Nova, PreprocessorParam},
    frontend::FCircuit,
    transcript::poseidon::poseidon_canonical_config,
    Error, FoldingScheme,
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
        todo!()
    }
}

#[derive(Debug)]
pub struct VerificationCircuit<F: PrimeField> {
    pub delta: F,           // generate at step.1
    pub q: Vec<F>,          // generate at step.2 (q'1,...,q'l)
    pub f_tilde: Vec<F>,    // [f̄_{i,0}, f̄_{i,1}, f̄_{i,2}] for each f~_i
    pub challenges: Vec<F>, // challenge values for each f~_i
    pub a_tilde: F,         // send by prover
    pub b_tilde: F,         // send by prover
}

impl<F: PrimeField> ConstraintSynthesizer<F> for VerificationCircuit<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        // Step 1
        let delta_var = FpVar::new_input(cs.clone(), || Ok(self.delta))?;
        // Step 2: q'_i
        // easy version without using compute_q_prime and G_c
        // this is also used in schmivitz
        let q_prime: Vec<FpVar<F>> = self
            .q
            .iter()
            .map(|&q| FpVar::new_input(cs.clone(), || Ok(q)))
            .collect::<Result<Vec<_>, _>>()?;
        // step 3: lifting \Delta and q'_i
        // Step 4: c_i(Δ)
        let t = self.f_tilde.len();
        let mut c = Vec::with_capacity(t);
        for i in 0..t {
            let mut c_i = FpVar::zero();
            for h in 0..3 {
                let f = self.f_tilde[i * 3 + h]; //
                let f_var = FpVar::new_input(cs.clone(), || Ok(f))?;
                let exp = (2 - h) as u64;
                let delta_exp = delta_var.clone().pow_by_constant(&[exp])?;
                c_i += f_var * delta_exp;
            }
            c.push(c_i);
        }

        // Step 5: q^*
        let mut q_star = FpVar::zero();
        for (j, q_var) in q_prime.iter().enumerate() {
            let exp = j as u64;
            let delta_exp = delta_var.clone().pow_by_constant(&[exp])?;
            q_star += q_var.clone() * delta_exp;
        }

        // Step 6: \tilde{c}
        let mut tilde_c = q_star.clone();
        for (i, &ch) in self.challenges.iter().enumerate() {
            let chi_var = FpVar::new_input(cs.clone(), || Ok(ch))?;
            tilde_c += chi_var * c[i].clone();
        }

        // Step 7: \tilde{c} = \tilde{a} * Δ + \tilde{b}
        let a_var = FpVar::new_input(cs.clone(), || Ok(self.a_tilde))?;
        let b_var = FpVar::new_input(cs.clone(), || Ok(self.b_tilde))?;
        let a_delta = a_var * delta_var;
        let computed_c = a_delta + b_var;
        tilde_c.enforce_equal(&computed_c)?;

        Ok(())
    }
}

fn mat_mul<F: PrimeField>(a: &Vec<Vec<F>>, b: &Vec<Vec<F>>) -> Vec<Vec<F>> {
    let a_rows = a.len();
    let a_cols = if a_rows > 0 { a[0].len() } else { 0 };
    let b_cols = if !b.is_empty() { b.len() } else { 0 };

    let mut res = vec![vec![F::zero(); b_cols]; a_rows];
    for i in 0..a_rows {
        for j in 0..b_cols {
            for k in 0..a_cols {
                res[i][j] += a[i][k] * b[k][j];
            }
        }
    }
    res
}

fn diag<F: PrimeField>(v: &Vec<F>) -> Vec<Vec<F>> {
    let n = v.len();
    let mut res = vec![vec![F::zero(); n]; n];
    for i in 0..n {
        res[i][i] = v[i];
    }
    res
}

// pub fn compute_q_prime<F: PrimeField>(Q: &[F], d: &[F], delta: &F) -> Vec<F> {
//     let l = Q.len();

//     let G_c = todo!(); // G_c を生成

//     // 1. d^T: 1×l
//     let d_row = vec![d.to_vec()]; // 1×l

//     // 2. v = d^T × G_c (ここで G_c は l×l)
//     let v = mat_mul(&d_row, G_c); // 結果は 1×l
//                                   // 3. D = diag(Δ) (l×l)
//     let delta_vec = vec![*delta; l]; // Δをl回繰り返したベクトルを作成
//     let D = diag(&delta_vec); // 対角行列を生成

//     // 4. folded = v × D (1×l)
//     let folded_matrix = mat_mul(&v, &D); // folded_matrix: 1×l
//     let folded = &folded_matrix[0]; // 1行目のベクトルを取得

//     // 5. Q' = Q + folded (要素ごと)
//     let mut q_prime = Vec::with_capacity(l);
//     for i in 0..l {
//         q_prime.push(Q[i] + folded[i]);
//     }
//     q_prime
// }

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
