use ark_bn254::Fr as F; // BLS12-381 or BN254 のフィールドを使用
use ark_ff::{Field, PrimeField};
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::R1CSVar;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use rand::{thread_rng, Rng};

// VOLE-in-the-Head の Verification Circuit (Step 1～7)
struct VOLEVerificationCircuit<F: PrimeField> {
    pub q_vals: Vec<F>,   // q'_1, ..., q'_l
    pub delta: F,         // ランダムチャレンジ Δ
    pub f_vals: Vec<F>,   // f̄_{i,h} の値
    pub chi_vals: Vec<F>, // Verifier のチャレンジ値
    pub a: F,             // Prover から送られた a
    pub b: F,             // Prover から送られた b
}

impl<F: PrimeField> ConstraintSynthesizer<F> for VOLEVerificationCircuit<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        // Step 3: q'_i の値を R1CS にマッピング
        let q_vars: Vec<FpVar<F>> = self
            .q_vals
            .iter()
            .map(|&q| FpVar::new_input(cs.clone(), || Ok(q)))
            .collect::<Result<Vec<_>, _>>()?;

        let delta_var = FpVar::new_input(cs.clone(), || Ok(self.delta))?;
        let a_var = FpVar::new_input(cs.clone(), || Ok(self.a))?;
        let b_var = FpVar::new_input(cs.clone(), || Ok(self.b))?;

        // Step 4: c_i(Δ) の計算
        let mut c_delta = FpVar::zero();
        for (h, &f_val) in self.f_vals.iter().enumerate() {
            let f_var = FpVar::new_input(cs.clone(), || Ok(f_val))?;
            let delta_exp = delta_var.clone().pow([(2 - h) as u64]); // Δ^(2-h)
            c_delta += f_var * delta_exp;
        }

        // Step 5: q^* の計算
        let mut q_star = FpVar::zero();
        for (i, &q) in self.q_vals.iter().enumerate() {
            let q_var = FpVar::new_input(cs.clone(), || Ok(q))?;
            let delta_exp = delta_var.clone().pow([(i) as u64]); // Δ^(i)
            q_star += q_var * delta_exp;
        }

        // Step 6: \tilde{c} の計算
        let mut tilde_c = q_star.clone();
        for (i, &chi) in self.chi_vals.iter().enumerate() {
            let chi_var = FpVar::new_input(cs.clone(), || Ok(chi))?;
            tilde_c += chi_var * c_delta.clone();
        }

        // Step 7: \tilde{c} = \tilde{a} * Δ + \tilde{b} のチェック
        let a_delta = a_var * delta_var;
        let computed_c = a_delta + b_var;
        tilde_c.enforce_equal(&computed_c)?;

        Ok(())
    }
}

fn main() {
    use ark_relations::r1cs::{ConstraintSystem, ConstraintSystemRef};

    // 1. サンプルデータを生成
    let mut rng = thread_rng();
    let q_vals: Vec<F> = (0..3).map(|_| F::from(rng.gen_range(1..10) as u64)).collect();
    let delta = F::from(rng.gen_range(1..10) as u64);
    let f_vals: Vec<F> = (0..3).map(|_| F::from(rng.gen_range(1..10) as u64)).collect();
    let chi_vals: Vec<F> = (0..3).map(|_| F::from(rng.gen_range(1..10) as u64)).collect();
    let a = F::from(rng.gen_range(1..10) as u64);
    let b = F::from(rng.gen_range(1..10) as u64);

    // 2. Constraint System を作成
    let cs = ConstraintSystem::<F>::new_ref();
    let circuit = VOLEVerificationCircuit { q_vals, delta, f_vals, chi_vals, a, b };

    // 3. 制約を追加
    circuit.generate_constraints(cs.clone()).unwrap();

    // 4. 検証 (制約が満たされているか)
    assert!(cs.is_satisfied().unwrap());
    println!("VOLE-in-the-Head の検証が成功しました。");
}
#[cfg(test)]
mod tests {
    use super::*;
    use ark_relations::r1cs::{ConstraintSystem, ConstraintSystemRef};
    use rand::{thread_rng, Rng};

    // ✅ **1. 正しい入力で検証が成功するか**
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

    // ❌ **2. 誤った a, b を与えた場合に検証が失敗するか**
    #[test]
    fn test_incorrect_verification() {
        let mut rng = thread_rng();
        let q_vals: Vec<F> = (0..3).map(|_| F::from(rng.gen_range(1..10) as u64)).collect();
        let delta = F::from(rng.gen_range(1..10) as u64);
        let f_vals: Vec<F> = (0..3).map(|_| F::from(rng.gen_range(1..10) as u64)).collect();
        let chi_vals: Vec<F> = (0..3).map(|_| F::from(rng.gen_range(1..10) as u64)).collect();
        let a = F::from(rng.gen_range(1..10) as u64);
        let b = F::from(rng.gen_range(1..10) as u64) + F::from(1u64); // わざと誤った b を設定

        let cs = ConstraintSystem::<F>::new_ref();
        let circuit = VOLEVerificationCircuit { q_vals, delta, f_vals, chi_vals, a, b };

        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(!cs.is_satisfied().unwrap(), "VOLE Verification should fail with incorrect input.");
    }

    // ✅ **3. 異なる Δ で検証が影響を受けるか**
    #[test]
    fn test_different_delta() {
        let mut rng = thread_rng();
        let q_vals: Vec<F> = (0..3).map(|_| F::from(rng.gen_range(1..10) as u64)).collect();
        let delta1 = F::from(rng.gen_range(1..10) as u64);
        let delta2 = F::from(rng.gen_range(1..10) as u64) + F::from(1u64); // 違う Δ を用意
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
        let circuit2 = VOLEVerificationCircuit {
            q_vals,
            delta: delta2, // Δ のみ異なる
            f_vals,
            chi_vals,
            a,
            b,
        };
        circuit2.generate_constraints(cs2.clone()).unwrap();
        let result2 = cs2.is_satisfied().unwrap();

        assert_ne!(
            result1, result2,
            "Different Δ should result in different verification results."
        );
    }
}
