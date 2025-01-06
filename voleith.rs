use crate::arithmetic::{bit_xor_assign, hash_bitvector_and_matrix, hash_matrix};
use crate::field::BitMulAccumulate;
use crate::gf2::{GF2Vector, GF2View};
use crate::gf2psmall::SmallGF;
use crate::veccom::VecCom;
use core::marker::PhantomData;
use core::mem;
use digest::XofReader;
use digest::{Digest, Output as DigestOutput};
use itertools::izip;
use ndarray::{Array1, Array2, ArrayView1, ArrayView2, Axis, s};
use rand::{Rng, SeedableRng, thread_rng};
use rand_chacha::ChaChaRng;

type Vector<T> = Array1<T>;
type VectorView<'a, T> = ArrayView1<'a, T>;
type Matrix<T> = Array2<T>;
type MatrixView<'a, T> = ArrayView2<'a, T>;

pub trait VoleInTheHeadSender {
    type Commitment: Clone;
    type Challenge: Clone;
    type Response: Clone;
    type Decommitment: Clone;
    type Field: Clone;

    const FIELD_SIZE: usize;

    fn new(vole_length: usize, num_repetitions: usize) -> Self;
    fn commit_message(&mut self, message: GF2Vector) -> Self::Commitment;
    fn commit_random(&mut self) -> Self::Commitment;
    fn consistency_check_respond(&mut self, random_points: Self::Challenge) -> Self::Response;
    #[allow(non_snake_case)]
    fn decommit(&mut self, Deltas: Vector<Self::Field>) -> Self::Decommitment;
    fn get_output(&self) -> (&GF2View, MatrixView<'_, Self::Field>);
}

pub trait VoleInTheHeadReceiver {
    type Commitment: Clone;
    type Challenge: Clone;
    type Response: Clone;
    type Decommitment: Clone;
    type Field: Clone;

    const FIELD_SIZE: usize;

    fn new(vole_length: usize, num_repetitions: usize) -> Self;
    fn commit_message(&mut self, message: GF2Vector) -> Self::Commitment;
    fn commit_random(&mut self) -> Self::Commitment;
    fn consistency_check_respond(&mut self, random_points: Self::Challenge) -> Self::Response;
    #[allow(non_snake_case)]
    fn decommit(&mut self, Deltas: Vector<Self::Field>) -> Self::Decommitment;
    fn get_output(&self) -> (&GF2View, MatrixView<'_, Self::Field>);
}

#[derive(Clone, Debug, Copy, PartialEq, Eq)]
enum VoleInTheHeadSenderState {
    New,
    Committed,
    RespondedToConsistencyChallenge,
    Ready,
}

#[allow(non_snake_case)]
pub struct VoleInTheHeadSenderFromVC<F: SmallGF, VC: VecCom, H: Digest = blake3::Hasher> {
    vole_length: usize,
    num_repetitions: usize,
    state: VoleInTheHeadSenderState,
    u: GF2Vector,
    v: Matrix<F>,
    decommitment_keys: Vec<VC::decommitmentKey>,
    _phantom_vc: PhantomData<VC>,
    _phantom_h: PhantomData<H>,
}
impl<F: SmallGF, VC: VecCom, H: Digest> VoleInTheHeadSenderFromVC<F, VC, H> {
    fn commit_impl(
        &mut self,
        message: Option<GF2Vector>,
    ) -> <Self as VoleInTheHeadSender>::Commitment {
        assert_eq!(self.state, VoleInTheHeadSenderState::New);

        let log_q = F::LOG_ORDER;
        let tau = self.num_repetitions;
        let ell_hat = self.vole_length + self.num_repetitions;

        let mut hasher = H::new();
        let mut correction_values =
            Vec::with_capacity(if message.is_some() { tau } else { tau - 1 });

        // iteration i = 0
        {
            let (commitment, decommitment_key, mut xofs) = VC::commit(log_q);
            self.decommitment_keys.push(decommitment_key);
            hasher.update(commitment.as_ref());
            // iteration x = 0
            let u_0 = &mut self.u;
            xofs[0].read(u_0.bits.as_raw_mut_slice());
            let mut v_0 = self.V.row_mut(0);
            debug_assert_eq!(xofs.len(), F::ORDER);
            for (x, xof_x) in xofs.iter_mut().enumerate().skip(1) {
                let mut r_x_0 = GF2Vector::with_capacity(ell_hat);
                r_x_0.resize(ell_hat, false);
                xof_x.read(r_x_0.as_raw_mut_slice());
                bit_xor_assign(u_0, &r_x_0);
                BitMulAccumulate::bitmul_accumulate(
                    v_0.as_slice_mut().unwrap(),
                    F::from(x),
                    r_x_0.as_raw_slice(),
                );
            }
            if let Some(msg) = message {
                let mut msg_correction = msg.clone();
                bit_xor_assign(&mut msg_correction, u_0);
                msg_correction.bits.set_uninitialized(false);
                debug_assert_eq!(msg_correction.bits.len(), self.vole_length);
                correction_values.push(msg_correction);
                u_0.bits[0..self.vole_length].copy_from_bitslice(msg.as_ref());
            }
        }

        // other iterations
        for i in 1..tau {
            let (commitment, decommitment_key, mut xofs) = VC::commit(log_q);
            self.decommitment_keys.push(decommitment_key);
            hasher.update(commitment.as_ref());
            // iteration x = 0
            let mut u_i = {
                let mut r_0_1 = GF2Vector::with_capacity(ell_hat);
                r_0_1.resize(ell_hat, false);
                xofs[0].read(r_0_1.as_raw_mut_slice());
                r_0_1
            };
            let mut v_i = self.V.row_mut(i);
            debug_assert_eq!(xofs.len(), F::ORDER);
            for (x, xof_x) in xofs.iter_mut().enumerate().skip(1) {
                let mut r_x_i = GF2Vector::with_capacity(ell_hat);
                r_x_i.resize(ell_hat, false);
                xof_x.read(r_x_i.as_raw_mut_slice());
                bit_xor_assign(&mut u_i, &r_x_i);
                BitMulAccumulate::bitmul_accumulate(
                    v_i.as_slice_mut().unwrap(),
                    F::from(x),
                    r_x_i.as_raw_slice(),
                );
            }
            bit_xor_assign(&mut u_i, &self.u);
            correction_values.push(u_i);
        }

        let vc_commitment_hash = hasher.finalize();

        // transpose V such that we can now access it row-wise
        {
            // reversed_axes consumes self, but we cannot move out of the &mut ref.
            // Hence, we do the swapping with a dummy value.
            let mut tmp = Matrix::<F>::default((1, 1));
            mem::swap(&mut tmp, &mut self.V);
            tmp = tmp.reversed_axes();
            mem::swap(&mut tmp, &mut self.V);
            self.V = self.V.as_standard_layout().into_owned();
        }

        self.state = VoleInTheHeadSenderState::Committed;
        Commitment { vc_commitment_hash, correction_values }
    }
}
