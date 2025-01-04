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

type Vector<T,> = Array1<T,>;
type VectorView<'a, T,> = ArrayView1<'a, T,>;
type Matrix<T,> = Array2<T,>;
type MatrixView<'a, T,> = ArrayView2<'a, T,>;

pub trait VoleInTheHeadSender {
    type Commitment: Clone;
    type Challenge: Clone;
    type Response: Clone;
    type Decommitment: Clone;
    type Field: Clone;

    const FIELD_SIZE: usize;

    fn new(vole_length: usize, num_repetitions: usize,) -> Self;
    fn commit_message(&mut self, message: GF2Vector,) -> Self::Commitment;
    fn commit_random(&mut self,) -> Self::Commitment;
    fn consistency_check_respond(&mut self, random_points: Self::Challenge,) -> Self::Response;
    #[allow(non_snake_case)]
    fn decommit(&mut self, Deltas: Vector<Self::Field,>,) -> Self::Decommitment;
    fn get_output(&self,) -> (&GF2View, MatrixView<'_, Self::Field,>,);
}


#[derive(Clone, Debug,Copy,PartialEq,Eq,)]
