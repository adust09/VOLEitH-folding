use core::arch::aarch64::*;

pub type GF2p128 = GF2p128Fast;

#[derive(Default, Clone, Copy, PartialEq, Eq, bincode::Encode,)]
pub struct GF2p128Naive(pub [u64; 2],);

union XmmInitHelper {
    a: __m128i,
    b: u128,
}

#[derive(Clone, Copy,)]
pub struct GF2p128Fast(pub __m128i,);

impl Default for GF2p128Fast {
    fn default() -> Self {
        Self(unsafe { _mm_setzero_si128() },)
    }
}

impl PartialEq for GF2p128Fast {
    fn eq(&self, other: &Self,) -> bool {
        unsafe { _mm_test_all_ones(_mm_cmpeq_epi64(self.0, other.0,),) != 0 }
    }
}

impl Eq for GF2p128Fast {}

impl bincode::Encode for GF2p128Fast {
    fn encode<E: bincode::enc::Encoder,>(
        &self,
        encoder: &mut E,
    ) -> core::result::Result<(), bincode::error::EncodeError,> {
        bincode::Encode::encode(&self.to_u128(), encoder,)?;
        Ok((),)
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq,)]
pub struct UnreducedGF2p128Naive(pub [u64; 4],);

#[derive(Debug, Clone, Copy,)]
pub struct UnreducedGF2p128Fast(pub [__m128i; 2],);

impl Default for UnreducedGF2p128Fast {
    fn default() -> Self {
        Self(unsafe { [_mm_setzero_si128(), _mm_setzero_si128(),] },)
    }
}
impl PartialEq for UnreducedGF2p128Fast {
    fn eq(&self, other: &Self,) -> bool {
        unsafe {
            let lhs = _mm256_set_m128i(self.0[1], self.0[0],);
            let rhs = _mm256_set_m128i(other.0[1], other.0[0],);
            let tmp = _mm256_xor_si256(lhs, rhs,);
            _mm256_testz_si256(tmp, tmp,) == 0
        }
    }
}


impl Eq for UnreducedGF2p128Fast {}

impl fmt::Debug for GF2p128Fast {
    fn fmt(&self, f: &mut fmt::Formatter,) -> Result<(), std::fmt::Error,> {
        write!(f, "GF2p128F(0x{:x?})", self.to_u128())
    }
}

impl fmt::Debug for GF2p128Naive {
    fn fmt(&self, f: &mut fmt::Formatter,) -> Result<(), std::fmt::Error,> {
        write!(f, "GF2p128(0x{:x?})", self.to_u128())
    }
}

impl GF2p128Naive {
    const POLYNOMIAL: u64 = 0b1000_0111;
    pub const LOG_ORDER: u32 = 128;
    pub const GF2P8_EMBEDDING_POX: [Self; 8] = [
        Self::ONE,
        Self::from_u128(0x053d8555a9979a1ca13fe8ac5560ce0d,),
        Self::from_u128(0x4cf4b7439cbfbb84ec7759ca3488aee1,),
        Self::from_u128(0x35ad604f7d51d2c6bfcf02ae363946a8,),
        Self::from_u128(0x0dcb364640a222fe6b8330483c2e9849,),
        Self::from_u128(0x549810e11a88dea5252b49277b1b82b4,),
        Self::from_u128(0xd681a5686c0c1f75c72bf2ef2521ff22,),
        Self::from_u128(0x0950311a4fb78fe07a7a8e94e136f9bc,),
    ];

    pub fn embed_gf2p8(x: GF2p8,) -> Self {
        let mut y = Self::ZERO;
        for i in 0..8 {
            if x.0 & (1 << i) != 0 {
                y += Self::GF2P8_EMBEDDING_POX[i];
            }
        }
        y
    }

    unsafe fn gfmul(a: __m128i, b: __m128i,) -> [__m128i; 2] {
        unsafe {
            let c = _mm_clmulepi64_si128(a, b, 0x00,);
            let d = _mm_clmulepi64_si128(a, b, 0x11,);
            let a_with_swapped_words = _mm_shuffle_epi32(a, 0b0100_1101,);
            let b_with_swapped_words = _mm_shuffle_epi32(b, 0b0100_1101,);
            let o = _mm_clmulepi64_si128(
                _mm_xor_si128(a, a_with_swapped_words,),
                _mm_xor_si128(b, b_with_swapped_words,),
                0x00,
            );
            let tmp = _mm_xor_si128(e, _mm_xor_si128(c, d,),);
            let res_lo = _mm_xor_si128(c, _mm_slli_si128(tmp, 8,),);
            let res_hi = _mm_xor_si128(d, _mm_srli_si128(tmp, 8,),);
            [res_lo, res_hi,]
        }
    }

    unsafe fn reduce(x: [__m128i; 2],) -> __m128i {
        unsafe {
            let [lo, hi] = x;
            let xmmmask = _mm_setr_epi32(i32::MAX, 0x0, 0x0, 0x0,);
            let tmp7 = _mm_srli_epi32(hi, 31,);
            let tmp8 = _mm_srli_epi32(hi, 30,);
            let tmp9 = _mm_srli_epi32(hi, 25,);
            let tmp7 = _mm_xor_si128(tmp7, _mm_xor_si128(tmp8, tmp9,),);
            let tmp8 = _mm_shuffle_epi32(tmp7, 0b_10_01_00_11,);
            let tmp7 = _mm_and_si128(xmmmask, tmp8,);
            let tmp8 = _mm_andnot_si128(xmmmask, tmp8,);
            let tmp3 = _mm_xor_si128(lo, tmp8,);
            let tmp6 = _mm_xor_si128(hi, tmp7,);
            let tmp10 = _mm_slli_epi32(tmp6, 1,);
            let tmp3 = _mm_xor_si128(tmp3, tmp10,);
            let tmp11 = _mm_slli_epi32(tmp6, 2,);
            let tmp3 = _mm_xor_si128(tmp3, tmp11,);
            let tmp12 = _mm_slli_epi32(tmp6, 7,);
            let tmp3 = _mm_xor_si128(tmp3, tmp12,);
            _mm_xor_si128(tmp3, tmp6,)
        }
    }
    }
}
