//! Helper trait for converting T to bytes

use std::vec::Vec;
use std::borrow::Cow;

use smallvec::SmallVec;

/// Helper trait for converting T to bytes
pub trait IntoBytes<'a> {
    #[must_use]
    fn into_bytes(self) -> Cow<'a, [u8]>;

    #[inline(always)]
    fn copy_into(self, dst: &mut [u8])
    where
        Self: Sized
    {
        dst.copy_from_slice(&self.into_bytes())
    }
}

impl<'a> IntoBytes<'a> for crate::bytecode::Opcode {
    #[inline(always)]
    fn into_bytes(self) -> Cow<'a, [u8]> {
        Cow::Owned(Vec::from((self as u8).to_le_bytes()))
    }
}

impl<'a> IntoBytes<'a> for &'a [u8] {
    #[inline(always)]
    fn into_bytes(self) -> Cow<'a, [u8]> {
        Cow::Borrowed(self)
    }
}

impl<'a, const N: usize> IntoBytes<'a> for &'a [u8; N] {
    #[inline(always)]
    fn into_bytes(self) -> Cow<'a, [u8]> {
        Cow::Borrowed(&self[..])
    }
}

impl<'a> IntoBytes<'a> for &'a str {
    #[inline(always)]
    fn into_bytes(self) -> Cow<'a, [u8]> {
        Cow::Borrowed(self.as_bytes())
    }
}

impl<'a> IntoBytes<'a> for Vec<u8> {
    #[inline(always)]
    fn into_bytes(self) -> Cow<'a, [u8]> {
        Cow::Owned(self)
    }
}

impl<'a> IntoBytes<'a> for Cow<'a, [u8]> {
    #[inline(always)]
    fn into_bytes(self) -> Cow<'a, [u8]> {
        self
    }
}

impl<'a, A: smallvec::Array<Item = u8>> IntoBytes<'a> for SmallVec<A> {
    #[inline(always)]
    fn into_bytes(self) -> Cow<'a, [u8]> {
        Cow::Owned(self.into_vec())
    }
}

macro_rules! impl_into_bytes_for_int {
    ($($t:ty),* $(,)?) => { $(
        impl<'a> IntoBytes<'a> for $t {
            #[inline(always)]
            fn into_bytes(self) -> Cow<'a, [u8]> {
                Cow::Owned(Vec::from(self.to_le_bytes()))
            }
        }
    )* };
}

// implement for signed/unsigned integer scalars (including pointer-sized)
impl_into_bytes_for_int!{
    f32, f64,
    u8, u16, u32, u64, u128,
    i8, i16, i32, i64, i128,
    usize, isize,
}
