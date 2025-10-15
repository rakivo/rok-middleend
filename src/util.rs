//! Helper trait for converting T to bytes

use std::vec::Vec;
use std::borrow::Cow;

use smallvec::SmallVec;

#[inline(always)]
#[must_use]
pub const fn align_up(value: u32, alignment: u32) -> u32 {
    (value + alignment - 1) & !(alignment - 1)
}

#[inline(always)]
#[must_use]
pub const fn align_down(value: i32, alignment: i32) -> i32 {
    value & !(alignment - 1)
}

/// # Safety
///
/// Caller ensures that this is safe
#[inline(always)]
pub const unsafe fn reborrow<'a, T>(t: &T) -> &'a T {
    unsafe { &*std::ptr::from_ref::<T>(t) }
}

/// # Safety
///
/// Caller ensures that this is safe
#[inline(always)]
pub const unsafe fn reborrow_mut<'a, T>(t: &mut T) -> &'a mut T {
    unsafe { &mut *std::ptr::from_mut::<T>(t) }
}

/// Helper trait for converting T to bytes
pub trait IntoBytes<'a> {
    #[must_use]
    fn into_bytes(self) -> Cow<'a, [u8]>;

    #[inline(always)]
    fn copy_into(self, dst: &mut [u8])
    where
        Self: Sized
    {
        dst.copy_from_slice(&self.into_bytes());
    }
}

impl<'a> IntoBytes<'a> for crate::bytecode::Opcode {
    #[inline(always)]
    fn into_bytes(self) -> Cow<'a, [u8]> {
        Cow::Owned(Vec::from((self as u8).to_le_bytes()))
    }
}

impl<'a, T> IntoBytes<'a> for T
where
    T: crate::entity::EntityRef
{
    #[inline(always)]
    fn into_bytes(self) -> Cow<'a, [u8]> {
        Cow::Owned(Vec::from((self.index() as u32).to_le_bytes()))
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

#[macro_export]
macro_rules! with_comment {
    (
        $comment_name:ident,
        $(#[$meta:meta])*
        $vis:vis fn $name:ident
        $(<$($generics:tt),*>)?
        (
            &mut $self:ident $(, $param_name:ident: $param_type:ty $(,)?)*
        ) $(-> $ret:ty)? $body:block
    ) => {
        $(#[$meta])*
        $vis fn $name
        $(<$($generics),*>)?
        (&mut $self $(, $param_name: $param_type)*)
        $(-> $ret)?
        $body

        $(#[$meta])*
        #[inline(always)]
        #[allow(unused_attributes)]
        $vis fn $comment_name
        $(<$($generics),*>)?
        (
            &mut $self
            $(, $param_name: $param_type)*,
            #[cfg_attr(not(debug_assertions), allow(unused))]
            comment: impl Into<Box<str>>
        )
        $(-> $ret)?
        {
            let res = $self.$name($($param_name),*);
            #[cfg(debug_assertions)] {
                let inserted_inst = $self.get_last_inst().unwrap();
                $self.insert_comment(inserted_inst, comment);
            }
            res
        }
    };

    (
        $ir_builder:ident,
        $comment_name:ident,
        $(#[$meta:meta])*
        $vis:vis fn $name:ident
        $(<$($generics:tt),*>)?
        (
            &mut $self:ident $(, $param_name:ident: $param_type:ty $(,)?)*
        ) $(-> $ret:ty)? $body:block
    ) => {
        $(#[$meta])*
        $vis fn $name
        $(<$($generics),*>)?
        (&mut $self $(, $param_name: $param_type)*)
        $(-> $ret)?
        $body

        $(#[$meta])*
        #[inline(always)]
        #[allow(unused_attributes)]
        $vis fn $comment_name
        $(<$($generics),*>)?
        (
            &mut $self
            $(, $param_name: $param_type)*,
            #[cfg_attr(not(debug_assertions), allow(unused))]
            comment: impl Into<Box<str>>
        )
        $(-> $ret)?
        {
            let res = $self.$name($($param_name),*);
            #[cfg(debug_assertions)] {
                let inserted_inst = $ir_builder.get_last_inst().unwrap();
                $ir_builder.insert_comment(inserted_inst, comment);
            }
            res
        }
    };

    (
        $ir_builder:ident,
        $comment_name:ident,
        $(#[$meta:meta])*
        $vis:vis fn $name:ident
        $(<$($generics:tt),*>)?
        (
            &$self:ident $(, $param_name:ident: $param_type:ty $(,)?)*
        ) $(-> $ret:ty)? $body:block
    ) => {
        $(#[$meta])*
        $vis fn $name
        $(<$($generics),*>)?
        (&$self $(, $param_name: $param_type)*)
        $(-> $ret)?
        $body

        $(#[$meta])*
        #[inline(always)]
        #[allow(unused_attributes)]
        $vis fn $comment_name
        $(<$($generics),*>)?
        (
            &mut $self
            $(, $param_name: $param_type)*,
            #[cfg_attr(not(debug_assertions), allow(unused))]
            comment: impl Into<Box<str>>
        )
        $(-> $ret)?
        {
            let res = $self.$name($($param_name),*);
            #[cfg(debug_assertions)] {
                let inserted_inst = $ir_builder.get_last_inst().unwrap();
                $ir_builder.insert_comment(inserted_inst, comment);
            }
            res
        }
    };
}
