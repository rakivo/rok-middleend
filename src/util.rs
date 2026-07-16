//! Helper trait for converting T to bytes

use std::borrow::Cow;
use std::vec::Vec;

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
        Self: Sized,
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
impl_into_bytes_for_int! {
    f32, f64,
    u8, u16, u32, u64, u128,
    i8, i16, i32, i64, i128,
    usize, isize,
}

#[macro_export]
macro_rules! with_comment {
    //
    // Internal Code Generators
    //

    // No $ir_builder, &mut self
    (
        @generate
        {
            @mode(1) @builder() @comment_name($comment_name:ident) @meta($(#[$meta:meta])*)
            @vis($vis:vis) @name($name:ident) @generics($(<$($generics:tt),*>)?)
            @self_(&mut $self:ident) @params($($param_name:ident: $param_type:ty),*)
            @ret($(-> $ret:ty)?) @where($($where_clause:tt)*)
        }
        { $($body:tt)* }
    ) => {
        $(#[$meta])*
        $vis fn $name
        $(<$($generics),*>)?
        (&mut $self $(, $param_name: $param_type)*)
        $(-> $ret)?
        $($where_clause)*
        { $($body)* }

        $(#[$meta])*
        #[inline(always)]
        #[allow(unused_attributes)]
        $vis fn $comment_name
        $(<$($generics),*>)?
        (
            &mut $self
            $(, $param_name: $param_type)*,
            #[cfg_attr(not(debug_assertions), allow(unused))]
            comment: impl AsRef<str>
        )
        $(-> $ret)?
        $($where_clause)*
        {
            let res = $self.$name($($param_name),*);
            #[cfg(debug_assertions)] {
                let inserted_inst = $self.get_last_inst().unwrap();
                $self.insert_comment(inserted_inst, comment);
            }
            res
        }
    };

    // Mode 2: $ir_builder, &mut self
    (
        @generate
        {
            @mode(2) @builder($ir_builder:ident) @comment_name($comment_name:ident) @meta($(#[$meta:meta])*)
            @vis($vis:vis) @name($name:ident) @generics($(<$($generics:tt),*>)?)
            @self_(&mut $self:ident) @params($($param_name:ident: $param_type:ty),*)
            @ret($(-> $ret:ty)?) @where($($where_clause:tt)*)
        }
        { $($body:tt)* }
    ) => {
        $(#[$meta])*
        $vis fn $name
        $(<$($generics),*>)?
        (&mut $self $(, $param_name: $param_type)*)
        $(-> $ret)?
        $($where_clause)*
        { $($body)* }

        $(#[$meta])*
        #[inline(always)]
        #[allow(unused_attributes)]
        $vis fn $comment_name
        $(<$($generics),*>)?
        (
            &mut $self
            $(, $param_name: $param_type)*,
            #[cfg_attr(not(debug_assertions), allow(unused))]
            comment: impl AsRef<str>
        )
        $(-> $ret)?
        $($where_clause)*
        {
            let res = $self.$name($($param_name),*);
            #[cfg(debug_assertions)] {
                let inserted_inst = $ir_builder.get_last_inst().unwrap();
                $ir_builder.insert_comment(inserted_inst, comment);
            }
            res
        }
    };

    // Mode 3: $ir_builder, &$self
    (
        @generate
        {
            @mode(3) @builder($ir_builder:ident) @comment_name($comment_name:ident) @meta($(#[$meta:meta])*)
            @vis($vis:vis) @name($name:ident) @generics($(<$($generics:tt),*>)?)
            @self_(&$self:ident) @params($($param_name:ident: $param_type:ty),*)
            @ret($(-> $ret:ty)?) @where($($where_clause:tt)*)
        }
        { $($body:tt)* }
    ) => {
        $(#[$meta])*
        $vis fn $name
        $(<$($generics),*>)?
        (&$self $(, $param_name: $param_type)*)
        $(-> $ret)?
        $($where_clause)*
        { $($body)* }

        $(#[$meta])*
        #[inline(always)]
        #[allow(unused_attributes)]
        $vis fn $comment_name
        $(<$($generics),*>)?
        (
            &mut $self
            $(, $param_name: $param_type)*,
            #[cfg_attr(not(debug_assertions), allow(unused))]
            comment: impl AsRef<str>
        )
        $(-> $ret)?
        $($where_clause)*
        {
            let res = $self.$name($($param_name),*);
            #[cfg(debug_assertions)] {
                let inserted_inst = $ir_builder.get_last_inst().unwrap();
                $ir_builder.insert_comment(inserted_inst, comment);
            }
            res
        }
    };

    //
    // TT Muncher for 'where' clauses
    //

    // Base Case: Only the block '{ ... }' is left. Forward to @generate.
    (
        @munch_where
        { $($ctx:tt)* }
        { $($body:tt)* }
    ) => {
        $crate::with_comment! { @generate { $($ctx)* } { $($body)* } }
    };

    // Recursive Step: Shift one token into the `where` clause.
    (
        @munch_where
        {
            @mode($mode:tt) @builder($($builder:tt)*) @comment_name($comment_name:ident) @meta($(#[$meta:meta])*)
            @vis($vis:vis) @name($name:ident) @generics($(<$($generics:tt),*>)?)
            @self_($($self_tokens:tt)*) @params($($param_name:ident: $param_type:ty),*)
            @ret($(-> $ret:ty)?) @where($($where_clause:tt)*)
        }
        $next:tt $($rest:tt)*
    ) => {
        $crate::with_comment! {
            @munch_where
            {
                @mode($mode) @builder($($builder)*) @comment_name($comment_name) @meta($(#[$meta])*)
                @vis($vis) @name($name) @generics($(<$($generics),*>)?)
                @self_($($self_tokens)*) @params($($param_name: $param_type),*)
                @ret($(-> $ret)?) @where($($where_clause)* $next)
            }
            $($rest)*
        }
    };

    //
    // Public API: Entry Points
    //

    // No $ir_builder, &mut self

    // 1A. No where clause (ty followed directly by `{`, which is legal)
    (
        $comment_name:ident,
        $(#[$meta:meta])*
        $vis:vis fn $name:ident $(<$($generics:tt),*>)?
        ( &mut $self:ident $(, $param_name:ident: $param_type:ty $(,)?)* ) $(-> $ret:ty)?
        { $($body:tt)* }
    ) => {
        $crate::with_comment! {
            @generate
            {
                @mode(1) @builder() @comment_name($comment_name) @meta($(#[$meta])*)
                @vis($vis) @name($name) @generics($(<$($generics),*>)?)
                @self_(&mut $self) @params($($param_name: $param_type),*)
                @ret($(-> $ret)?) @where()
            }
            { $($body)* }
        }
    };

    // 1B. With where clause (ty followed directly by `where`, which is legal)
    (
        $comment_name:ident,
        $(#[$meta:meta])*
        $vis:vis fn $name:ident $(<$($generics:tt),*>)?
        ( &mut $self:ident $(, $param_name:ident: $param_type:ty $(,)?)* ) $(-> $ret:ty)?
        where $($rest:tt)*
    ) => {
        $crate::with_comment! {
            @munch_where
            {
                @mode(1) @builder() @comment_name($comment_name) @meta($(#[$meta])*)
                @vis($vis) @name($name) @generics($(<$($generics),*>)?)
                @self_(&mut $self) @params($($param_name: $param_type),*)
                @ret($(-> $ret)?) @where(where)
            }
            $($rest)*
        }
    };

    // Signature 2: $ir_builder, &mut self

    // 2A. No where clause
    (
        $ir_builder:ident,
        $comment_name:ident,
        $(#[$meta:meta])*
        $vis:vis fn $name:ident $(<$($generics:tt),*>)?
        ( &mut $self:ident $(, $param_name:ident: $param_type:ty $(,)?)* ) $(-> $ret:ty)?
        { $($body:tt)* }
    ) => {
        $crate::with_comment! {
            @generate
            {
                @mode(2) @builder($ir_builder) @comment_name($comment_name) @meta($(#[$meta])*)
                @vis($vis) @name($name) @generics($(<$($generics),*>)?)
                @self_(&mut $self) @params($($param_name: $param_type),*)
                @ret($(-> $ret)?) @where()
            }
            { $($body)* }
        }
    };

    // 2B. With where clause
    (
        $ir_builder:ident,
        $comment_name:ident,
        $(#[$meta:meta])*
        $vis:vis fn $name:ident $(<$($generics:tt),*>)?
        ( &mut $self:ident $(, $param_name:ident: $param_type:ty $(,)?)* ) $(-> $ret:ty)?
        where $($rest:tt)*
    ) => {
        $crate::with_comment! {
            @munch_where
            {
                @mode(2) @builder($ir_builder) @comment_name($comment_name) @meta($(#[$meta])*)
                @vis($vis) @name($name) @generics($(<$($generics),*>)?)
                @self_(&mut $self) @params($($param_name: $param_type),*)
                @ret($(-> $ret)?) @where(where)
            }
            $($rest)*
        }
    };

    // Signature 3: $ir_builder, &$self

    // 3A. No where clause
    (
        $ir_builder:ident,
        $comment_name:ident,
        $(#[$meta:meta])*
        $vis:vis fn $name:ident $(<$($generics:tt),*>)?
        ( &$self:ident $(, $param_name:ident: $param_type:ty $(,)?)* ) $(-> $ret:ty)?
        { $($body:tt)* }
    ) => {
        $crate::with_comment! {
            @generate
            {
                @mode(3) @builder($ir_builder) @comment_name($comment_name) @meta($(#[$meta])*)
                @vis($vis) @name($name) @generics($(<$($generics),*>)?)
                @self_(&$self) @params($($param_name: $param_type),*)
                @ret($(-> $ret)?) @where()
            }
            { $($body)* }
        }
    };

    // 3B. With where clause
    (
        $ir_builder:ident,
        $comment_name:ident,
        $(#[$meta:meta])*
        $vis:vis fn $name:ident $(<$($generics:tt),*>)?
        ( &$self:ident $(, $param_name:ident: $param_type:ty $(,)?)* ) $(-> $ret:ty)?
        where $($rest:tt)*
    ) => {
        $crate::with_comment! {
            @munch_where
            {
                @mode(3) @builder($ir_builder) @comment_name($comment_name) @meta($(#[$meta])*)
                @vis($vis) @name($name) @generics($(<$($generics),*>)?)
                @self_(&$self) @params($($param_name: $param_type),*)
                @ret($(-> $ret)?) @where(where)
            }
            $($rest)*
        }
    };
}
