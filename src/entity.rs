/// A type wrapping a small integer index should implement `EntityRef` so it can be used as the key
/// of an `SecondaryMap` or `SparseMap`.
pub trait EntityRef: Copy + Eq {
    /// Create a new entity reference from a small integer.
    /// This should crash if the requested index is not representable.
    fn new(_: usize) -> Self;

    /// Get the index that was used to create this entity reference.
    fn index(self) -> usize;
}

#[macro_export]
macro_rules! entity_ref {
    // Basic traits.
    ($entity:ident) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $entity(u32);
        $crate::entity_impl!($entity);
    };

    ($entity:ident, $display_prefix:expr) => {
        #[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $entity(u32);
        $crate::entity_impl!($entity, $display_prefix);
    };

    ($entity:ident, $display_prefix:expr, $arg:ident, $to_expr:expr, $from_expr:expr) => {
        #[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $entity(u32);
        $crate::entity_impl!($entity, $display_prefix, $arg, $to_expr, $from_expr);
    }
}

/// Macro which provides the common implementation of a 32-bit entity reference.
#[macro_export]
macro_rules! entity_impl {
    // Basic traits.
    ($entity:ident) => {
        impl $crate::entity::EntityRef for $entity {
            #[inline]
            fn new(index: usize) -> Self {
                $entity(index as u32)
            }

            #[inline]
            fn index(self) -> usize {
                self.0 as usize
            }
        }

        impl $entity {
            /// Create a new instance from a `u32`.
            #[allow(dead_code, reason = "macro-generated code")]
            #[inline]
            pub fn from_u32(x: u32) -> Self {
                $entity(x)
            }

            /// Return the underlying index value as a `u32`.
            #[allow(dead_code, reason = "macro-generated code")]
            #[inline]
            pub fn as_u32(self) -> u32 {
                self.0
            }

            /// Return the raw bit encoding for this instance.
            ///
            /// __Warning__: the raw bit encoding is opaque and has no
            /// guaranteed correspondence to the entity's index. It encodes the
            /// entire state of this index value: either a valid index or an
            /// invalid-index sentinel. The value returned by this method should
            /// only be passed to `from_bits`.
            #[allow(dead_code, reason = "macro-generated code")]
            #[inline]
            pub fn as_bits(self) -> u32 {
                self.0
            }

            /// Create a new instance from the raw bit encoding.
            ///
            /// __Warning__: the raw bit encoding is opaque and has no
            /// guaranteed correspondence to the entity's index. It encodes the
            /// entire state of this index value: either a valid index or an
            /// invalid-index sentinel. The value returned by this method should
            /// only be given bits from `as_bits`.
            #[allow(dead_code, reason = "macro-generated code")]
            #[inline]
            pub fn from_bits(x: u32) -> Self {
                $entity(x)
            }
        }
    };

    // Include basic `Display` impl using the given display prefix.
    // Display a `Block` reference as "block12".
    ($entity:ident, $display_prefix:expr) => {
        $crate::entity_impl!($entity);

        impl std::fmt::Display for $entity {
            fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(f, concat!($display_prefix, "{}"), self.0)
            }
        }

        impl std::fmt::Debug for $entity {
            fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                (self as &dyn std::fmt::Display).fmt(f)
            }
        }
    };

    // Alternate form for tuples we can't directly construct; providing "to" and "from" expressions
    // to turn an index *into* an entity, or get an index *from* an entity.
    ($entity:ident, $display_prefix:expr, $arg:ident, $to_expr:expr, $from_expr:expr) => {
        impl $crate::EntityRef for $entity {
            #[inline]
            fn new(index: usize) -> Self {
                debug_assert!(index < (std::u32::MAX as usize));
                let $arg = index as u32;
                $to_expr
            }

            #[inline]
            fn index(self) -> usize {
                let $arg = self;
                $from_expr as usize
            }
        }

        impl $entity {
            /// Create a new instance from a `u32`.
            #[allow(dead_code, reason = "macro-generated code")]
            #[inline]
            pub fn from_u32(x: u32) -> Self {
                debug_assert!(x < std::u32::MAX);
                let $arg = x;
                $to_expr
            }

            /// Return the underlying index value as a `u32`.
            #[allow(dead_code, reason = "macro-generated code")]
            #[inline]
            pub fn as_u32(self) -> u32 {
                let $arg = self;
                $from_expr
            }
        }

        impl std::fmt::Display for $entity {
            fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(f, concat!($display_prefix, "{}"), self.as_u32())
            }
        }

        impl std::fmt::Debug for $entity {
            fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                (self as &dyn std::fmt::Display).fmt(f)
            }
        }
    };
}

