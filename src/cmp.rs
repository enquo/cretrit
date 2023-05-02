//! Comparison helper traits/functions
//!
//! Given that this is a library all about comparison-revealing encryption, it's unsurprising
//! that, sooner or later, you're going to find some comparisons.
//!
//! CRE actually encodes the various "states" of a comparison into non-negative integers, with
//! 0 always meaning "equal" (or at least "nothing interesting here").  The other values that are
//! possible need to be manually mapped in both directions, in line with whatever comparison scheme
//! you're working with.
//!

use std::cmp::Ordering;

use crate::Error;

/// What you have to implement in order to be considered a comparator.
pub trait Comparator<const M: u8> {
    /// Compare two values, return the value that'll get encoded into the ciphertext
    fn compare(a: u16, b: u16) -> u8;
}

/// A comparator implementation that can do <, =, >
#[derive(Debug, Clone)]
pub struct OrderingCMP {}

impl OrderingCMP {
    /// Turn the return value from a CRE comparison into something that users will recognise
    pub fn invert(i: u8) -> Result<Ordering, Error> {
        match i {
            0 => Ok(Ordering::Equal),
            1 => Ok(Ordering::Less),
            2 => Ok(Ordering::Greater),
            _ => Err(Error::RangeError(format!(
                "value passed to invert must be in the range 0..2 (got {i})"
            ))),
        }
    }
}

impl Comparator<3> for OrderingCMP {
    fn compare(a: u16, b: u16) -> u8 {
        match a.cmp(&b) {
            Ordering::Equal => 0,
            Ordering::Less => 1,
            Ordering::Greater => 2,
        }
    }
}

/// A comparator implementation for strict equality
#[derive(Debug, Clone)]
pub struct EqualityCMP {}

impl EqualityCMP {
    /// Turn the return value from a CRE comparison into something that users will recognise
    pub fn invert(i: u8) -> Result<bool, Error> {
        if i > 1 {
            Err(Error::RangeError(format!(
                "value passed to invert must be in the range 0..2 (got {i})"
            )))
        } else {
            Ok(i == 0)
        }
    }
}

impl Comparator<2> for EqualityCMP {
    fn compare(a: u16, b: u16) -> u8 {
        u8::from(a != b)
    }
}
