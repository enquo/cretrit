//! Types to make sequences of bytes comprising individual bits "packed" together
//!
//! CRE ciphertexts are largely comprised of a long set of values that are either 0, 1, or 2.
//! Storing each of those as separate bytes on disk would be hideously wasteful, so part of the
//! serialisation process is to pack them into a stream of bits.
//!

use crate::Error;

/// This seems, annoyingly enough, the easiest way to jam a common function into both structs
macro_rules! fn_next_bit {
    () => {
        fn next_bit(&mut self) {
            if self.bitmask == 128 {
                self.curbyte = self.curbyte.saturating_add(1);
                self.bitmask = 1;
            } else {
                self.bitmask = self.bitmask.wrapping_shl(1u32);
            }
        }
    };
}

/// Construct a Vec<u8> of bits
///
pub(crate) struct WritableBitList {
    /// Where the bits get written
    list: Vec<u8>,
    /// The byte that is currently being written to
    curbyte: usize,
    /// Which bit in the current byte is next to be written, represented as a "mask"
    bitmask: u8,
}

impl WritableBitList {
    /// Create a new `WritableBitList`
    ///
    /// The only thing you can do with a `WritableBitList` is add new bits to the end of the list with
    /// `push()`, then read off the resulting sequence of bytes with `vec()`.
    ///
    /// The `capacity` parameter is the number of ***bits*** you expect to need to store; like the
    /// equivalent parameter of [`Vec::new`](std::vec::Vec::with_capacity), it is just a hint as to
    /// how much space you think you'll need, to save on reallocations as the list grows.
    ///
    pub(crate) fn new(capacity: usize) -> Self {
        Self {
            list: Vec::with_capacity(num::Integer::div_ceil(&capacity, &8)),
            curbyte: 0,
            bitmask: 1,
        }
    }

    /// Add another bit to the list
    pub(crate) fn push(&mut self, b: bool) -> Result<(), Error> {
        if self.bitmask == 1 {
            self.list.push(0);
        }

        if b {
            let byte = self.list.get_mut(self.curbyte).ok_or_else(|| {
                Error::InternalError(format!("Could not get byte {} of vector", self.curbyte))
            })?;
            *byte |= self.bitmask;
        }

        self.next_bit();
        Ok(())
    }

    /// Get the sequence of bytes representing the pushed bits
    pub(crate) fn vec(&self) -> Vec<u8> {
        let mut v = vec![0u8; self.list.len()];
        v.clone_from_slice(&self.list);
        v
    }

    fn_next_bit!();
}

/// Read bits out of a packed slice o' bytes
pub(crate) struct ReadableBitList {
    /// Where the bits are read from
    list: Vec<u8>,
    /// The byte that is currently being read from
    curbyte: usize,
    /// Which bit in the current byte is next to be read, represented as a "mask"
    bitmask: u8,
}

impl ReadableBitList {
    /// Create a bitlist pre-filled with bits from the given slice
    ///
    /// A pre-filled `ReadableBitList` can only have bits read off one-at-a-time from the front, with `shift()`.
    ///
    pub(crate) fn from_slice(s: &[u8]) -> Self {
        let mut v = vec![0u8; s.len()];
        v.clone_from_slice(s);

        Self {
            list: v,
            curbyte: 0,
            bitmask: 1,
        }
    }

    /// Read the next bit off the list
    ///
    /// Returns `None` if we've reached the end of the list.
    ///
    pub(crate) fn shift(&mut self) -> Option<bool> {
        let r = self.list.get(self.curbyte).map(|b| *b & self.bitmask > 0);
        self.next_bit();

        r
    }

    /// Reports whether all bits in the list have been read
    ///
    /// This allows the [`CipherText`](crate::CipherText) to detect whether its input was
    /// malformed, due to there being extra "garbage" data at the end.
    ///
    pub(crate) fn fully_consumed(&self) -> bool {
        self.curbyte == self.list.len()
            || (self.curbyte == self.list.len().saturating_sub(1) && self.bitmask > 1)
    }

    fn_next_bit!();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn micro_push() {
        let mut bl = WritableBitList::new(1);

        bl.push(true).unwrap();
        bl.push(false).unwrap();
        bl.push(true).unwrap();
        bl.push(false).unwrap();
        bl.push(true).unwrap();

        assert_eq!(vec![0x15u8], bl.vec());
    }

    #[test]
    fn smol_push() {
        let mut bl = WritableBitList::new(1);

        for _ in 0..4 {
            bl.push(false).unwrap();
        }

        bl.push(true).unwrap();

        for _ in 0..3 {
            bl.push(false).unwrap();
        }

        bl.push(true).unwrap();

        for _ in 0..12 {
            bl.push(false).unwrap();
        }

        assert_eq!(vec![0x10u8, 0x01, 0x00], bl.vec());
    }

    #[test]
    fn micro_shift() {
        let mut bl = ReadableBitList::from_slice(&vec![0x15u8]);

        assert_eq!(Some(true), bl.shift());
        assert_eq!(Some(false), bl.shift());
        assert_eq!(Some(true), bl.shift());
        assert_eq!(Some(false), bl.shift());
        assert_eq!(Some(true), bl.shift());
        assert_eq!(Some(false), bl.shift());
        assert_eq!(Some(false), bl.shift());
        assert_eq!(Some(false), bl.shift());
        assert_eq!(None, bl.shift());
    }

    #[test]
    fn smol_shift() {
        let mut bl = ReadableBitList::from_slice(&vec![0x10u8, 0x01, 0x00]);

        for _ in 0..4 {
            assert_eq!(Some(false), bl.shift());
        }
        assert_eq!(Some(true), bl.shift());
        for _ in 0..3 {
            assert_eq!(Some(false), bl.shift());
        }
        assert_eq!(Some(true), bl.shift());
        for _ in 0..12 {
            assert_eq!(Some(false), bl.shift());
        }
        for _ in 0..3 {
            assert_eq!(Some(false), bl.shift());
        }
        assert_eq!(None, bl.shift());
    }
}
