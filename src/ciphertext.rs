//! An encrypted, comparable data type.

use std::convert::AsMut;

use crate::bitlist::{ReadableBitList, WritableBitList};
use crate::cipher::Cipher;
use crate::ciphersuite::CipherSuite;
use crate::cmp::Comparator;
use crate::error::Error;
use crate::hash::HashFunction;
use crate::kbkdf::{KBKDFInit, KBKDF};
use crate::plaintext::PlainText;
use crate::prf::PseudoRandomFunction;
use crate::util::check_overflow;

/// Provide the ability to serialise/deserialise a ciphertext
///
/// Convert a [`CipherText`] to/from a sequence of bytes suitable for storage or transmission.
///
pub trait Serializable<const N: usize, const W: u16, const M: u8> {
    /// Parse the [`CipherText`](super::CipherText) data out of a slice of bytes.
    ///
    /// Since a `CipherText`'s exact structure is dependent on the various parameters that went into
    /// creating it, deserialising it goes through the ciphersuite-specific module's `CipherText`
    /// type (such as, for example, [`aes128v1::ore::CipherText`](crate::aes128v1::ore::CipherText)
    /// which itself needs to know the number of blocks and "width" of each block, specified in the
    /// type parameters provided.  It all gets very messy behind the scenes.
    ///
    /// # Examples
    ///
    /// Deserialising a ciphertext for an order-revealing, aes128v1-encrypted, `u32` which has been
    /// chopped up into four blocks with a width of 256 (ie 8 bits):
    ///
    /// ```rust
    /// use cretrit::aes128v1::ore;
    /// use cretrit::SerializableCipherText;
    ///
    /// # fn main() -> Result<(), cretrit::Error> {
    /// # let key = [0u8; 16];
    /// # let cipher = ore::Cipher::<4, 256>::new(key)?;
    /// # let forty_two = cipher.full_encrypt(&42u32.try_into()?)?;
    /// # let serialised_ciphertext = forty_two.to_vec()?;
    /// // Assuming serialised_ciphertext is a Vec<u8> or similar...
    /// let ct = ore::CipherText::<4, 256>::from_slice(&serialised_ciphertext)?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// Will return an error if passed something that isn't a legitimate ciphertext for the given
    /// block count and width, either because N/W is wrong, or because the ciphertext is corrupted
    /// in some way.
    ///
    fn from_slice(bytes: &[u8]) -> Result<Self, Error>
    where
        Self: Sized;

    /// Serialise a [`CipherText`](super::CipherText) into a vector of bytes.
    ///
    /// # Errors
    ///
    /// The only time an error should be returned, really, is when there was a bug in the
    /// serialisation implementation.
    ///
    fn to_vec(&self) -> Result<Vec<u8>, Error>;
}

/// Rust is weird sometimes.
fn clone_into_array<A, T>(slice: &[T]) -> A
where
    A: Sized + Default + AsMut<[T]>,
    T: Clone,
{
    let mut a = Default::default();
    <A as AsMut<[T]>>::as_mut(&mut a).clone_from_slice(slice);
    a
}

/// A generic large-domain left ciphertext for the Lewi-Wu comparison-revealing encryption scheme.
#[derive(Debug)]
pub(crate) struct LeftCipherText<
    'a,
    S: CipherSuite<W, M>,
    CMP: Comparator<M>,
    const N: usize,
    const W: u16,
    const M: u8,
> {
    /// The F(k, p(x)) for each block in the large-domain left ciphertext
    f: [<<S as CipherSuite<W, M>>::PRF as PseudoRandomFunction>::BlockType; N],
    /// The p(x) for each block in the large-domain left ciphertext
    px: [u16; N],
    /// The cipher being used to construct this left ciphertext, or None if this ciphertext came
    /// from deserialisation (in which case it can't be modified, only compared)
    cipher: Option<&'a Cipher<S, CMP, N, W, M>>,
}

impl<'a, S: CipherSuite<W, M>, CMP: Comparator<M>, const N: usize, const W: u16, const M: u8>
    LeftCipherText<'a, S, CMP, N, W, M>
{
    /// Create a new, blank left ciphertext, ready for writing a value into
    pub(crate) fn new(cipher: &'a Cipher<S, CMP, N, W, M>) -> Self {
        LeftCipherText {
            f: [Default::default(); N],
            px: [0; N],
            cipher: Some(cipher),
        }
    }

    /// Encrypt the block value into the `n`th block of the left ciphertext
    pub(crate) fn set_block(&mut self, n: usize, value: u16) -> Result<(), Error> {
        if n >= N {
            return Err(Error::RangeError(format!(
                "attempted to write to the {n}th block of {N} in left ciphertext"
            )));
        }
        if value >= W {
            return Err(Error::RangeError(format!("attempted to write a value {value} greater than the left ciphertext block width {W}")));
        }

        let cipher = self.cipher.ok_or_else(|| {
            Error::InternalError(
                "attempted to set_block on a read-only left ciphertext".to_string(),
            )
        })?;

        let permuted_value = cipher.permuted_value(value)?;

        let px_n_ref = self
            .px
            .get_mut(n)
            .ok_or_else(|| Error::InternalError(format!("failed to write to px[{n}]")))?;
        *px_n_ref = permuted_value;
        let f_n = self
            .f
            .get_mut(n)
            .ok_or_else(|| Error::InternalError(format!("failed to get f[{n}]")))?;
        cipher.pseudorandomise(permuted_value, f_n);

        Ok(())
    }

    /// Retrieve the F(k, p(x)) value for the `n`th block of the left ciphertext
    pub(crate) fn f(
        &self,
        n: usize,
    ) -> Result<<<S as CipherSuite<W, M>>::PRF as PseudoRandomFunction>::BlockType, Error> {
        self.f
            .get(n)
            .ok_or_else(|| {
                Error::RangeError(format!(
                    "attempted to read the {n}th F(k, p(x)) of {N} in left ciphertext"
                ))
            })
            .copied()
    }

    /// Retrieve the p(x) value for the `n`th block of the left ciphertext
    pub(crate) fn px(&self, n: usize) -> Result<u16, Error> {
        self.px
            .get(n)
            .ok_or_else(|| {
                Error::RangeError(format!(
                    "attempted to read the {n}th p(x) of {N} in left ciphertext"
                ))
            })
            .copied()
    }
}

impl<S: CipherSuite<W, M>, CMP: Comparator<M>, const N: usize, const W: u16, const M: u8>
    Serializable<N, W, M> for LeftCipherText<'_, S, CMP, N, W, M>
{
    fn from_slice(bytes: &[u8]) -> Result<Self, Error> {
        let mut f: [<<S as CipherSuite<W, M>>::PRF as PseudoRandomFunction>::BlockType; N] =
            [Default::default(); N];
        // Like I'm typing this out more often than I absolutely need to...
        let f_size = <<S as CipherSuite<W, M>>::PRF as PseudoRandomFunction>::BLOCK_SIZE;
        let mut px = [0u16; N];
        let px_start = check_overflow(
            N.overflowing_mul(f_size),
            &format!("overflow while calculating px_start (N={N}*f_size={f_size})"),
        )?;

        for i in 0..N {
            let first_byte = check_overflow(
                i.overflowing_mul(f_size),
                &format!("overflow while calculating first byte of block (i={i}*f_size={f_size})"),
            )?;
            let last_byte = check_overflow(first_byte.overflowing_add(f_size), &format!("overflow while calculating last byte of block (first_byte={first_byte}+f_size={f_size})"))?;
            let block = bytes.get(first_byte..last_byte).ok_or_else(|| {
                Error::ParseError(format!("end-of-data while looking for f[{i}]"))
            })?;
            let f_i_ref = f.get_mut(i).ok_or_else(|| {
                Error::ParseError(format!("could not get f[{i}] to write block into"))
            })?;
            *f_i_ref = clone_into_array(block);

            let px_i = if W <= 256 {
                u16::from(
                    *bytes
                        .get(check_overflow(
                            px_start.overflowing_add(i),
                            &format!("overflow while adding i={i} to px_start={px_start}"),
                        )?)
                        .ok_or_else(|| {
                            Error::ParseError(format!("end-of-data while looking for px[{i}]"))
                        })?,
                )
            } else {
                let px_loc = check_overflow(
                    px_start.overflowing_add(check_overflow(
                        i.overflowing_add(2),
                        &format!(
                            "overflow while multiplying i={i} by 2 in LeftCipherText::from_slice"
                        ),
                    )?),
                    &format!("overflow while adding px_start={px_start} to 2*{i}"),
                )?;
                let px_bytes = bytes.get(px_loc..=px_loc).ok_or_else(|| {
                    Error::ParseError(format!("end-of-data while looking for px[{i}]"))
                })?;
                u16::from_be_bytes(px_bytes.try_into().map_err(|e| {
                    Error::ParseError(format!(
                        "failed to convert {px_bytes:?} into u16 for px[{i}] ({e})"
                    ))
                })?)
            };
            let px_i_ref = px.get_mut(i).ok_or_else(|| Error::InternalError(format!("failed to get {i}th element of px array (which is supposed to have {N} elements)")))?;
            *px_i_ref = px_i;
        }

        Ok(Self {
            f,
            px,
            cipher: None,
        })
    }

    fn to_vec(&self) -> Result<Vec<u8>, Error> {
        let f_size = <<S as CipherSuite<W, M>>::PRF as PseudoRandomFunction>::BLOCK_SIZE;

        let mut v: Vec<u8> = Vec::with_capacity(N.saturating_mul(f_size.saturating_add(2)));

        for n in 0..N {
            v.extend_from_slice(
                &(*self.f.get(n).ok_or_else(|| {
                    Error::RangeError(format!(
                        "failed to get {n}th F(k, p(x)) from left ciphertext"
                    ))
                })?)
                .into(),
            );
        }
        for n in 0..N {
            let px_n = self.px.get(n).ok_or_else(|| {
                Error::RangeError(format!("failed to get {n}th p(x) from left ciphertext"))
            })?;
            if W <= 256 {
                v.extend_from_slice(&(u8::try_from(*px_n).map_err(|e| Error::InternalError(format!("failed to convert {px_n} to u8, even though it's supposed to be within range ({e})")))?).to_be_bytes());
            } else {
                v.extend_from_slice(&(*px_n).to_be_bytes());
            }
        }

        Ok(v)
    }
}

/// A generic large-domain right ciphertext for the Lewi-Wu comparison-revealing encryption scheme.
#[derive(Debug)]
pub(crate) struct RightCipherText<
    'a,
    S: CipherSuite<W, M>,
    CMP: Comparator<M>,
    const N: usize,
    const W: u16,
    const M: u8,
> {
    /// The base nonce from which the per-block nonces are derived
    nonce_base: [u8; 16],
    /// Cached copies of the per-block nonces
    nonce_cache: [[u8; 16]; N],
    /// The v_i sequences for each block
    values: Vec<Vec<u8>>,
    /// The cipher instance with which to encrypt the blocks if we're writing, or None if this
    /// ciphertext came from deserialisation (in which case it cannot be written, only compared)
    cipher: Option<&'a Cipher<S, CMP, N, W, M>>,
}

impl<'a, S: CipherSuite<W, M>, CMP: Comparator<M>, const N: usize, const W: u16, const M: u8>
    RightCipherText<'a, S, CMP, N, W, M>
{
    /// Spawn a new right ciphertext, ready to have its blocks written
    pub(crate) fn new(cipher: &'a Cipher<S, CMP, N, W, M>) -> Result<Self, Error> {
        let values: Vec<Vec<u8>> = (0..N).map(|_| vec![0u8; W as usize]).collect();
        let mut rct = RightCipherText {
            nonce_base: Default::default(),
            nonce_cache: [Default::default(); N],
            values,
            cipher: Some(cipher),
        };

        cipher.fill_nonce(&mut rct.nonce_base)?;

        Self::cache_nonces(&mut rct)?;

        Ok(rct)
    }

    /// Generate the per-block nonces and cache them so we don't have to generate them every time
    /// we want to read them
    fn cache_nonces(rct: &mut RightCipherText<'a, S, CMP, N, W, M>) -> Result<(), Error> {
        let ndf = S::KBKDF::new(&rct.nonce_base)?;

        for i in 0..N {
            let mut k = Vec::<u8>::with_capacity(11);
            k.extend_from_slice(b"RCTnonce.");
            k.extend_from_slice(
                &(u16::try_from(i).map_err(|e| {
                    Error::RangeError(format!("failed to convert {i} to u16 ({e})"))
                })?)
                .to_be_bytes(),
            );

            ndf.derive_key(
                rct.nonce_cache.get_mut(i).ok_or_else(|| {
                    Error::RangeError(format!("failed to get {i}th nonce from cache"))
                })?,
                &k,
            )?;
        }

        Ok(())
    }

    /// Encrypt the value provided into the `n`th block of the right ciphertext
    pub(crate) fn set_block(&mut self, n: usize, value: u16) -> Result<(), Error> {
        if n >= N {
            return Err(Error::RangeError(format!(
                "attempted to write to the {n}th block of {N} in right ciphertext"
            )));
        }
        if value >= W {
            return Err(Error::RangeError(format!("attempted to write a value {value} greater than the right ciphertext block width {W}")));
        }
        let cipher = self.cipher.ok_or_else(|| {
            Error::InternalError(
                "attempted to set_block on a read-only right ciphertext".to_string(),
            )
        })?;

        for i in 0..W {
            let mut b: <<S as CipherSuite<W, M>>::PRF as PseudoRandomFunction>::BlockType =
                Default::default();

            cipher.pseudorandomise(i, &mut b);

            let p_i_y = CMP::compare(cipher.inverse_permuted_value(i)?, value);
            let nonce = self.nonce(n)?;
            let h_f_r = <<S as CipherSuite<W, M>>::HF as HashFunction<M>>::hash(&b.into(), &nonce)?;

            // Absolutely *shits* me that we can't get this ref once at the top of the function;
            // nope, gotta deref it on every loop to keep the borrow checker happy
            let block_values = self.values.get_mut(n).ok_or_else(|| {
                Error::RangeError(format!(
                    "attempted to set_block on {n}th block of {N} of right ciphertext"
                ))
            })?;
            let v_ref = block_values.get_mut(usize::from(i)).ok_or_else(|| {
                Error::RangeError(format!("couldn't set {i}th value of {n}th block"))
            })?;
            *v_ref = check_overflow(p_i_y.overflowing_add(h_f_r), &format!("overflow while attempting to add right ciphertext value components p_i_y={p_i_y}, h_f_r={h_f_r}"))?.rem_euclid(M);
        }

        Ok(())
    }

    /// Fetch the value of the `px`th element in the `n`th block of the [`RightCipherText`].
    ///
    pub(crate) fn value(&self, n: usize, px: u16) -> Result<u8, Error> {
        self.values
            .get(n)
            .ok_or_else(|| {
                Error::RangeError(format!(
                    "attempted to get the values of the {n}th block of {N}"
                ))
            })?
            .get(usize::from(px))
            .ok_or_else(|| {
                Error::RangeError(format!("couldn't get the {px}th value of the {n}th block"))
            })
            .copied()
    }

    /// Fetch the nonce for the `n`th block of the [`RightCipherText`].
    ///
    pub(crate) fn nonce(&self, n: usize) -> Result<[u8; 16], Error> {
        self.nonce_cache
            .get(n)
            .ok_or_else(|| {
                Error::RangeError(format!("attempted to get the {n}th nonce of {N} blocks"))
            })
            .copied()
    }

    /// Decode a packed set of binary values into the nested vector-of-vectors that is the
    /// in-memory representation of the values arrays in the right ciphertext.
    fn unpack_binary_values(bytes: &[u8]) -> Result<Vec<Vec<u8>>, Error> {
        let mut v = ReadableBitList::from_slice(bytes);
        let mut vals: Vec<Vec<u8>> = Vec::with_capacity(N);

        for _n in 0..N {
            let mut block_vals = Vec::with_capacity(W.into());
            for _w in 0..W {
                let b = u8::from(v.shift().ok_or_else(|| {
                    Error::ParseError(
                        "end-of-data reached while unpacking binary values".to_string(),
                    )
                })?);
                block_vals.push(b);
            }
            vals.push(block_vals);
        }

        if v.fully_consumed() {
            Ok(vals)
        } else {
            Err(Error::ParseError(
                "bitlist longer than required number of entries".to_string(),
            ))
        }
    }

    /// Jam all of the binary values for this ciphertext into a byte vector, in such a way that
    /// they take up a *lot* less space than they would if we just wrote out each value as a u8.
    fn pack_binary_values(&self) -> Result<Vec<u8>, Error> {
        let mut v = WritableBitList::new(N.saturating_mul(usize::from(W)));

        for n in 0..N {
            for w in 0..W {
                let val = self
                    .values
                    .get(n)
                    .ok_or_else(|| {
                        Error::RangeError(format!(
                            "could not get value list for {n}th block because it wasn't there"
                        ))
                    })?
                    .get(usize::from(w))
                    .ok_or_else(|| {
                        Error::RangeError(format!("could not get {w}th value from {n}th block"))
                    })?;
                v.push(*val > 0)?;
            }
        }

        Ok(v.vec())
    }

    /// Decode a packed set of trinary values into the nested vector-of-vectors that is the
    /// in-memory representation of the values arrays in the right ciphertext.
    fn unpack_trinary_values(bytes: &[u8]) -> Result<Vec<Vec<u8>>, Error> {
        let mut v = ReadableBitList::from_slice(bytes);
        let mut vals: Vec<Vec<u8>> = Vec::with_capacity(N);

        for _n in 0..N {
            let mut block_vals = Vec::with_capacity(W.into());
            for _w in 0..W {
                let b = if v.shift().ok_or_else(|| {
                    Error::ParseError(
                        "end-of-data reached while unpacking trinary values".to_string(),
                    )
                })? {
                    if v.shift().ok_or_else(|| {
                        Error::ParseError(
                            "end-of-data reached while unpacking trinary values".to_string(),
                        )
                    })? {
                        2
                    } else {
                        1
                    }
                } else {
                    0
                };
                block_vals.push(b);
            }
            vals.push(block_vals);
        }

        if v.fully_consumed() {
            Ok(vals)
        } else {
            Err(Error::ParseError(
                "bitlist longer than required number of entries".to_string(),
            ))
        }
    }

    /// Jam all of the trinary values for this ciphertext into a byte vector, in such a way that
    /// they take up a *lot* less space than they would if we just wrote out each value as a u8.
    fn pack_trinary_values(&self) -> Result<Vec<u8>, Error> {
        let mut v = WritableBitList::new(N.saturating_mul(usize::from(W).saturating_mul(2usize)));

        for n in 0..N {
            for w in 0..W {
                let val = self
                    .values
                    .get(n)
                    .ok_or_else(|| {
                        Error::RangeError(format!(
                            "could not get value list for {n}th block because it wasn't there"
                        ))
                    })?
                    .get(usize::from(w))
                    .ok_or_else(|| {
                        Error::RangeError(format!("could not get {w}th value from {n}th block"))
                    })?;

                if *val == 0 {
                    v.push(false)?;
                } else {
                    v.push(true)?;
                    if *val > 1 {
                        v.push(true)?;
                    } else {
                        v.push(false)?;
                    }
                }
            }
        }

        Ok(v.vec())
    }
}

impl<'a, S: CipherSuite<W, M>, CMP: Comparator<M>, const N: usize, const W: u16, const M: u8>
    Serializable<N, W, M> for RightCipherText<'a, S, CMP, N, W, M>
{
    fn from_slice(bytes: &[u8]) -> Result<Self, Error> {
        let nonce_base: [u8; 16] = clone_into_array(bytes.get(0..16).ok_or_else(|| {
            Error::ParseError("end-of-data found while looking for nonce base".to_string())
        })?);

        let value_slice = bytes.get(16..).ok_or_else(|| {
            Error::ParseError("end-of-data found while looking for value bitlist".to_string())
        })?;
        let values = if M == 2 {
            Self::unpack_binary_values(value_slice)
        } else if M == 3 {
            Self::unpack_trinary_values(value_slice)
        } else {
            Err(Error::RangeError(format!(
                "don't know how to unpack bytes for M={M}"
            )))
        }?;

        let mut rct = RightCipherText::<'a, S, CMP, N, W, M> {
            nonce_base,
            values,
            nonce_cache: [Default::default(); N],
            cipher: None,
        };
        Self::cache_nonces(&mut rct)?;

        Ok(rct)
    }

    fn to_vec(&self) -> Result<Vec<u8>, Error> {
        let mut v: Vec<u8> = Vec::with_capacity(
            16usize.saturating_add(N.saturating_mul(usize::from(W).saturating_div(4usize))),
        );

        v.extend_from_slice(&self.nonce_base);

        let value_slice = if M == 2 {
            self.pack_binary_values()
        } else if M == 3 {
            self.pack_trinary_values()
        } else {
            Err(Error::RangeError(format!(
                "don't know how to pack values for M={M}"
            )))
        }?;

        v.extend_from_slice(&value_slice);

        Ok(v)
    }
}

/// A Comparison-Revealing Encrypted value.
///
#[doc = include_str!("../doc/ciphertexts.md")]
#[derive(Debug)]
pub struct CipherText<
    'a,
    S: CipherSuite<W, M>,
    CMP: Comparator<M>,
    const N: usize,
    const W: u16,
    const M: u8,
> {
    /// The left part of the ciphertext, or None if this is a IND-CPA secure ciphertext
    pub(crate) left: Option<LeftCipherText<'a, S, CMP, N, W, M>>,
    /// The right side of the ciphertext
    pub(crate) right: RightCipherText<'a, S, CMP, N, W, M>,
}

impl<'a, S: CipherSuite<W, M>, CMP: Comparator<M>, const N: usize, const W: u16, const M: u8>
    CipherText<'a, S, CMP, N, W, M>
{
    /// Encrypt the plaintext to produce a new comparable ciphertext.
    ///
    /// This produces a ciphertext that contains both the "left" and "right" parts, which are
    /// required in order to perform a comparison.  However, the "left" ciphertext is
    /// deterministic, so if the same value is encrypted multiple times with the same key, the
    /// "left" ciphertext will always be the same.  This makes storing "left" ciphertexts somewhat
    /// problematic, because it means that an attacker who makes off with your database of "left"
    /// ciphertexts can perform correlation attacks to try and figure out what values are.
    ///
    pub(crate) fn new(
        cipher: &'a Cipher<S, CMP, N, W, M>,
        plaintext: &PlainText<N, W>,
    ) -> Result<Self, Error> {
        let mut left = LeftCipherText::new(cipher);
        let mut right = RightCipherText::new(cipher)?;

        for n in 0..N {
            left.set_block(n, plaintext.block(n)?)?;
            right.set_block(n, plaintext.block(n)?)?;
        }

        Ok(CipherText {
            left: Some(left),
            right,
        })
    }

    /// Encrypt the plaintext to produce a new ciphertext that only contains a "right" ciphertext.
    ///
    /// In the Lewi-Wu ORE scheme, a "left" ciphertext must be compared with a "right" ciphertext
    /// in order for a comparison to be performed.  Producing a ciphertext that only contains a
    /// "right" ciphertext means that you have something that cannot be directly compared to other
    /// "right" ciphertexts, but it does have the useful property of being [IND-CPA
    /// secure](https://en.wikipedia.org/wiki/Ciphertext_indistinguishability).
    ///
    pub(crate) fn new_right(
        cipher: &'a Cipher<S, CMP, N, W, M>,
        plaintext: &PlainText<N, W>,
    ) -> Result<Self, Error> {
        let mut right = RightCipherText::new(cipher)?;

        for n in 0..N {
            right.set_block(n, plaintext.block(n)?)?;
        }

        Ok(CipherText { left: None, right })
    }

    /// Generic comparison function between [`CipherText`]s.
    ///
    /// Comparison in the Lewi-Wu ORE scheme produces an integer result, and it is up to the
    /// comparator to interpret that integer into something meaningful for the given comparator.
    ///
    pub(crate) fn compare(&self, other: &Self) -> Result<u8, Error> {
        match &self.left {
            None => Err(Error::ComparisonError(
                "No left part in this ciphertext".to_string(),
            )),
            Some(v) => Self::compare_parts(v, &other.right),
        }
    }

    /// Determine whether this ciphertext has a "left" ciphertext
    ///
    pub fn has_left(&self) -> bool {
        self.left.is_some()
    }

    /// Compare two ciphertexts
    ///
    /// Returns the numeric comparison value, which needs to be run through the comparator's invert
    /// function in order to convert that into a "proper" logical comparison value.
    ///
    fn compare_parts(
        left: &LeftCipherText<'a, S, CMP, N, W, M>,
        right: &RightCipherText<'a, S, CMP, N, W, M>,
    ) -> Result<u8, Error> {
        let mut result: Option<u8> = None;

        for n in 0..N {
            let v_h = check_overflow(
                right.value(n, left.px(n)?)?.overflowing_add(M),
                "overflow while adding M to v_h",
            )?;
            let h_k_r = S::HF::hash(&left.f(n)?.into(), &right.nonce(n)?)?;

            let res = check_overflow(v_h.overflowing_sub(h_k_r), "overflow on v_h - h_k_r")?
                .rem_euclid(M);

            if res != 0 && result.is_none() {
                // Returning early here would further damage our attempts to
                // do constant-time comparisons
                result = Some(res);
            }
        }

        Ok(result.unwrap_or(0))
    }
}

impl<'a, S: CipherSuite<W, M>, CMP: Comparator<M>, const N: usize, const W: u16, const M: u8>
    Serializable<N, W, M> for CipherText<'a, S, CMP, N, W, M>
{
    fn from_slice(bytes: &[u8]) -> Result<Self, Error> {
        let mut v = bytes;

        let t = v.first().ok_or_else(|| {
            Error::ParseError("end-of-data while looking for ciphertext type marker".to_string())
        })?;
        v = v.get(1..).ok_or_else(|| {
            Error::ParseError(
                "end-of-data while looking for rest of ciphertext after ciphertext type marker"
                    .to_string(),
            )
        })?;

        let left: Option<LeftCipherText<'a, S, CMP, N, W, M>> = if *t == 0 {
            None
        } else if *t == 1 {
            let len_bytes = v.get(..2).ok_or_else(|| {
                Error::ParseError(
                    "end-of-data while looking for left ciphertext length".to_string(),
                )
            })?;
            v = v.get(2..).ok_or_else(|| {
                Error::ParseError(
                    "end-of-data while looking for rest of ciphertext after left ciphertext length"
                        .to_string(),
                )
            })?;
            let len = u16::from_be_bytes(len_bytes.try_into().map_err(|e| {
                Error::ParseError(format!(
                    "failed to convert {len_bytes:?} into u16 for left ciphertext length ({e})"
                ))
            })?) as usize;
            let left_bytes = v.get(..len).ok_or_else(|| {
                Error::ParseError("end-of-data while looking for left ciphertext".to_string())
            })?;
            v = v.get(len..).ok_or_else(|| {
                Error::ParseError("end-of-data while looking for rest of ciphertext".to_string())
            })?;
            Some(LeftCipherText::<'a, S, CMP, N, W, M>::from_slice(
                left_bytes,
            )?)
        } else {
            return Err(Error::ParseError(format!("unrecognised type byte {t}")));
        };

        let len_bytes = v.get(..2).ok_or_else(|| {
            Error::ParseError("end-of-data while looking for right ciphertext length".to_string())
        })?;
        v = v.get(2..).ok_or_else(|| {
            Error::ParseError("end-of-data while looking for right ciphertext".to_string())
        })?;
        let len = u16::from_be_bytes(len_bytes.try_into().map_err(|e| {
            Error::ParseError(format!(
                "failed to convert {len_bytes:?} into u16 for right ciphertext length ({e})"
            ))
        })?) as usize;

        if len == v.len() {
            let right_bytes = v.get(..len).ok_or_else(|| {
                Error::ParseError("end-of-data while looking for right ciphertext".to_string())
            })?;
            let right = RightCipherText::<'a, S, CMP, N, W, M>::from_slice(right_bytes)?;

            Ok(CipherText::<'a, S, CMP, N, W, M> { left, right })
        } else {
            Err(Error::ParseError(format!(
                "length does not match size in right ciphertext (expected={len}, actual={})",
                v.len()
            )))
        }
    }

    fn to_vec(&self) -> Result<Vec<u8>, Error> {
        let f_size = <<S as CipherSuite<W, M>>::PRF as PseudoRandomFunction>::BLOCK_SIZE;

        // Saturating arithmetic is fine here, because even if we end up with an underestimate of
        // the vector's capacity, it can always expand it later
        //
        // 5 for type byte (u8), left CT len (maybe u16), right CT len (u16)
        let meta_len: usize = 5;
        // N * (f_size + 2) + 16 for left CT, just in case it's needed
        let left_len: usize =
            N.saturating_mul(f_size.saturating_add(2usize).saturating_add(16usize));
        // 16 + N * W / 4 for right CT
        let right_len: usize =
            16usize.saturating_add(N.saturating_mul(num::Integer::div_ceil(&W.into(), &4usize)));
        let vec_len: usize = meta_len.saturating_add(left_len).saturating_add(right_len);
        let mut v: Vec<u8> = Vec::with_capacity(vec_len);

        // Type byte -- 0 is just a right CT, 1 is left+right
        // other values to be worried about later
        match &self.left {
            Some(l) => {
                v.push(1);
                let left_bytes = l.to_vec()?;
                v.extend_from_slice(
                    &u16::try_from(left_bytes.len())
                        .map_err(|e| {
                            Error::RangeError(format!(
                                "Couldn't represent length left_bytes ({}) as u16 ({e})",
                                left_bytes.len()
                            ))
                        })?
                        .to_be_bytes(),
                );
                v.extend_from_slice(&left_bytes);
            }
            None => v.push(0),
        };

        let right_bytes = self.right.to_vec()?;
        v.extend_from_slice(
            &u16::try_from(right_bytes.len())
                .map_err(|e| {
                    Error::RangeError(format!(
                        "Couldn't represent length of right_bytes ({}) as u16 ({e})",
                        right_bytes.len()
                    ))
                })?
                .to_be_bytes(),
        );
        v.extend_from_slice(&right_bytes);

        Ok(v)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::Rng;

    fn key() -> [u8; 16] {
        let mut k: [u8; 16] = Default::default();

        // Yes, using a potentially-weak RNG would normally be terribad, but
        // for testing purposes, it's not going to break anything
        let mut rng = rand::thread_rng();

        rng.try_fill(&mut k).unwrap();

        k
    }

    mod ere {
        use super::*;
        use crate::aes128v1::ere;

        #[cfg(feature = "serde")]
        use serde_json;

        #[test]
        fn full_ciphertext_has_left() {
            let cipher = ere::Cipher::<8, 256>::new(key()).unwrap();

            let n = cipher.full_encrypt(&31_337u64.try_into().unwrap()).unwrap();

            assert!(n.has_left());
        }

        #[test]
        fn right_ciphertext_does_not_have_left() {
            let cipher = ere::Cipher::<8, 256>::new(key()).unwrap();

            let n = cipher
                .right_encrypt(&31_337u64.try_into().unwrap())
                .unwrap();

            assert!(!n.has_left());
        }

        #[test]
        fn binary_full_ciphertext_roundtrips_correctly() {
            let cipher = ere::Cipher::<8, 256>::new(key()).unwrap();

            let n = cipher.full_encrypt(&31_337u64.try_into().unwrap()).unwrap();

            let v = n.to_vec().unwrap();

            let n_rt = ere::CipherText::<8, 256>::from_slice(&v).unwrap();

            assert_eq!(n, n_rt);
            assert_eq!(n_rt, n);
        }

        #[test]
        fn binary_right_ciphertext_roundtrips_correctly() {
            let cipher = ere::Cipher::<8, 256>::new(key()).unwrap();

            let n1 = cipher.full_encrypt(&31_337u64.try_into().unwrap()).unwrap();
            let n2 = cipher
                .right_encrypt(&31_337u64.try_into().unwrap())
                .unwrap();

            let v = n2.to_vec().unwrap();

            let n2_rt = ere::CipherText::<8, 256>::from_slice(&v).unwrap();

            assert_eq!(n1, n2_rt);
        }

        #[test]
        #[cfg(feature = "serde")]
        fn serde_full_ciphertext_roundtrips_correctly() {
            let cipher = ere::Cipher::<8, 256>::new(key()).unwrap();

            let n = cipher.full_encrypt(&31_337u64.try_into().unwrap()).unwrap();

            let s = serde_json::to_string(&n).unwrap();

            let n_rt: ere::CipherText<'_, 8, 256> = serde_json::from_str(&s).unwrap();

            assert_eq!(n, n_rt);
            assert_eq!(n_rt, n);
        }

        #[test]
        #[cfg(feature = "serde")]
        fn serde_right_ciphertext_roundtrips_correctly() {
            let cipher = ere::Cipher::<8, 256>::new(key()).unwrap();

            let n1 = cipher.full_encrypt(&31_337u64.try_into().unwrap()).unwrap();
            let n2 = cipher
                .right_encrypt(&31_337u64.try_into().unwrap())
                .unwrap();

            let s = serde_json::to_string(&n2).unwrap();
            dbg!(&s);

            let n2_rt: ere::CipherText<'_, 8, 256> = serde_json::from_str(&s).unwrap();

            assert_eq!(n1, n2_rt);
        }

        #[test]
        fn cannot_deserialise_full_ciphertext_with_smaller_chunk_count() {
            let cipher = ere::Cipher::<4, 256>::new(key()).unwrap();

            let n = cipher.full_encrypt(&31_337u32.try_into().unwrap()).unwrap();
            let v = n.to_vec().unwrap();

            assert!(ere::CipherText::<8, 256>::from_slice(&v).is_err());
        }

        #[test]
        fn cannot_deserialise_full_ciphertext_with_larger_chunk_count() {
            let cipher = ere::Cipher::<8, 256>::new(key()).unwrap();

            let n = cipher.full_encrypt(&31_337u32.try_into().unwrap()).unwrap();
            let v = n.to_vec().unwrap();

            assert!(ere::CipherText::<4, 256>::from_slice(&v).is_err());
        }

        #[test]
        fn cannot_deserialise_full_ciphertext_with_smaller_chunk_width() {
            let cipher = ere::Cipher::<4, 16>::new(key()).unwrap();

            let n = cipher.full_encrypt(&42u16.try_into().unwrap()).unwrap();
            let v = n.to_vec().unwrap();

            assert!(ere::CipherText::<4, 256>::from_slice(&v).is_err());
        }

        #[test]
        fn cannot_deserialise_full_ciphertext_with_larger_chunk_width() {
            let cipher = ere::Cipher::<4, 256>::new(key()).unwrap();

            let n = cipher.full_encrypt(&42u16.try_into().unwrap()).unwrap();
            let v = n.to_vec().unwrap();

            assert!(ere::CipherText::<4, 16>::from_slice(&v).is_err());
        }

        #[test]
        fn cannot_deserialise_right_ciphertext_with_smaller_chunk_count() {
            let cipher = ere::Cipher::<4, 256>::new(key()).unwrap();

            let n = cipher
                .right_encrypt(&31_337u32.try_into().unwrap())
                .unwrap();
            let v = n.to_vec().unwrap();

            assert!(ere::CipherText::<8, 256>::from_slice(&v).is_err());
        }

        #[test]
        fn cannot_deserialise_right_ciphertext_with_larger_chunk_count() {
            let cipher = ere::Cipher::<8, 256>::new(key()).unwrap();

            let n = cipher
                .right_encrypt(&31_337u32.try_into().unwrap())
                .unwrap();
            let v = n.to_vec().unwrap();

            assert!(ere::CipherText::<4, 256>::from_slice(&v).is_err());
        }

        #[test]
        fn cannot_deserialise_right_ciphertext_with_smaller_chunk_width() {
            let cipher = ere::Cipher::<4, 16>::new(key()).unwrap();

            let n = cipher.right_encrypt(&42u16.try_into().unwrap()).unwrap();
            let v = n.to_vec().unwrap();

            assert!(ere::CipherText::<4, 256>::from_slice(&v).is_err());
        }

        #[test]
        fn cannot_deserialise_right_ciphertext_with_larger_chunk_width() {
            let cipher = ere::Cipher::<4, 256>::new(key()).unwrap();

            let n = cipher.right_encrypt(&42u16.try_into().unwrap()).unwrap();
            let v = n.to_vec().unwrap();

            assert!(ere::CipherText::<4, 16>::from_slice(&v).is_err());
        }
    }

    mod ore {
        use super::*;
        use crate::aes128v1::ore;

        #[test]
        fn trinary_full_ciphertext_roundtrips_correctly() {
            let cipher = ore::Cipher::<8, 256>::new(key()).unwrap();

            let n1 = cipher.full_encrypt(&42u64.try_into().unwrap()).unwrap();
            let n2 = cipher.full_encrypt(&31_337u64.try_into().unwrap()).unwrap();

            let v1 = n1.to_vec().unwrap();
            let v2 = n2.to_vec().unwrap();

            let n1_rt = ore::CipherText::<8, 256>::from_slice(&v1).unwrap();
            let n2_rt = ore::CipherText::<8, 256>::from_slice(&v2).unwrap();

            assert!(n1 == n1_rt);
            assert!(n2 == n2_rt);
            assert!(n1 < n2_rt);
            assert!(n2 > n1_rt);

            assert!(n1_rt == n1);
            assert!(n2_rt == n2);
            assert!(n1_rt < n2);
            assert!(n2_rt > n1);
        }

        #[test]
        fn trinary_right_ciphertext_roundtrips_correctly() {
            let cipher = ore::Cipher::<8, 256>::new(key()).unwrap();

            let n1f = cipher.full_encrypt(&42u64.try_into().unwrap()).unwrap();
            let mut n1r = cipher.full_encrypt(&42u64.try_into().unwrap()).unwrap();
            n1r.left = None;

            let v1r = n1r.to_vec().unwrap();

            let n1r_rt = ore::CipherText::<8, 256>::from_slice(&v1r).unwrap();

            let n2f = cipher.full_encrypt(&31_337u64.try_into().unwrap()).unwrap();
            let mut n2r = cipher.full_encrypt(&31_337u64.try_into().unwrap()).unwrap();
            n2r.left = None;

            let v2r = n2r.to_vec().unwrap();

            let n2r_rt = ore::CipherText::<8, 256>::from_slice(&v2r).unwrap();

            assert!(n1f == n1r_rt);
            assert!(n2f == n2r_rt);
            assert!(n1f < n2r_rt);
            assert!(n2f > n1r_rt);
        }

        #[test]
        fn cannot_deserialise_full_ciphertext_with_smaller_chunk_count() {
            let cipher = ore::Cipher::<4, 256>::new(key()).unwrap();

            let n = cipher.full_encrypt(&31_337u32.try_into().unwrap()).unwrap();
            let v = n.to_vec().unwrap();

            assert!(ore::CipherText::<8, 256>::from_slice(&v).is_err());
        }

        #[test]
        fn cannot_deserialise_full_ciphertext_with_larger_chunk_count() {
            let cipher = ore::Cipher::<8, 256>::new(key()).unwrap();

            let n = cipher.full_encrypt(&31_337u32.try_into().unwrap()).unwrap();
            let v = n.to_vec().unwrap();

            assert!(ore::CipherText::<4, 256>::from_slice(&v).is_err());
        }

        #[test]
        fn cannot_deserialise_full_ciphertext_with_smaller_chunk_width() {
            let cipher = ore::Cipher::<4, 16>::new(key()).unwrap();

            let n = cipher.full_encrypt(&42u16.try_into().unwrap()).unwrap();
            let v = n.to_vec().unwrap();

            assert!(ore::CipherText::<4, 256>::from_slice(&v).is_err());
        }

        #[test]
        fn cannot_deserialise_full_ciphertext_with_larger_chunk_width() {
            let cipher = ore::Cipher::<4, 256>::new(key()).unwrap();

            let n = cipher.full_encrypt(&42u16.try_into().unwrap()).unwrap();
            let v = n.to_vec().unwrap();

            assert!(ore::CipherText::<4, 16>::from_slice(&v).is_err());
        }

        #[test]
        fn cannot_deserialise_right_ciphertext_with_smaller_chunk_count() {
            let cipher = ore::Cipher::<4, 256>::new(key()).unwrap();

            let n = cipher
                .right_encrypt(&31_337u32.try_into().unwrap())
                .unwrap();
            let v = n.to_vec().unwrap();

            assert!(ore::CipherText::<8, 256>::from_slice(&v).is_err());
        }

        #[test]
        fn cannot_deserialise_right_ciphertext_with_larger_chunk_count() {
            let cipher = ore::Cipher::<8, 256>::new(key()).unwrap();

            let n = cipher
                .right_encrypt(&31_337u32.try_into().unwrap())
                .unwrap();
            let v = n.to_vec().unwrap();

            assert!(ore::CipherText::<4, 256>::from_slice(&v).is_err());
        }

        #[test]
        fn cannot_deserialise_right_ciphertext_with_smaller_chunk_width() {
            let cipher = ore::Cipher::<4, 16>::new(key()).unwrap();

            let n = cipher.right_encrypt(&42u16.try_into().unwrap()).unwrap();
            let v = n.to_vec().unwrap();

            assert!(ore::CipherText::<4, 256>::from_slice(&v).is_err());
        }

        #[test]
        fn cannot_deserialise_right_ciphertext_with_larger_chunk_width() {
            let cipher = ore::Cipher::<4, 256>::new(key()).unwrap();

            let n = cipher.right_encrypt(&42u16.try_into().unwrap()).unwrap();
            let v = n.to_vec().unwrap();

            assert!(ore::CipherText::<4, 16>::from_slice(&v).is_err());
        }
    }
}
