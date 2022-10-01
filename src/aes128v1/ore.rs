use std::cmp::Ordering;

use super::CipherSuite;
use crate::cipher::Cipher as C;
use crate::ciphertext::{CipherText as CT, LeftCipherText as LCT, RightCipherText as RCT};
use crate::cmp::OrderingCMP;

pub type Cipher<const N: usize, const W: u16> = C<CipherSuite<W, 3>, OrderingCMP, N, W, 3>;
pub type CipherText<'a, const N: usize, const W: u16> =
    CT<'a, CipherSuite<W, 3>, OrderingCMP, N, W, 3>;
pub type LeftCipherText<'a, const N: usize, const W: u16> =
    LCT<'a, CipherSuite<W, 3>, OrderingCMP, N, W, 3>;
pub type RightCipherText<'a, const N: usize, const W: u16> =
    RCT<'a, CipherSuite<W, 3>, OrderingCMP, N, W, 3>;

impl<const N: usize, const W: u16> Ord for CipherText<'_, N, W> {
    fn cmp(&self, other: &CipherText<N, W>) -> Ordering {
        match self.left {
            None => match other.left {
                None => panic!("Neither ciphertext in comparison has a left component"),
                Some(_) => match other.cmp(self) {
                    Ordering::Equal => Ordering::Equal,
                    Ordering::Less => Ordering::Greater,
                    Ordering::Greater => Ordering::Less,
                },
            },
            Some(_) => OrderingCMP::invert(self.compare(other).expect("comparison failed")),
        }
    }
}

impl<const N: usize, const W: u16> PartialOrd for CipherText<'_, N, W> {
    fn partial_cmp(&self, other: &CipherText<N, W>) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<const N: usize, const W: u16> PartialEq for CipherText<'_, N, W> {
    fn eq(&self, other: &CipherText<N, W>) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl<const N: usize, const W: u16> Eq for CipherText<'_, N, W> {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PlainText;
    use rand::Rng;
    use std::cmp::Ordering;

    fn key() -> [u8; 16] {
        let mut k: [u8; 16] = Default::default();

        // Yes, using a potentially-weak RNG would normally be terribad, but
        // for testing purposes, it's not going to break anything
        let mut rng = rand::thread_rng();

        rng.try_fill(&mut k).unwrap();

        k
    }

    #[test]
    fn tiny_self_equality() {
        let cipher = Cipher::<1, 4>::new(key()).unwrap();

        let n = cipher.encrypt(PlainText::<1, 4>::new([2u16])).unwrap();

        assert_eq!(0, n.compare(&n).unwrap());
    }

    #[test]
    fn tiny_equality() {
        let cipher = Cipher::<1, 4>::new(key()).unwrap();

        let n2_1 = cipher.encrypt(PlainText::<1, 4>::new([2u16])).unwrap();
        let n2_2 = cipher.encrypt(PlainText::<1, 4>::new([2u16])).unwrap();

        assert_eq!(0, n2_1.compare(&n2_2).unwrap());
        assert_eq!(0, n2_2.compare(&n2_1).unwrap());
    }

    #[test]
    fn tiny_inequality() {
        let cipher = Cipher::<1, 4>::new(key()).unwrap();

        let n1 = cipher.encrypt(PlainText::<1, 4>::new([1u16])).unwrap();
        let n2 = cipher.encrypt(PlainText::<1, 4>::new([2u16])).unwrap();

        assert_eq!(1, n1.compare(&n2).unwrap());
        assert_eq!(2, n2.compare(&n1).unwrap());
    }

    #[test]
    fn smol_self_equality() {
        let cipher = Cipher::<2, 16>::new(key()).unwrap();

        let n12 = cipher.encrypt(PlainText::<2, 16>::new([0u16, 12])).unwrap();

        assert_eq!(0, n12.compare(&n12).unwrap());
    }

    #[test]
    fn smol_equality() {
        let cipher = Cipher::<2, 16>::new(key()).unwrap();

        let n12_1 = cipher.encrypt(PlainText::<2, 16>::new([0u16, 12])).unwrap();
        let n12_2 = cipher.encrypt(PlainText::<2, 16>::new([0u16, 12])).unwrap();

        assert_eq!(0, n12_1.compare(&n12_2).unwrap());
        assert_eq!(0, n12_2.compare(&n12_1).unwrap());
    }

    #[test]
    fn smol_inequality() {
        let cipher = Cipher::<2, 16>::new(key()).unwrap();

        let n1 = cipher.encrypt(PlainText::<2, 16>::new([0u16, 1])).unwrap();
        let n2 = cipher.encrypt(PlainText::<2, 16>::new([0u16, 2])).unwrap();

        assert_eq!(1, n1.compare(&n2).unwrap());
        assert_eq!(2, n2.compare(&n1).unwrap());
    }

    #[test]
    fn big_diff_energy() {
        let cipher = Cipher::<8, 256>::new(key()).unwrap();

        let n1 = cipher.encrypt(1u64.into()).unwrap();
        let n2 = cipher.encrypt(372_363_178_678_738_176u64.into()).unwrap();

        assert_eq!(1, n1.compare(&n2).unwrap());
        assert_eq!(2, n2.compare(&n1).unwrap());
    }

    quickcheck! {
        fn u64_compare(a: u64, b: u64) -> bool {
            let cipher = Cipher::<8, 256>::new(key()).unwrap();

            let ca = cipher.encrypt(a.into()).unwrap();
            let cb = cipher.encrypt(b.into()).unwrap();

            match a.cmp(&b) {
                Ordering::Equal   => ca.compare(&cb).unwrap() == 0,
                Ordering::Less    => ca.compare(&cb).unwrap() == 1,
                Ordering::Greater => ca.compare(&cb).unwrap() == 2,
            }
        }

        fn u64_cmp(a: u64, b: u64) -> bool {
            let cipher = Cipher::<8, 256>::new(key()).unwrap();

            let ca = cipher.encrypt(a.into()).unwrap();
            let cb = cipher.encrypt(b.into()).unwrap();

            match a.cmp(&b) {
                Ordering::Equal   => ca == cb,
                Ordering::Less    => ca < cb,
                Ordering::Greater => ca > cb,
            }
        }

        fn u32_compare(a: u32, b: u32) -> bool {
            let cipher = Cipher::<4, 256>::new(key()).unwrap();

            let ca = cipher.encrypt(a.into()).unwrap();
            let cb = cipher.encrypt(b.into()).unwrap();

            match a.cmp(&b) {
                Ordering::Equal   => ca.compare(&cb).unwrap() == 0,
                Ordering::Less    => ca.compare(&cb).unwrap() == 1,
                Ordering::Greater => ca.compare(&cb).unwrap() == 2,
            }
        }

        fn u32_cmp(a: u32, b: u32) -> bool {
            let cipher = Cipher::<4, 256>::new(key()).unwrap();

            let ca = cipher.encrypt(a.into()).unwrap();
            let cb = cipher.encrypt(b.into()).unwrap();

            match a.cmp(&b) {
                Ordering::Equal   => ca == cb,
                Ordering::Less    => ca < cb,
                Ordering::Greater => ca > cb,
            }
        }
    }
}
