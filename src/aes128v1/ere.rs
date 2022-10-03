use super::CipherSuite;
use crate::cipher::Cipher as C;
use crate::ciphertext::{CipherText as CT, LeftCipherText as LCT, RightCipherText as RCT};
use crate::cmp::EqualityCMP;

pub type Cipher<const N: usize, const W: u16> = C<CipherSuite<W, 2>, EqualityCMP, N, W, 2>;
pub type CipherText<'a, const N: usize, const W: u16> =
    CT<'a, CipherSuite<W, 2>, EqualityCMP, N, W, 2>;
pub type LeftCipherText<'a, const N: usize, const W: u16> =
    LCT<'a, CipherSuite<W, 2>, EqualityCMP, N, W, 2>;
pub type RightCipherText<'a, const N: usize, const W: u16> =
    RCT<'a, CipherSuite<W, 2>, EqualityCMP, N, W, 2>;

impl<const N: usize, const W: u16> PartialEq for CipherText<'_, N, W> {
    fn eq(&self, other: &CipherText<N, W>) -> bool {
        match self.left {
            None => match other.left {
                None => panic!("Neither ciphertext in comparison has a left component"),
                Some(_) => !other.eq(self),
            },
            Some(_) => EqualityCMP::invert(self.compare(other).expect("comparison failed")),
        }
    }
}

impl<const N: usize, const W: u16> Eq for CipherText<'_, N, W> {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PlainText;
    use rand::Rng;

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

        let n = cipher.full_encrypt(PlainText::<1, 4>::new([2u16])).unwrap();

        assert_eq!(0, n.compare(&n).unwrap());
    }

    #[test]
    fn tiny_equality() {
        let cipher = Cipher::<1, 4>::new(key()).unwrap();

        let n2_1 = cipher.full_encrypt(PlainText::<1, 4>::new([2u16])).unwrap();
        let n2_2 = cipher.full_encrypt(PlainText::<1, 4>::new([2u16])).unwrap();

        assert_eq!(0, n2_1.compare(&n2_2).unwrap());
        assert_eq!(0, n2_2.compare(&n2_1).unwrap());
    }

    #[test]
    fn tiny_inequality() {
        let cipher = Cipher::<1, 4>::new(key()).unwrap();

        let n1 = cipher.full_encrypt(PlainText::<1, 4>::new([1u16])).unwrap();
        let n2 = cipher.full_encrypt(PlainText::<1, 4>::new([2u16])).unwrap();

        assert_eq!(1, n1.compare(&n2).unwrap());
        assert_eq!(1, n2.compare(&n1).unwrap());
    }

    #[test]
    fn smol_self_equality() {
        let cipher = Cipher::<2, 16>::new(key()).unwrap();

        let n12 = cipher
            .full_encrypt(PlainText::<2, 16>::new([0u16, 12]))
            .unwrap();

        assert_eq!(0, n12.compare(&n12).unwrap());
    }

    #[test]
    fn smol_equality() {
        let cipher = Cipher::<2, 16>::new(key()).unwrap();

        let n12_1 = cipher
            .full_encrypt(PlainText::<2, 16>::new([0u16, 12]))
            .unwrap();
        let n12_2 = cipher
            .full_encrypt(PlainText::<2, 16>::new([0u16, 12]))
            .unwrap();

        assert_eq!(0, n12_1.compare(&n12_2).unwrap());
        assert_eq!(0, n12_2.compare(&n12_1).unwrap());
    }

    #[test]
    fn smol_inequality() {
        let cipher = Cipher::<2, 16>::new(key()).unwrap();

        let n1 = cipher
            .full_encrypt(PlainText::<2, 16>::new([0u16, 1]))
            .unwrap();
        let n2 = cipher
            .full_encrypt(PlainText::<2, 16>::new([0u16, 2]))
            .unwrap();

        assert_eq!(1, n1.compare(&n2).unwrap());
        assert_eq!(1, n2.compare(&n1).unwrap());
    }

    #[test]
    fn big_diff_energy() {
        let cipher = Cipher::<8, 256>::new(key()).unwrap();

        let n1 = cipher.full_encrypt(1u64.into()).unwrap();
        let n2 = cipher
            .full_encrypt(372_363_178_678_738_176u64.into())
            .unwrap();

        assert_eq!(1, n1.compare(&n2).unwrap());
        assert_eq!(1, n2.compare(&n1).unwrap());
    }

    quickcheck! {
        fn u64_compare(a: u64, b: u64) -> bool {
            let cipher = Cipher::<8, 256>::new(key()).unwrap();

            let ca = cipher.full_encrypt(a.into()).unwrap();
            let cb = cipher.full_encrypt(b.into()).unwrap();

            if a == b {
                ca.compare(&cb).unwrap() == 0
            } else {
                ca.compare(&cb).unwrap() == 1
            }
        }

        fn u32_compare(a: u32, b: u32) -> bool {
            let cipher = Cipher::<4, 256>::new(key()).unwrap();

            let ca = cipher.full_encrypt(a.into()).unwrap();
            let cb = cipher.full_encrypt(b.into()).unwrap();

            if a == b {
                ca.compare(&cb).unwrap() == 0
            } else {
                ca.compare(&cb).unwrap() == 1
            }
        }

        fn u64_eq(a: u64, b: u64) -> bool {
            let cipher = Cipher::<8, 256>::new(key()).unwrap();

            let ca = cipher.full_encrypt(a.into()).unwrap();
            let cb = cipher.full_encrypt(b.into()).unwrap();

            if a == b {
                ca == cb
            } else {
                ca != cb
            }
        }

        fn u32_eq(a: u32, b: u32) -> bool {
            let cipher = Cipher::<4, 256>::new(key()).unwrap();

            let ca = cipher.full_encrypt(a.into()).unwrap();
            let cb = cipher.full_encrypt(b.into()).unwrap();

            if a == b {
                ca == cb
            } else {
                ca != cb
            }
        }
    }
}
