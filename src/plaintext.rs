pub struct PlainText<const N: usize, const W: u16>([u16; N]);

impl<const N: usize, const W: u16> PlainText<N, W> {
    pub fn new(a: [u16; N]) -> PlainText<N, W> {
        PlainText(a)
    }

    pub fn block(&self, n: usize) -> u16 {
        assert!(n < N, "{n} < {N} violated");

        self.0[n]
    }
}

macro_rules! from_uint_to_plaintext {
    ($ty:ident) => {
        impl<const N: usize, const W: u16> From<$ty> for PlainText<N, W> {
            fn from(value: $ty) -> PlainText<N, W> {
                let mut u = value as u128;
                let mut p = [0u16; N];

                for i in 0..N {
                    p[N - i as usize - 1] = (u as u128 % W as u128) as u16;
                    u /= W as u128;
                }

                assert!(
                    u == 0,
                    "Could not represent {value}{} in PlainText<{N}, {W}>",
                    stringify!($ty)
                );

                PlainText::<N, W>::new(p)
            }
        }
    };
}

from_uint_to_plaintext!(u128);
from_uint_to_plaintext!(u64);
from_uint_to_plaintext!(u32);
from_uint_to_plaintext!(u16);
from_uint_to_plaintext!(u8);

impl<const N: usize, const W: u16> From<bool> for PlainText<N, W> {
    fn from(value: bool) -> PlainText<N, W> {
        PlainText::<N, W>::from(u8::from(value))
    }
}

#[cfg(test)]
mod tests {
    pub use super::*;

    mod pt_4_256 {
        use super::*;

        #[test]
        fn zero() {
            assert_eq!([0u16; 4], PlainText::<4, 256>::from(0u32).0);
        }

        #[test]
        fn tiny() {
            assert_eq!([0u16, 0, 0, 42], PlainText::<4, 256>::from(42u32).0);
        }

        #[test]
        fn smol() {
            assert_eq!([0u16, 0, 91, 42], PlainText::<4, 256>::from(23_338u32).0);
        }

        #[test]
        fn yuuuge() {
            assert_eq!([4u16, 3, 2, 1], PlainText::<4, 256>::from(67_305_985u32).0);
        }
    }

    mod pt_8_256 {
        use super::*;

        #[test]
        fn zero() {
            assert_eq!([0u16; 8], PlainText::<8, 256>::from(0u64).0);
        }

        #[test]
        fn one() {
            assert_eq!(
                [0u16, 0, 0, 0, 0, 0, 0, 1],
                PlainText::<8, 256>::from(1u64).0
            );
        }

        #[test]
        fn tiny() {
            assert_eq!(
                [0u16, 0, 0, 0, 0, 0, 0, 42],
                PlainText::<8, 256>::from(42u64).0
            );
        }

        #[test]
        fn smol() {
            assert_eq!(
                [0u16, 0, 0, 0, 0, 0, 91, 42],
                PlainText::<8, 256>::from(23_338u64).0
            );
        }

        #[test]
        fn yuuuge() {
            assert_eq!(
                [8u16, 7, 6, 5, 4, 3, 2, 1],
                PlainText::<8, 256>::from(578_437_695_752_307_201u64).0
            );
        }
    }

    mod pt_1_256 {
        use super::*;

        #[test]
        fn zero() {
            assert_eq!([0u16], PlainText::<1, 256>::from(0u8).0);
        }

        #[test]
        fn tiny() {
            assert_eq!([42u16], PlainText::<1, 256>::from(42u8).0);
        }
    }

    mod pt_1_2_bool {
        use super::*;

        #[test]
        fn from_true() {
            assert_eq!([1u16; 1], PlainText::<1, 2>::from(true).0);
        }

        #[test]
        fn from_false() {
            assert_eq!([0u16], PlainText::<1, 2>::from(false).0);
        }
    }
}
