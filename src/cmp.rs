use std::cmp::Ordering;

pub trait Comparator<const M: u8> {
    fn compare(a: u16, b: u16) -> u8;
}

#[derive(Debug)]
pub struct OrderingCMP {}

impl OrderingCMP {
    pub fn invert(i: u8) -> Ordering {
        assert!(i < 3);

        match i {
            0 => Ordering::Equal,
            1 => Ordering::Less,
            2 => Ordering::Greater,
            _ => panic!("Da fuq?"),
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

#[derive(Debug)]
pub struct EqualityCMP {}

impl EqualityCMP {
    pub fn invert(i: u8) -> bool {
        assert!(i < 2);

        i == 0
    }
}

impl Comparator<2> for EqualityCMP {
    fn compare(a: u16, b: u16) -> u8 {
        if a == b {
            0
        } else {
            1
        }
    }
}
