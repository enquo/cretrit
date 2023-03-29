pub(crate) struct BitList {
    list: Vec<u8>,
    curbyte: usize,
    bitmask: u8,
}

impl BitList {
    pub fn new(capacity: usize) -> BitList {
        BitList {
            list: Vec::with_capacity(capacity / 8),
            curbyte: 0,
            bitmask: 1,
        }
    }

    pub fn from_slice(s: &[u8]) -> BitList {
        let mut v = vec![0u8; s.len()];
        v.clone_from_slice(s);

        BitList {
            list: v,
            curbyte: 0,
            bitmask: 1,
        }
    }

    pub fn push(&mut self, b: bool) {
        if self.bitmask == 1 {
            self.list.push(0);
        }

        if b {
            self.list[self.curbyte] |= self.bitmask;
        }

        self.next_bit();
    }

    pub fn shift(&mut self) -> Option<bool> {
        let r = self.list.get(self.curbyte).map(|b| *b & self.bitmask > 0);
        self.next_bit();

        r
    }

    pub fn fully_consumed(&self) -> bool {
        self.curbyte == self.list.len() || (self.curbyte == self.list.len() - 1 && self.bitmask > 1)
    }

    pub fn vec(&self) -> Vec<u8> {
        let mut v = vec![0u8; self.list.len()];
        v.clone_from_slice(&self.list);
        v
    }

    fn next_bit(&mut self) {
        if self.bitmask == 128 {
            self.curbyte += 1;
            self.bitmask = 1;
        } else {
            self.bitmask <<= 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn micro_push() {
        let mut bl = BitList::new(1);

        bl.push(true);
        bl.push(false);
        bl.push(true);
        bl.push(false);
        bl.push(true);

        assert_eq!(vec![0x15u8], bl.vec());
    }

    #[test]
    fn smol_push() {
        let mut bl = BitList::new(1);

        for _ in 0..4 {
            bl.push(false);
        }

        bl.push(true);

        for _ in 0..3 {
            bl.push(false);
        }

        bl.push(true);

        for _ in 0..12 {
            bl.push(false);
        }

        assert_eq!(vec![0x10u8, 0x01, 0x00], bl.vec());
    }

    #[test]
    fn micro_shift() {
        let mut bl = BitList::from_slice(&vec![0x15u8]);

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
        let mut bl = BitList::from_slice(&vec![0x10u8, 0x01, 0x00]);

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
