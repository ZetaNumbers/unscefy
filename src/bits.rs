use crate::take_from_bytes::TakenFromBytes;

pub struct Bits<T: Iterator<Item = u32>> {
    consumed_bits: u32,
    current_word: u32,
    inner: T,
    pub padding: bool,
}

impl<I: Iterator<Item = u32>> Bits<I> {
    pub fn new(iter: I, padding: bool) -> Self {
        Bits {
            consumed_bits: 32,
            current_word: 0,
            inner: iter,
            padding,
        }
    }

    pub fn take(&mut self, bits: u32) -> Option<u32> {
        assert_ne!(bits, 0);
        assert!(bits <= u32::BITS, "bits = {bits}");

        if self.consumed_bits + bits > u32::BITS {
            if self.consumed_bits != u32::BITS && !self.padding {
                panic!("Bit padding is forbidden");
            }
            self.current_word = self.inner.next()?;
            self.consumed_bits = 0;
        }

        let position = self.consumed_bits;
        self.consumed_bits += bits;
        Some(
            self.current_word.checked_shr(position).unwrap_or(0)
                & u32::MAX.checked_shr(u32::BITS - bits).unwrap_or(0),
        )
    }

    pub fn take_array<const N: usize>(&mut self, bits: u32) -> Option<[u32; N]> {
        let mut out = [0; N];
        for dst in &mut out {
            *dst = self.take(bits)?;
        }
        Some(out)
    }

    pub fn holding_bits(&self) -> u32 {
        u32::BITS - self.consumed_bits
    }
}

impl<'a, 'b> Bits<TakenFromBytes<'a, 'b, u32>> {
    pub fn take_from_bytes(bytes: &'a mut &'b [u8], padding: bool) -> Self {
        Bits::new(TakenFromBytes::new(bytes), padding)
    }
}

#[cfg(test)]
mod tests {
    use super::Bits;

    #[test]
    fn lsb_4bit() {
        let words = [0x76543210];
        let mut bits = Bits::new(words.into_iter(), false);
        for i in 0..8 {
            assert_eq!(bits.take(4), Some(i));
        }
        assert_eq!(bits.take(1), None);
    }
}
