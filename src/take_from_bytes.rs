use std::{iter, marker::PhantomData};

pub fn take_from_bytes<T: TakeFromBytes>(bytes: &mut &[u8]) -> Option<T> {
    T::take_from_bytes(bytes)
}

pub fn whole_take_from_bytes<T: TakeFromBytes>(bytes: &mut &[u8]) -> Option<T> {
    if bytes.is_empty() {
        return None;
    }
    Some(T::take_from_bytes(bytes).unwrap())
}

#[allow(clippy::needless_lifetimes)]
pub fn whole_from_bytes_all<'a, T>(mut bytes: &'a [u8]) -> impl Iterator<Item = T> + 'a
where
    T: TakeFromBytes,
{
    iter::from_fn(move || whole_take_from_bytes(&mut bytes))
}

pub trait TakeFromBytes: Sized {
    fn take_from_bytes(bytes: &mut &[u8]) -> Option<Self>;
}

impl TakeFromBytes for u32 {
    fn take_from_bytes(bytes: &mut &[u8]) -> Option<Self> {
        Some(u32::from_le_bytes(*take_bytes(bytes)?))
    }
}

impl TakeFromBytes for u16 {
    fn take_from_bytes(bytes: &mut &[u8]) -> Option<Self> {
        Some(u16::from_le_bytes(*take_bytes(bytes)?))
    }
}

impl TakeFromBytes for u8 {
    fn take_from_bytes(bytes: &mut &[u8]) -> Option<Self> {
        Some(u8::from_le_bytes(*take_bytes(bytes)?))
    }
}

impl<const N: usize> TakeFromBytes for [u8; N] {
    fn take_from_bytes(bytes: &mut &[u8]) -> Option<Self> {
        take_bytes(bytes).copied()
    }
}

fn take_bytes<'a, const N: usize>(bytes: &mut &'a [u8]) -> Option<&'a [u8; N]> {
    if bytes.len() < N {
        assert_eq!(bytes.len(), 0);
        return None;
    }

    let out;
    (out, *bytes) = bytes.split_array_ref();
    Some(out)
}

pub struct TakenFromBytes<'a, 'b, T> {
    bytes: &'a mut &'b [u8],
    _marker: PhantomData<&'b T>,
}

impl<'a, 'b, T> TakenFromBytes<'a, 'b, T> {
    pub fn new(bytes: &'a mut &'b [u8]) -> Self {
        TakenFromBytes {
            bytes,
            _marker: PhantomData,
        }
    }
}

impl<T> Iterator for TakenFromBytes<'_, '_, T>
where
    T: TakeFromBytes,
{
    type Item = T;

    fn next(&mut self) -> Option<Self::Item> {
        take_from_bytes(self.bytes)
    }
}
