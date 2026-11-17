//! Byte buffers that are safe to reinterpret as Win32/NT structures.
//!
//! Many Windows APIs fill a caller-supplied byte buffer with a header struct followed by
//! variable-length data. Reading those structs through a `Vec<u8>` is undefined behaviour in
//! principle, because a `Vec<u8>` is only guaranteed to be 1-byte aligned (the allocator
//! usually returns more, but nothing promises it). `AlignedBuf` stores its bytes in `u64`s so
//! the start of the buffer is always 8-byte aligned, which covers every structure PMonNT reads.

use std::mem::{align_of, size_of};

/// A zero-initialised byte buffer whose start is 8-byte aligned.
#[derive(Clone, Default)]
pub struct AlignedBuf {
    words: Vec<u64>,
    len: usize,
}

impl std::fmt::Debug for AlignedBuf {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AlignedBuf")
            .field("len", &self.len)
            .finish()
    }
}

impl AlignedBuf {
    /// Allocate `len` zeroed bytes.
    pub fn new(len: usize) -> Self {
        Self {
            words: vec![0; len.div_ceil(size_of::<u64>())],
            len,
        }
    }

    /// Length in bytes.
    pub const fn len(&self) -> usize {
        self.len
    }

    /// True if the buffer holds no bytes.
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Resize to `len` bytes, zero-filling any new space.
    pub fn resize(&mut self, len: usize) {
        self.words.resize(len.div_ceil(size_of::<u64>()), 0);
        self.len = len;
    }

    /// Length in bytes as the `u32` most Win32 size parameters take (saturating).
    pub fn len_u32(&self) -> u32 {
        u32::try_from(self.len).unwrap_or(u32::MAX)
    }

    /// Pointer to the first byte.
    pub fn as_ptr(&self) -> *const u8 {
        self.words.as_ptr().cast()
    }

    /// Mutable pointer to the first byte, for passing to an API that fills the buffer.
    pub fn as_mut_ptr(&mut self) -> *mut u8 {
        self.words.as_mut_ptr().cast()
    }

    /// The buffer contents as bytes.
    pub fn as_bytes(&self) -> &[u8] {
        // SAFETY: `words` owns at least `len` initialised bytes and u8 has alignment 1.
        unsafe { std::slice::from_raw_parts(self.as_ptr(), self.len) }
    }

    /// The buffer contents as mutable bytes.
    pub fn as_bytes_mut(&mut self) -> &mut [u8] {
        let len = self.len;
        // SAFETY: as above; the exclusive borrow of `self` makes the slice unique.
        unsafe { std::slice::from_raw_parts_mut(self.as_mut_ptr(), len) }
    }

    /// Pointer to a `T` starting `offset` bytes into the buffer.
    ///
    /// The pointer is correctly aligned whenever `offset` is a multiple of `align_of::<T>()`
    /// (true for every offset Windows hands back for these structures). The caller must still
    /// check that the bytes it reads lie within `len()`.
    ///
    /// # Panics
    /// If `offset > len()` or `T` needs more than 8-byte alignment.
    pub fn ptr_at<T>(&self, offset: usize) -> *const T {
        assert!(
            offset <= self.len,
            "offset {offset} past end of {} byte buffer",
            self.len
        );
        const { assert!(align_of::<T>() <= align_of::<u64>()) };
        debug_assert_eq!(offset % align_of::<T>(), 0, "misaligned offset {offset}");
        self.words.as_ptr().wrapping_byte_add(offset).cast()
    }

    /// Mutable pointer to a `T` starting `offset` bytes into the buffer (see [`Self::ptr_at`]).
    ///
    /// # Panics
    /// If `offset > len()` or `T` needs more than 8-byte alignment.
    pub fn mut_ptr_at<T>(&mut self, offset: usize) -> *mut T {
        assert!(
            offset <= self.len,
            "offset {offset} past end of {} byte buffer",
            self.len
        );
        const { assert!(align_of::<T>() <= align_of::<u64>()) };
        debug_assert_eq!(offset % align_of::<T>(), 0, "misaligned offset {offset}");
        self.words.as_mut_ptr().wrapping_byte_add(offset).cast()
    }

    /// Whether a `T` fits entirely inside the buffer at `offset`.
    pub const fn fits<T>(&self, offset: usize) -> bool {
        match offset.checked_add(size_of::<T>()) {
            Some(end) => end <= self.len,
            None => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn start_is_eight_byte_aligned_and_zeroed() {
        for len in [0, 1, 7, 8, 9, 4096, 4097] {
            let buf = AlignedBuf::new(len);
            assert_eq!(buf.len(), len);
            assert_eq!(buf.as_ptr() as usize % 8, 0);
            assert!(buf.as_bytes().iter().all(|&b| b == 0));
        }
    }

    #[test]
    fn resize_preserves_prefix_and_zero_fills() {
        let mut buf = AlignedBuf::new(3);
        buf.as_bytes_mut().copy_from_slice(&[1, 2, 3]);
        buf.resize(20);
        assert_eq!(&buf.as_bytes()[..3], &[1, 2, 3]);
        assert!(buf.as_bytes()[3..].iter().all(|&b| b == 0));
        buf.resize(2);
        assert_eq!(buf.as_bytes(), &[1, 2]);
    }

    #[test]
    fn ptr_at_reads_structs() {
        #[repr(C)]
        struct Pair {
            a: u32,
            b: u64,
        }
        let mut buf = AlignedBuf::new(64);
        buf.as_bytes_mut()[16..20].copy_from_slice(&7u32.to_ne_bytes());
        buf.as_bytes_mut()[24..32].copy_from_slice(&9u64.to_ne_bytes());
        assert!(buf.fits::<Pair>(16));
        assert!(!buf.fits::<Pair>(56));
        let p = buf.ptr_at::<Pair>(16);
        // SAFETY: offset 16 is 8-aligned and 16 + size_of::<Pair>() <= 64.
        let pair = unsafe { &*p };
        assert_eq!((pair.a, pair.b), (7, 9));
    }

    #[test]
    #[should_panic(expected = "past end")]
    fn ptr_at_rejects_out_of_range_offsets() {
        let buf = AlignedBuf::new(8);
        let _ = buf.ptr_at::<u8>(9);
    }
}
