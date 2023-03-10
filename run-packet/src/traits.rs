pub use bytes::Buf;

pub trait PktBuf: Buf {
    fn move_back(&mut self, cnt: usize);
    fn trim_off(&mut self, cnt: usize);
}

impl<T: PktBuf + ?Sized> PktBuf for &mut T {
    #[inline]
    fn move_back(&mut self, cnt: usize) {
        (**self).move_back(cnt)
    }

    #[inline]
    fn trim_off(&mut self, cnt: usize) {
        (**self).trim_off(cnt);
    }
}

pub trait PktMut: PktBuf {
    fn chunk_headroom(&self) -> usize;
    fn chunk_mut(&mut self) -> &mut [u8];
}

impl<T: PktMut + ?Sized> PktMut for &mut T {
    #[inline]
    fn chunk_mut(&mut self) -> &mut [u8] {
        (**self).chunk_mut()
    }

    #[inline]
    fn chunk_headroom(&self) -> usize {
        (**self).chunk_headroom()
    }
}
