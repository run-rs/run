use core::ptr::NonNull;

#[derive(Debug)]
pub struct SocketBuffer {
  ptr: NonNull<u8>,
  read_at: usize,
  length: usize,
  cap: usize,
}

impl SocketBuffer {
  #[must_use]
  pub fn new(mut size: usize) -> SocketBuffer {
    if size < 64 {
      size = 64;
    }
    let layout = std::alloc::Layout::from_size_align(size, 64).unwrap();
    let ptr = unsafe { std::alloc::alloc_zeroed(layout) };
    SocketBuffer {
      ptr: unsafe { NonNull::new_unchecked(ptr) },
      read_at: 0,
      length: 0,
      cap: size,
    }
  }

  pub fn clear(&mut self) {
    self.read_at = 0;
    self.length = 0;
  }

  pub fn cap(&self) -> usize {
    self.cap
  }

  pub fn len(&self) -> usize {
    self.length
  }

  pub fn window_size(&self) -> usize {
    self.cap() - self.len()
  }

  pub fn contiguous_window_size(&self) -> usize {
    std::cmp::min(self.window_size(), self.cap - self.get_idx(self.length))
  }

  fn get_idx(&self, idx: usize) -> usize {
    (self.read_at + idx) % self.cap
  }

  #[allow(dead_code)]
  pub fn is_empty(&self) -> bool {
    self.len() == 0
  }

  #[allow(dead_code)]
  pub fn is_full(&self) -> bool {
    self.window_size() == 0
  }
}

impl SocketBuffer {
  fn enqueue_many(&mut self, buf: &[u8]) -> usize {
    let len = std::cmp::min(self.contiguous_window_size(), buf.len());
    unsafe {
      std::ptr::copy_nonoverlapping(
        buf.as_ptr(),
        self.ptr.as_ptr().add(self.get_idx(self.length)),
        len,
      );
    };
    self.length += len;
    return len;
  }

  fn dequeue_many(&mut self, buf: &mut [u8]) -> usize {
    let len = std::cmp::min(self.len(), buf.len());
    unsafe {
      std::ptr::copy_nonoverlapping(
        self.ptr.as_ptr().add(self.read_at % self.cap),
        buf.as_mut_ptr(),
        len,
      );
    };
    self.length -= len;
    self.read_at += len;
    return len;
  }

  pub fn enqueue_slice(&mut self, data: &[u8]) -> usize {
    let size1 = self.enqueue_many(data);
    let size2 = self.enqueue_many(&data[size1..]);
    size1 + size2
  }

  pub fn dequeue_slice(&mut self, data: &mut [u8]) -> usize {
    let size1 = self.dequeue_many(data);
    let size2 = self.dequeue_many(&mut data[size1..]);
    size1 + size2
  }
}

impl SocketBuffer {
  pub fn write_unallocated(&mut self, mut offset: usize, data: &[u8]) -> usize {
    offset = self.length + offset;
    let can_write = std::cmp::min(data.len(), self.window_size());
    let mut remianing_bytes = can_write;
    while remianing_bytes != 0 {
      let start_at = self.get_idx(can_write - remianing_bytes + offset);
      let size = std::cmp::min(self.cap - start_at, remianing_bytes);
      unsafe {
        std::ptr::copy_nonoverlapping(
          data.as_ptr().add(can_write - remianing_bytes),
          self.ptr.as_ptr().add(start_at),
          size,
        );
      }
      remianing_bytes -= size;
    }
    can_write
  }

  pub fn enqueue_unallocated(&mut self, count: usize) {
    assert!(count <= self.window_size());
    self.length += count;
  }

  pub fn read_allocated(
    &mut self,
    mut offset: usize,
    data: &mut [u8],
  ) -> usize {
    offset = self.length + offset;
    let can_read = std::cmp::min(data.len(), self.len());
    let mut remianing_bytes = can_read;
    while remianing_bytes != 0 {
      let start_at = self.get_idx(can_read - remianing_bytes + offset);
      let size = std::cmp::min(self.cap - start_at, remianing_bytes);
      unsafe {
        std::ptr::copy_nonoverlapping(
          self.ptr.as_ptr().add(start_at),
          data.as_mut_ptr().add(can_read - remianing_bytes),
          size,
        );
      }
      remianing_bytes -= size;
    }
    can_read
  }

  pub fn dequeue_allocated(&mut self, count: usize) {
    self.length -= count;
    self.read_at = self.get_idx(count);
  }
}

impl Drop for SocketBuffer {
  fn drop(&mut self) {
    let layout = std::alloc::Layout::from_size_align(self.cap, 64).unwrap();
    unsafe {
      std::alloc::dealloc(self.ptr.as_ptr(), layout);
    }
  }
}

#[cfg(test)]
mod test {
  use super::*;
  use mockalloc::Mockalloc;
  use std::alloc::System;

  #[global_allocator]
  static ALLOCATOR: Mockalloc<System> = Mockalloc(System);

  #[test]
  fn test_buffer_new() {
    let buffer = SocketBuffer::new(63);
    assert_eq!(buffer.cap, 64);
    assert_eq!(buffer.length, 0);
    let buffer = SocketBuffer::new(64);
    assert_eq!(buffer.cap, 64);
    assert_eq!(buffer.length, 0);
    let buffer = SocketBuffer::new(65);
    assert_eq!(buffer.cap, 65);
    assert_eq!(buffer.length, 0);
    let buffer = SocketBuffer::new(1000);
    assert_eq!(buffer.cap, 1000);
    assert_eq!(buffer.length, 0);
    let buffer = SocketBuffer::new(0);
    assert_eq!(buffer.cap, 64);
    assert_eq!(buffer.length, 0);
  }

  #[test]
  fn test_buffer_drop() {
    let alloc_info = mockalloc::record_allocs(|| {
      let _ = SocketBuffer::new(2);
    });
    assert_eq!(alloc_info.mem_allocated(), 64);
    assert_eq!(alloc_info.mem_freed(), 64);
    assert_eq!(alloc_info.mem_leaked(), 0);

    let alloc_info = mockalloc::record_allocs(|| {
      let _ = SocketBuffer::new(64);
    });
    assert_eq!(alloc_info.mem_allocated(), 64);
    assert_eq!(alloc_info.mem_freed(), 64);
    assert_eq!(alloc_info.mem_leaked(), 0);

    let alloc_info = mockalloc::record_allocs(|| {
      let _ = SocketBuffer::new(65);
    });
    assert_eq!(alloc_info.mem_allocated(), 65);
    assert_eq!(alloc_info.mem_freed(), 65);
    assert_eq!(alloc_info.mem_leaked(), 0);

    let alloc_info = mockalloc::record_allocs(|| {
      let _ = SocketBuffer::new(63);
    });
    assert_eq!(alloc_info.mem_allocated(), 64);
    assert_eq!(alloc_info.mem_freed(), 64);
    assert_eq!(alloc_info.mem_leaked(), 0);

    let alloc_info = mockalloc::record_allocs(|| {
      let _ = SocketBuffer::new(1000);
    });
    assert_eq!(alloc_info.mem_allocated(), 1000);
    assert_eq!(alloc_info.mem_freed(), 1000);
    assert_eq!(alloc_info.mem_leaked(), 0);
  }

  #[test]
  fn test_buffer_length_change() {
    let mut buffer = SocketBuffer::new(64);
    assert_eq!(buffer.contiguous_window_size(), 64);
    assert_eq!(buffer.window_size(), 64);
    assert_eq!(buffer.len(), 0);
    assert_eq!(buffer.cap(), 64);
    assert!(buffer.is_empty());
    assert!(!buffer.is_full());

    buffer.length = 1;
    assert_eq!(buffer.len(), 1);
    assert_eq!(buffer.cap(), 64);
    assert_eq!(buffer.contiguous_window_size(), 63);
    assert_eq!(buffer.window_size(), 63);
    assert!(!buffer.is_empty());
    assert!(!buffer.is_full());

    buffer.length = 64;
    assert_eq!(buffer.len(), 64);
    assert_eq!(buffer.cap(), 64);
    assert_eq!(buffer.contiguous_window_size(), 0);
    assert_eq!(buffer.window_size(), 0);
    assert!(!buffer.is_empty());
    assert!(buffer.is_full());

    buffer.length = 10;
    buffer.read_at = 54;
    assert_eq!(buffer.len(), 10);
    assert_eq!(buffer.cap(), 64);
    assert_eq!(buffer.contiguous_window_size(), 54);
    assert_eq!(buffer.window_size(), 54);
    assert!(!buffer.is_empty());
    assert!(!buffer.is_full());

    buffer.length = 0;
    buffer.read_at = 63;
    assert_eq!(buffer.len(), 0);
    assert_eq!(buffer.cap(), 64);
    assert_eq!(buffer.contiguous_window_size(), 1);
    assert_eq!(buffer.window_size(), 64);
    assert!(buffer.is_empty());
    assert!(!buffer.is_full());

    buffer.length = 0;
    buffer.read_at = 64;
    assert_eq!(buffer.len(), 0);
    assert_eq!(buffer.cap(), 64);
    assert_eq!(buffer.contiguous_window_size(), 64);
    assert_eq!(buffer.window_size(), 64);
    assert!(buffer.is_empty());
    assert!(!buffer.is_full());
  }

  #[test]
  fn test_buffer_clear() {
    let mut buffer = SocketBuffer::new(64);
    buffer.length = 10;
    buffer.read_at = 10;
    buffer.clear();
    assert_eq!(buffer.len(), 0);
    assert_eq!(buffer.read_at, 0);
    assert_eq!(buffer.window_size(), 64);
    assert_eq!(buffer.contiguous_window_size(), 64);
  }

  #[test]
  fn test_buffer_enqueue_dequeue_many() {
    let mut buffer = SocketBuffer::new(64);
    let mut data1 = vec![0; 64];
    let mut data2 = vec![0; 64];
    for i in 0..64 {
      data1[i] = i as u8;
    }
    assert_eq!(buffer.enqueue_many(&data1[..]), 64);
    assert_eq!(buffer.len(), 64);
    assert_eq!(buffer.window_size(), 0);
    assert_eq!(buffer.contiguous_window_size(), 0);
    assert!(buffer.is_full());
    assert_eq!(buffer.dequeue_many(&mut data2[..]), 64);
    assert_eq!(buffer.len(), 0);
    assert_eq!(buffer.window_size(), 64);
    assert_eq!(buffer.contiguous_window_size(), 64);
    assert_eq!(data1[..], data2[..]);
    assert!(buffer.is_empty());

    let mut data2 = vec![0; 64];
    buffer.length = 0;
    buffer.read_at = 20;
    assert_eq!(buffer.enqueue_many(&data1[..]), 44);
    assert_eq!(buffer.len(), 44);
    assert_eq!(buffer.window_size(), 20);
    assert_eq!(buffer.contiguous_window_size(), 20);
    assert!(!buffer.is_full());
    assert_eq!(buffer.dequeue_many(&mut data2[..]), 44);
    assert_eq!(buffer.len(), 0);
    assert_eq!(buffer.window_size(), 64);
    assert_eq!(buffer.contiguous_window_size(), 64);
    assert_eq!(data1[..44], data2[0..44]);
    assert!(buffer.is_empty());
  }

  #[test]
  fn test_buffer_enqueue_slice() {
    let mut buffer = SocketBuffer::new(64);
    let data = vec![0; 64];
    buffer.read_at = 10;
    buffer.length = 0;
    assert_eq!(buffer.enqueue_slice(&data[..]), 64);
    assert_eq!(buffer.len(), 64);
    assert_eq!(buffer.window_size(), 0);
    assert_eq!(buffer.contiguous_window_size(), 0);
    assert!(buffer.is_full());
  }

  #[test]
  fn test_buffer_dequeue_slice() {
    let mut buffer = SocketBuffer::new(64);
    let mut data = vec![0; 64];
    buffer.read_at = 10;
    buffer.length = 64;
    assert_eq!(buffer.dequeue_slice(&mut data[..]), 64);
    assert_eq!(buffer.len(), 0);
    assert_eq!(buffer.window_size(), 64);
    assert_eq!(buffer.contiguous_window_size(), 54);
    assert!(buffer.is_empty());
  }

  #[test]
  fn test_buffer_enqueue_dequeue_slice() {
    let mut buffer = SocketBuffer::new(64);
    let mut data = vec![0; 64];
    for i in 0u8..64 {
      data[i as usize] = i;
    }
    let mut read_data = vec![65; 64];
    let _ = buffer.enqueue_slice(&data[..]);
    let _ = buffer.dequeue_slice(&mut read_data[..]);
    assert_eq!(data[..], read_data[..]);
  }

  #[test]
  fn test_buffer_enqueue_unallocated() {
    let mut buffer = SocketBuffer::new(64);
    buffer.enqueue_unallocated(30);
    assert_eq!(buffer.len(), 30);
    buffer.clear();
    buffer.enqueue_unallocated(64);
    assert_eq!(buffer.len(), 64);
  }

  #[test]
  fn test_buffer_dequeue_allocated() {
    let mut buffer = SocketBuffer::new(64);
    buffer.length = 64;
    buffer.dequeue_allocated(20);
    assert_eq!(buffer.len(), 44);
    buffer.dequeue_allocated(44);
    assert_eq!(buffer.len(), 0);
  }

  #[test]
  fn test_buffer_write_unallocated() {
    let mut buffer = SocketBuffer::new(64);
    let mut data = vec![0; 64];
    for i in 0..64 {
      data[i] = i as u8;
    }
    buffer.write_unallocated(0, &data[..]);
    assert_eq!(buffer.len(), 0);
    buffer.enqueue_unallocated(64);
    let mut read = vec![65; 64];
    buffer.dequeue_slice(&mut read[..]);
    assert_eq!(data[..], read[..]);
  }

  #[test]
  fn test_buffer_read_allocated() {
    let mut buffer = SocketBuffer::new(64);
    let mut data = vec![0; 64];
    for i in 0..64 {
      data[i] = i as u8;
    }
    buffer.read_at = 10;
    buffer.length = 0;
    buffer.write_unallocated(0, &data[..]);
    assert_eq!(buffer.len(), 0);
    buffer.enqueue_unallocated(64);
    let mut read = vec![65; 64];
    buffer.read_allocated(0, &mut read[..]);
    assert_eq!(buffer.len(), 64);
    assert_eq!(read[..], data[..]);
    buffer.dequeue_allocated(64);
    assert_eq!(buffer.len(), 0);
  }
}
