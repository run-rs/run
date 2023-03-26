use std::ptr::NonNull;

use arrayvec::ArrayVec;
use libnuma_sys::mbind;

use crate::{
  constant::HUGE_PAGE_SIZE,
  transport::{DeRegMrFunc, MemRegInfo, RegMrFunc},
  utils::SlowRand,
};

use libc::{
  c_void, shmat, shmctl, shmdt, shmget, IPC_CREAT, IPC_EXCL, IPC_RMID,
  MPOL_BIND, SHM_HUGETLB,
};

struct ShmRegion {
  shm_key: i32,
  buf: Option<NonNull<u8>>,
  size: usize,
  registered: bool,
  mem_reg_info: MemRegInfo,
}

impl ShmRegion {
  pub fn new(
    shm_key: i32,
    buf: Option<NonNull<u8>>,
    size: usize,
    registerd: bool,
    mem_reg_info: MemRegInfo,
  ) -> Self {
    assert!(size % HUGE_PAGE_SIZE == 0);
    Self {
      shm_key: shm_key,
      buf: buf,
      size: size,
      registered: registerd,
      mem_reg_info: mem_reg_info,
    }
  }
}
pub struct Buffer {
  pub(crate) buf: Option<NonNull<u8>>,
  pub(crate) class_size: usize,
  pub(crate) lkey: u32,
}
impl Buffer {
  pub(crate) fn split(self) -> (Self, Self) {
    (
      Buffer {
        buf: self.buf,
        class_size: self.class_size / 2,
        lkey: self.lkey,
      },
      Buffer {
        buf: self.buf.map(|ptr| {
          let ptr = unsafe { ptr.as_ptr().add(self.class_size / 2) };
          unsafe { NonNull::new_unchecked(ptr) }
        }),
        class_size: self.class_size / 2,
        lkey: self.lkey,
      },
    )
  }
}

pub struct HugeAlloctor {
  /// Shared Memory Regions by increasing alloc size
  shm_list: Vec<ShmRegion>,
  /// Per-class freelist
  freelist: ArrayVec<Vec<Buffer>, { HugeAlloctor::NUM_CLASSES }>,
  ///RNG to generate SHM keys
  slow_rand: SlowRand,
  numa_node: i32,
  reg_mr_func: RegMrFunc,
  dereg_mr_func: DeRegMrFunc,
  pre_allocation_size: usize,
  stats: Stats,
}

impl HugeAlloctor {
  pub fn new(
    initial_size: usize,
    numa_node: i32,
    reg_mr_func: RegMrFunc,
    dereg_mr_func: DeRegMrFunc,
  ) -> Self {
    Self {
      shm_list: Vec::new(),
      freelist: ArrayVec::new(),
      slow_rand: SlowRand::new(),
      numa_node: numa_node,
      reg_mr_func: reg_mr_func,
      dereg_mr_func: dereg_mr_func,
      pre_allocation_size: core::cmp::max(
        initial_size,
        HugeAlloctor::MAX_CLASS_SIZE,
      ),
      stats: Stats::new(),
    }
  }

  pub fn print_stats(&self) {
    eprintln!("eRPC HugeAlloc stats:");
    eprintln!(
      "Total reserved SHM={} bytes ({} MB)",
      self.stats.shm_reserved,
      self.stats.shm_reserved / (1024 * 1024)
    );
    eprintln!(
      "Total memory allocated to user={} bytes({}MB) ",
      self.stats.user_alloc_tot,
      self.stats.user_alloc_tot / (1024 * 1024)
    );
    eprintln!("{} SHM regions", self.shm_list.len());
    for (index, shm_region) in self.shm_list.iter().enumerate() {
      eprintln!(
        "Region {}, size {}MB",
        index,
        shm_region.size / (1024 * 1024)
      );
    }

    eprintln!("Size classes:");

    for i in 0..HugeAlloctor::NUM_CLASSES {
      let class_size = class_max_size(i);
      if class_size < 1024 {
        eprintln!("     {} B: {} Buffers", class_size, self.freelist[i].len());
      } else if class_size < 1024 * 1024 {
        eprintln!(
          "     {} KB: {} Buffers",
          class_size / 1024,
          self.freelist[i].len()
        );
      } else {
        eprintln!(
          "     {} MB: {} Buffers",
          class_size / (1024 * 1024),
          self.freelist[i].len()
        );
      }
    }
  }

  fn alloc_raw(
    &mut self,
    size: usize,
    do_register: bool,
  ) -> Result<Buffer, HugeAlloctError> {
    if size > usize::MAX - HUGE_PAGE_SIZE {
      return Err(HugeAlloctError::AllocSizeTooLarge);
    }
    let size = (size + HUGE_PAGE_SIZE - 1) & !(HUGE_PAGE_SIZE - 1);
    let mut shm_key = 0;
    let mut shm_id = 0;

    loop {
      shm_key = self.slow_rand.next_u64() as i32;
      shm_key = shm_key.abs();
      shm_id = unsafe {
        shmget(shm_key, size, IPC_CREAT | IPC_EXCL | 0666 | SHM_HUGETLB)
      };

      if shm_id == -1 {
        let errno = unsafe { *libc::__errno_location() };
        match errno {
          libc::EEXIST => continue,
          libc::EACCES => {
            log::error!(
              "HugeAlloc: SHM allocation error\
                            Insufficient permissions."
            );
            return Err(HugeAlloctError::NoPermission);
          }
          libc::EINVAL => {
            log::error!(
              "HugeAlloc:SHM allocation error: SHMMAX/SHMMIN\
                            mismatch. size={}({}MB)",
              size,
              size / (1024 * 1024)
            );
            return Err(HugeAlloctError::InvalidReqSize);
          }
          libc::ENOMEM => {
            log::warn!(
              "HugeAlloc:Insufficient hugepages. Can't reserve {}MB",
              size / (1024 * 1024)
            );
            /* return Ok(Buffer{buf:None,class_size:0,lkey:0}); */
            return Err(HugeAlloctError::InsufficientHugePages);
          }
          _ => {
            log::error!("HugeAlloc:Unexpected SHM malloc error {}", errno);
            return Err(HugeAlloctError::UnKnownError);
          }
        }
      } else {
        break;
      }
    }

    let shm_buf = unsafe { shmat(shm_id, std::ptr::null(), 0) };
    if shm_buf.is_null() {
      log::error!("HugeAlloc:shmat() failed. Key={}", shm_key);
      return Err(HugeAlloctError::FailAttachMemory);
    }
    // Mark the SHM region for deletion when this process exits
    unsafe {
      shmctl(shm_id, IPC_RMID, std::ptr::null_mut());
    };
    let nodemask = 1u64 << self.numa_node;
    let ret = unsafe {
      mbind(
        shm_buf,
        size as u64,
        MPOL_BIND,
        &nodemask as *const u64,
        32,
        0,
      )
    };
    if ret != 0 {
      log::error!("HugeAlloc:mbind() failed.Key= {}", shm_key);
      return Err(HugeAlloctError::FailBindMemoryToNuma);
    }
    let mut reg_info = MemRegInfo::new();
    if do_register {
      reg_info = (self.reg_mr_func)(
        Some(unsafe { NonNull::new_unchecked(shm_buf) }),
        size,
      );
    }
    let reg_info_lkey = reg_info.lkey;
    self.shm_list.push(ShmRegion::new(
      shm_key,
      Some(unsafe { NonNull::new_unchecked(shm_buf as *mut u8) }),
      size,
      do_register,
      reg_info,
    ));
    self.stats.shm_reserved += size;
    return Ok(Buffer {
      buf: Some(unsafe { NonNull::new_unchecked(shm_buf as *mut u8) }),
      class_size: usize::MAX,
      lkey: {
        if do_register {
          reg_info_lkey
        } else {
          u32::MAX
        }
      },
    });
  }

  pub fn alloc(&mut self, size: usize) -> Buffer {
    assert!(size <= HugeAlloctor::MAX_CLASS_SIZE);
    let size_class = get_class(size);
    assert!(size_class < HugeAlloctor::NUM_CLASSES);
    if !self.freelist[size_class].is_empty() {
      return self.alloc_from_class(size_class);
    } else {
      let mut next_class = size_class + 1;
      while next_class < HugeAlloctor::NUM_CLASSES {
        if !self.freelist[next_class].is_empty() {
          break;
        }
        next_class += 1;
      }
      if next_class == HugeAlloctor::NUM_CLASSES {
        /*
            There's no larger size class with free pages, we need to allocate
            more hugepages. This adds some Buffers to the largest class.
        */
        self.pre_allocation_size *= 2;
        let success = self.reserve_hugepages();
        if !success {
          self.pre_allocation_size /= 2;
          return Buffer {
            buf: None,
            class_size: 0,
            lkey: 0,
          };
        } else {
          next_class = HugeAlloctor::NUM_CLASSES - 1;
        }
      }

      assert!(next_class < HugeAlloctor::NUM_CLASSES);
      while next_class != size_class {
        self.split(next_class);
        next_class -= 1;
      }

      assert!(!self.freelist[size_class].is_empty());
      return self.alloc_from_class(size_class);
    }

    unreachable!();
  }

  #[inline]
  fn alloc_from_class(&mut self, size_class: usize) -> Buffer {
    assert!(size_class < HugeAlloctor::NUM_CLASSES);
    let buffer = self.freelist[size_class].pop().unwrap();
    assert!(buffer.class_size == class_max_size(size_class));
    self.stats.user_alloc_tot += buffer.class_size;
    buffer
  }
  #[inline]
  fn split(&mut self, size_class: usize) {
    assert!(size_class >= 1);
    assert!(!self.freelist[size_class].is_empty());
    assert!(!self.freelist[size_class - 1].is_empty());

    let buffer = self.freelist[size_class].pop().unwrap();
    assert!(buffer.class_size == class_max_size(size_class));
    let (buffer_0, buffer_1) = buffer.split();
    self.freelist[size_class].push(buffer_0);
    self.freelist[size_class].push(buffer_1);
  }

  fn reserve_hugepages(&mut self) -> bool {
    assert!(self.pre_allocation_size >= HugeAlloctor::MAX_CLASS_SIZE);
    if let Ok(buffer) = self.alloc_raw(self.pre_allocation_size, true) {
      let num_buffers = self.pre_allocation_size / HugeAlloctor::MAX_CLASS_SIZE;
      assert!(num_buffers >= 1);
      let buf_start = buffer.buf.unwrap();
      for i in 0..num_buffers {
        let buf =
          unsafe { buf_start.as_ptr().add(i * HugeAlloctor::MAX_CLASS_SIZE) };
        self.freelist[HugeAlloctor::NUM_CLASSES - 1].push(Buffer {
          buf: Some(unsafe { NonNull::new_unchecked(buf) }),
          class_size: HugeAlloctor::MAX_CLASS_SIZE,
          lkey: buffer.lkey,
        });
      }
      true
    } else {
      false
    }
  }
}

impl Drop for HugeAlloctor {
  fn drop(&mut self) {
    // Deregister and detach the created SHM regions
    for shm_region in self.shm_list.iter_mut() {
      if shm_region.registered {
        (self.dereg_mr_func)(&mut shm_region.mem_reg_info);
      }
      if shm_region.buf.is_none() {
        log::error!(
          "The buffer start address of Shared Memory Region is Null,\
                SHM buf key:{}",
          shm_region.shm_key
        );
        std::process::exit(-1);
      }
      #[cfg(target_os = "linux")]
      {
        let ret =
          unsafe { shmdt(shm_region.buf.unwrap().as_ptr() as *const c_void) };

        if ret != 0 {
          log::error!(
            "HugeAlloc: Error freeing SHM buf for key {}",
            shm_region.shm_key
          );
          std::process::exit(-1);
        }
      }
    }
  }
}

enum HugeAlloctError {
  AllocSizeTooLarge,
  NoPermission,
  InvalidReqSize,
  UnKnownError,
  FailAttachMemory,
  FailBindMemoryToNuma,
  InsufficientHugePages,
}
struct Stats {
  /// Total hugepage memory reserved by allocator
  shm_reserved: usize,
  /// Total memory allocated to user
  user_alloc_tot: usize,
}
impl Stats {
  pub fn new() -> Self {
    Self {
      shm_reserved: 0,
      user_alloc_tot: 0,
    }
  }
}

impl HugeAlloctor {
  pub const ALLOC_FAIL_HELP_STR: &'static str =
    "This could be due to insufficient huge pages or SHM limits.";
  pub const MIN_CLASS_SIZE: usize = 64;
  pub const MIN_CLASS_BIT_SHIFT: usize = 6;
  pub const MAX_CLASS_SIZE: usize = 8 * 1024 * 1024;
  /*
      64B(2^6),...,8M (2^23)
  */
  pub const NUM_CLASSES: usize = 18;
}

#[inline]
fn class_max_size(class_i: usize) -> usize {
  HugeAlloctor::MAX_CLASS_SIZE * (1 << class_i)
}
#[inline]
fn get_class(size: usize) -> usize {
  assert!(size >= 1 && size <= HugeAlloctor::MAX_CLASS_SIZE);
  return msb_index(((size - 1) >> HugeAlloctor::MIN_CLASS_BIT_SHIFT) as i32);
}
#[inline]
fn msb_index(size: i32) -> usize {
  assert!(size < i32::MAX / 2);
  let mut index = 0;
  unsafe {
    std::arch::asm!(
        "bsr {y},{x}",
        x=in(reg) size<<1,
        y=out(reg) index
    );
  }
  return index as usize;
}

#[cfg(test)]
mod test {
  use super::*;
  fn get_class_slow(size: usize) -> usize {
    let mut size_class = 0;
    let mut class_lim = HugeAlloctor::MIN_CLASS_SIZE;
    while size > class_lim {
      size_class += 1;
      class_lim *= 2;
    }

    return size_class;
  }
  #[test]
  fn get_class_test() {
    for size in 1..=HugeAlloctor::MAX_CLASS_SIZE {
      assert_eq!(get_class_slow(size), get_class(size));
    }
  }
}
