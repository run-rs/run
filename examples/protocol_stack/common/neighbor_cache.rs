use std::{collections::HashMap, time::Duration};

use run_packet::{ether::MacAddr, ipv4::Ipv4Addr};
use run_time::Instant;
use log;

#[derive(Debug, Clone, Copy)]
pub struct Neighbor {
  hardware_addr: MacAddr,
  expires_at: Instant,
}

#[derive(Debug,PartialEq, Eq)]
pub(crate) enum Answer {
  Found(MacAddr),
  NotFound,
  RateLimited,  
}

impl Answer {
  pub(crate) fn found(&self) -> bool {
    match self {
        Answer::Found(_) => true,
        _ => false,
    }
  }
}

#[derive(Debug)]
pub struct Cache {
  storage: HashMap<Ipv4Addr,Neighbor>,
  silent_until: Instant,
  gc_threshold: usize,
}

impl Cache {
  pub(crate) const SILENT_TIME: Duration = Duration::from_millis(1_000);
  pub(crate) const ENTRY_LIFETIME: Duration = Duration::from_millis(60_000);
  pub(crate) const GC_THRESHOLD: usize = 1024;

  pub fn new() -> Cache
  {
    Cache {
        storage:HashMap::new(),
        gc_threshold: Self::GC_THRESHOLD,
        silent_until: Instant::from_millis(0),
      }
  } 

  pub fn fill(
    &mut self,
    protocol_addr: Ipv4Addr,
    hardware_addr: MacAddr,
    timestamp: Instant
  ) {
    let current_storage_size = self.storage.len();
    let neighbor = Neighbor{
      expires_at:timestamp + Self::ENTRY_LIFETIME,
      hardware_addr,
    };
    match self.storage.insert(protocol_addr, neighbor) {
      Some(old_neighbor) => {
        if old_neighbor.hardware_addr != hardware_addr {
          log::log!(log::Level::Trace,
                "replaced {} => {} (was {})",
                protocol_addr,
                hardware_addr,
                old_neighbor.hardware_addr);
        }
      },
      None => {
        log::log!(log::Level::Trace,
          "filled {} => {} (was empty)",protocol_addr,hardware_addr);
      }
    }
  }

  pub(crate) fn lookup(
    &self,
    protocol_addr: Ipv4Addr,
    timestamp:Instant
  ) -> Answer {
    if let Some(&Neighbor {
      expires_at,
      hardware_addr,
    }) = self.storage.get(&protocol_addr)
    {
      if timestamp < expires_at {
        return Answer::Found(hardware_addr);
      }
    }
    if timestamp < self.silent_until {
      Answer::RateLimited
    } else {
      Answer::NotFound
    }
  }

  pub(crate) fn limit_rate(&mut self,timestamp: Instant) {
    self.silent_until = timestamp + Self::SILENT_TIME
  }

  pub(crate) fn flush(&mut self) {
    self.storage.clear()
  }
}


#[cfg(test)]
mod test {
  use super::*;


  const HADDR_A: MacAddr = MacAddr([0, 0, 0, 0, 0, 1]);
  const HADDR_B: MacAddr = MacAddr([0, 0, 0, 0, 0, 2]);
  const MOCK_IP_A :Ipv4Addr = Ipv4Addr::new(0, 0, 0, 1);
  const MOCK_IP_B :Ipv4Addr = Ipv4Addr::new(0, 0, 0, 2);
  
  #[test]
  fn test_fill() {
    let mut cache = Cache::new();
    let now = Instant::now();
    assert_eq!(cache.lookup(MOCK_IP_A, now).found(),false);
    assert_eq!(cache.lookup(MOCK_IP_B, now).found(),false);

    cache.fill(MOCK_IP_A, HADDR_A, now);
    cache.fill(MOCK_IP_B, HADDR_B, now);

    assert_eq!(
      cache.lookup(MOCK_IP_A, now),
      Answer::Found(HADDR_A)
    );

    assert_eq!(
      cache.lookup(MOCK_IP_B, now),
      Answer::Found(HADDR_B)
    )
  }

  #[test]
  fn test_expire() {
    let mut cache = Cache::new();
    cache.fill(MOCK_IP_A,HADDR_A,  Instant::from_millis(0));
    assert!(cache.lookup(MOCK_IP_A, Instant::from_millis(0)).found());
    assert!(cache.lookup(MOCK_IP_A, Instant::from_millis(0) + Cache::ENTRY_LIFETIME - Duration::from_millis(1)).found());
    assert!(!cache.lookup(MOCK_IP_A, Instant::from_millis(0) + Cache::ENTRY_LIFETIME).found());
    assert!(!cache.lookup(MOCK_IP_A, Instant::from_millis(1) + Cache::ENTRY_LIFETIME).found());
  }

  #[test]
  fn test_replace() {
    let mut cache = Cache::new();
    cache.fill(MOCK_IP_A, HADDR_A, Instant::from_micros(0));
    assert_eq!(cache.lookup(MOCK_IP_A, Instant::from_millis(0)),
          Answer::Found(HADDR_A));
    cache.fill(MOCK_IP_A, HADDR_B, Instant::from_micros(0));
    assert_eq!(cache.lookup(MOCK_IP_A, Instant::from_millis(0)),
          Answer::Found(HADDR_B));
  }

  #[test]
  fn test_hush() {
    let mut cache = Cache::new();
    assert_eq!(
      cache.lookup(MOCK_IP_A, Instant::from_millis(0)),
      Answer::NotFound
    );

    cache.limit_rate(Instant::from_millis(0));
    assert_eq!(
      cache.lookup(MOCK_IP_A, Instant::from_millis(100)),
      Answer::RateLimited
    );

    assert_eq!(
      cache.lookup(MOCK_IP_A, Instant::from_millis(2000)),
      Answer::NotFound
    );
  }

  #[test]
  fn test_flush() {
    let mut cache = Cache::new();
    cache.fill(MOCK_IP_A, HADDR_A, Instant::from_millis(0));
    assert_eq!(
        cache.lookup(MOCK_IP_A, Instant::from_millis(0)),
        Answer::Found(HADDR_A)
    );
    assert!(!cache
        .lookup(MOCK_IP_B, Instant::from_millis(0))
        .found());

    cache.flush();
    assert!(!cache
        .lookup(MOCK_IP_A, Instant::from_millis(0))
        .found());
    assert!(!cache
        .lookup(MOCK_IP_B, Instant::from_millis(0))
        .found());
  }
}