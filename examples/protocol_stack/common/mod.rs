mod device;
mod socket_buffer;
mod assembler;
mod rand;
pub mod stack;

pub use device::DpdkDevice;
pub use device::DpdkDeviceHelper;


pub trait Device {
  fn alloc(&mut self) -> Option<run_dpdk::Mbuf>;
  fn send(&mut self,pkt:run_dpdk::Mbuf) -> Option<run_dpdk::Mbuf>;
  fn recv(&mut self)->Option<run_dpdk::Mbuf>;
}

pub trait Batch {

  fn recv_batch<const N:usize>(&mut self,
                              batch:&mut arrayvec::ArrayVec<run_dpdk::Mbuf,N>);

  fn send_batch<const N:usize>(&mut self,
                              batch:&mut arrayvec::ArrayVec<run_dpdk::Mbuf,N>);

  fn alloc_batch<const N:usize>(&mut self,
                              batch:&mut arrayvec::ArrayVec<run_dpdk::Mbuf,N>);
}

pub trait Stack {
  fn is_close(&self)-> bool;

  fn on_recv(&mut self,pkt:run_dpdk::Mbuf,ts:run_time::Instant) 
        -> Option<run_dpdk::Mbuf>;
  
  fn has_data(&mut self,ts:run_time::Instant) -> bool;
  
  fn do_send<F>(&mut self,pkt:run_dpdk::Mbuf,ts:run_time::Instant,emit:F)
        where F: FnOnce(run_dpdk::Mbuf) -> bool;
}


pub trait Producer {
  fn produce(&mut self,size:usize) -> Option<&[u8]>;
}

pub trait Consumer {
  fn consume(&mut self,size:usize) -> &mut [u8];
}


pub fn poll<S:Stack,P:Device>(dev:&mut P,stack:&mut S) {
  loop {
    if stack.is_close() {
      break;
    }
    let ts = run_time::Instant::now();
    if let Some(mut pkt) = dev.recv() {
      if let Some(response) = stack.on_recv(pkt, ts) {
        dev.send(response);
      }
    }
    if stack.has_data(ts) {
      if let Some(mut pkt) = dev.alloc() {
        stack.do_send(pkt,ts,|mbuf| {
          dev.send(mbuf).is_none()
        });
      }
    }
  }
}

pub fn poll_in_batch<S,P,const N:usize>(dev:&mut P,stack:&mut S) 
where 
  S: Stack,
  P: Batch + Device {
  loop {
    if stack.is_close() {
      break;
    }
    let ts = run_time::Instant::now();
    let mut recv_batch:arrayvec::ArrayVec<run_dpdk::Mbuf,N> = 
                                                    arrayvec::ArrayVec::new();
    let mut resp_batch:arrayvec::ArrayVec<run_dpdk::Mbuf,N> = 
                                                    arrayvec::ArrayVec::new();
    let mut send_batch:arrayvec::ArrayVec<run_dpdk::Mbuf,N> = 
                                                    arrayvec::ArrayVec::new();
    dev.recv_batch(&mut recv_batch);
    for pkt in recv_batch.into_iter() {
      if let Some(response) = stack.on_recv(pkt, ts) {
        resp_batch.push(response);
      }
    }
    dev.send_batch(&mut resp_batch);
    assert_eq!(resp_batch.len(),0);
    dev.alloc_batch(&mut resp_batch);
    for mbuf in resp_batch.into_iter() {
      stack.do_send(mbuf, ts, |mbuf| {
        send_batch.push(mbuf);
        true
      })
    }
    dev.send_batch(&mut send_batch);
  }
}