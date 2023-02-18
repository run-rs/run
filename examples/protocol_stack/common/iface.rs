use arrayvec::ArrayVec;
use run_dpdk::Mbuf;
pub use run_packet::Cursor;
pub use run_packet::CursorMut;
pub use run_dpdk::Pbuf;
use run_time::Instant;

struct If<const COND:bool>;
trait True {}

impl True for If<true> {}

pub trait Device {
  fn alloc(&mut self) -> Option<Mbuf>;
  fn send(&mut self,pkt:Mbuf) -> Option<Mbuf>;
  fn recv(&mut self)->Option<Mbuf>;
}

pub trait Batch {
  fn recv_batch<const N:usize>(&mut self,
                                  batch:&mut ArrayVec<Mbuf,N>);
  fn send_batch<const N:usize>(&mut self,
                                  batch:&mut ArrayVec<Mbuf,N>);
  fn alloc_batch<const N:usize>(&mut self,batch:&mut ArrayVec<Mbuf,N>);
}

pub trait Stack {
  fn is_close(&self)-> bool;
  fn on_recv(&mut self,pkt:Mbuf,ts:Instant) -> Option<Mbuf>;
  fn has_data(&mut self,ts:Instant) -> bool;
  fn do_send<F>(&mut self,pkt:Mbuf,ts:Instant,emit:F)
    where F: FnOnce(Mbuf) -> bool;
}

pub fn poll<S:Stack,P:Device>(dev:P,stack:S) {
  loop {
    if stack.is_close() {
      break;
    }
    let ts = Instant::now();
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

pub fn poll_in_batch<S:Stack,P:Device + Batch,const N:usize>(dev:P,stack:S) {
  loop {
    if stack.is_close() {
      break;
    }
    let ts = Instant::now();
    let mut recv_batch = ArrayVec::<Mbuf,N>::new();
    let mut send_batch = ArrayVec::<Mbuf,N>::new();
    dev.recv_batch(&mut recv_batch);
    for pkt in recv_batch.into_iter() {
      if let Some(response) = stack.on_recv(pkt, ts) {
        send_batch.push(response);
      }
    }
    dev.send_batch(&mut send_batch);
    let fail_to_send = send_batch.len();
    dev.alloc_batch(&mut send_batch);
    let mut write_at = fail_to_send;
    while write_at != N && stack.has_data(ts) {
      stack.do_send(send_batch[write_at],ts,|mbuf| {
        dev.send(mbuf).is_none()
      });
      write_at += 1;
    }
    dev.send_batch(&mut send_batch);
  }
}

#[cfg(test)]
mod test {
  use super::*;
  
  #[test]
  fn test_interface_socket_new() {
    
  }
}