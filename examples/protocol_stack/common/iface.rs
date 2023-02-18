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

pub struct Interface<S:Stack,P:Device>{
  dev:P,
  stack:S,
}

impl <S:Stack,P:Device> Interface<S,P> {
  #[must_use]
  pub fn new(dev:P,stack:S) -> Self {
    Interface { 
      dev:dev,
      stack:stack,
    }
  }

  pub fn poll(&mut self) {
    loop {
      if self.stack.is_close() {
        break;
      }
      let ts = Instant::now();
      if let Some(mut pkt) = self.dev.recv() {
        if let Some(response) = self.stack.on_recv(pkt, ts) {
          self.dev.send(response);
        }
      }
      if self.stack.has_data(ts) {
        if let Some(mut pkt) = self.dev.alloc() {
          self.stack.do_send(pkt,ts,|mbuf| {
            self.dev.send(mbuf).is_none()
          });
        }
      }
    }
  }
}

impl <S:Stack,P:Device + Batch> Interface<S,P> {
  pub fn poll_in_batch<const N:usize>(&mut self) {
    loop {
      if self.stack.is_close() {
        break;
      }
      let ts = Instant::now();
      let mut recv_batch = ArrayVec::<Mbuf,N>::new();
      let mut send_batch = ArrayVec::<Mbuf,N>::new();
      self.dev.recv_batch(&mut recv_batch);
      for pkt in recv_batch.into_iter() {
        if let Some(response) = self.stack.on_recv(pkt, ts) {
          send_batch.push(response);
        }
      }
      self.dev.send_batch(&mut send_batch);
      let fail_to_send = send_batch.len();
      self.dev.alloc_batch(&mut send_batch);
      let mut write_at = fail_to_send;
      while write_at != N && self.stack.has_data(ts) {
        self.stack.do_send(send_batch[write_at],ts,|mbuf| {
          self.dev.send(mbuf).is_none()
        });
        write_at += 1;
      }
      self.dev.send_batch(&mut send_batch);
    }
  }
}

#[cfg(test)]
mod test {
  use super::*;
  
  #[test]
  fn test_interface_socket_new() {
    
  }
}