mod tcp;

pub use tcp::*;


pub trait Producer {
    fn produce(&mut self,size:usize) -> Option<&[u8]>;
  }
  
  pub trait Consumer {
    fn consume(&mut self,size:usize) -> &mut [u8];
  }