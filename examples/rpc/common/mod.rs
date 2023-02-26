#![allow(dead_code)]
pub mod nexus;

pub mod constant;

pub mod transport;

/* pub mod utils; */

pub mod rpc;

pub mod time;

pub mod sslot;

pub mod msgbuffer;

#[derive(Debug)]
pub enum Error {
  InValidUri,
  ExceedMaxNumaNodes,
  FailBindThread,
  InValidCpuIndex,
  CreateSessionFail,
  ThreadMismatch,
  Exhausted,
  RegisterDisallow,
  ReqFuncExisting,
}

pub type Result<T> = core::result::Result<T, Error>;
