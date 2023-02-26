use std::{cell::RefCell, collections::VecDeque, ptr::NonNull, rc::Rc};

use arrayvec::ArrayVec;
use bytes::Buf;
use log::trace;
use run_dpdk::{Mbuf, Mempool, Pbuf, RxQueue, TxQueue};
use run_packet::{
  ether::{
    self, EtherPacket, EtherType, MacAddr, ETHER_HEADER_LEN,
    ETHER_HEADER_TEMPLATE,
  },
  ipv4::{
    self, IpProtocol, Ipv4Addr, Ipv4Packet, IPV4_HEADER_LEN,
    IPV4_HEADER_TEMPLATE,
  },
  udp::{self, UdpPacket, UDP_HEADER_TEMPLATE},
  PktBuf,
};
use smoltcp::time::Instant;

use crate::common::{
  constant::{INVALID_REQ_TYPE, MAX_MSG_SIZE, SESSION_CREDITS},
  msgbuffer::HEADER_LEN,
  sslot::{ClientInfo, Info},
  time::to_usec,
};

use super::{
  constant::{REQ_TYPE_ARRAY_SIZE, SESSION_REQ_WINDOW, TTR_UNSIG_BATCH},
  msgbuffer::{MsgBuffer, PktType, RpcHeader},
  nexus::Nexus,
  sslot::SSlot,
  time::{ms_to_cycles, rdtsc},
  transport::TxBurstItem,
};

/// The request handler registered by application
#[derive(Debug, Clone, Copy)]
pub struct ReqFunc {
  pub req_func: fn(req_handle: ReqHandle, ctx: RpcContext),
}

#[derive(Debug, Default)]
pub struct RpcContext {
  ptr: Option<NonNull<u8>>,
}

impl Clone for RpcContext {
  fn clone(&self) -> Self {
    Self {
      ptr: self.ptr.clone(),
    }
  }
}

#[repr(transparent)]
pub struct ReqHandle(Rc<RefCell<SSlot>>);

impl From<Rc<RefCell<SSlot>>> for ReqHandle {
  fn from(val: Rc<RefCell<SSlot>>) -> Self {
    Self(val)
  }
}

impl ReqHandle {
  pub fn get_req_msgbuf(&self) -> MsgBuffer {
    self
      .0
      .borrow()
      .server_info()
      .unwrap()
      .req_msgbuf
      .as_ref()
      .unwrap()
      .clone()
  }

  pub fn get_resp_msgbuf(&self) -> MsgBuffer {
    self.0.borrow().pre_resp_msgbuf.clone()
  }

  fn into_inner(self) -> Rc<RefCell<SSlot>> {
    self.0
  }
}

#[derive(PartialEq, Clone, Debug)]
pub struct Tag {
  ptr: Option<NonNull<u8>>,
}

impl Default for Tag {
  fn default() -> Self {
    Self { ptr: None }
  }
}

pub struct ReqArg {
  pub req_type: u8,
  pub req_msgbuf: MsgBuffer,
  pub resp_msgbuf: MsgBuffer,
  pub cont_func: fn(MsgBuffer),
  pub tag: Tag,
}

/// Single Session
pub struct Rpc {
  pub(crate) nexus: Nexus,
  pub(crate) is_client: bool,
  pub(crate) context: RpcContext,
  pub(crate) rpc_id: u8,

  pub(crate) txq: TxQueue,
  pub(crate) rxq: RxQueue,
  pub(crate) mp: Mempool,
  pub(crate) local_ipv4: Ipv4Addr,
  pub(crate) local_port: u16,
  pub(crate) local_mac: MacAddr,
  pub(crate) remote_ipv4: Ipv4Addr,
  pub(crate) remote_port: u16,
  pub(crate) remote_mac: MacAddr,

  pub(crate) freq_ghz: f64,
  pub(crate) ev_loop_tsc: u64,
  pub(crate) pkt_loss_scan_tsc: u64,
  pub(crate) rpc_pkt_loss_scan_cycles: u64,
  pub(crate) rpc_rto_cycles: u64,
  pub(crate) credits: u32,
  pub(crate) active_rpcs_tail_sentinel: Rc<RefCell<SSlot>>,
  pub(crate) active_rpcs_head_sentinel: Rc<RefCell<SSlot>>,
  pub(crate) sslot_free_vec: ArrayVec<usize, SESSION_REQ_WINDOW>,
  pub(crate) enq_req_backlog: VecDeque<ReqArg>,
  pub(crate) req_funcs: Box<[Option<ReqFunc>; REQ_TYPE_ARRAY_SIZE]>,
  pub(crate) sslot_arr: [Option<Rc<RefCell<SSlot>>>; SESSION_REQ_WINDOW],
  pub(crate) stall_q: Vec<Rc<RefCell<SSlot>>>,
  pub(crate) tx_burst_batch: ArrayVec<TxBurstItem, 32>,
  pub(crate) rx_ring: ArrayVec<Mbuf, 32>,
  pub(crate) ctrl_msgbufs: [Option<MsgBuffer>; TTR_UNSIG_BATCH * 2],
  pub(crate) ctrl_msg_head: usize,

  pub(crate) retrasmit_count: u64,
  pub(crate) out_of_order: u64,
  pub(crate) avg_tx: u64,
  pub(crate) avg_deal: u64,
  pub(crate) avg_trans: u64,
}

impl Drop for Rpc {
  fn drop(&mut self) {
    println!("RPC Retrasmit count: {}", self.retrasmit_count);
    println!("Out of order: {}", self.out_of_order);
    println!("RCP TX: {}us", to_usec(self.avg_tx, self.freq_ghz));
    println!("RCP Deal: {}us", to_usec(self.avg_deal, self.freq_ghz));
    println!("RCP Trans: {}us", to_usec(self.avg_trans, self.freq_ghz));
  }
}

impl Rpc {
  pub fn run_event_loop_once(&mut self) {
    self.run_event_loop_do_one_st()
  }

  fn run_event_loop_do_one_st(&mut self) {
    self.ev_loop_tsc = rdtsc();
    // packet Rx code use ev_loop_tsc as the Rx timestamp
    // So it must be next to ev_loop_tsc
    self.process_comps_st(); // Rx code
    self.process_credit_stall_queue_st(); // Tx Code

    if !self.tx_burst_batch.is_empty() {
      trace!("event loop do tx burst");
      self.do_tx_burst_st();
    }

    if self.ev_loop_tsc - self.pkt_loss_scan_tsc > self.rpc_pkt_loss_scan_cycles
    {
      self.pkt_loss_scan_tsc = self.ev_loop_tsc;
      self.pkt_loss_scan_st();
    }
  }

  fn run_event_loop_timeout_st(&mut self, timeout_ms: u64) {
    let timeout_tsc = ms_to_cycles(timeout_ms as f64, self.freq_ghz);
    let start_tsc = rdtsc();
    loop {
      self.run_event_loop_do_one_st();
      if self.ev_loop_tsc - start_tsc > timeout_tsc {
        break;
      }
    }
  }

  pub fn run_event_loop(&mut self, timeout_ms: u64) {
    self.run_event_loop_timeout_st(timeout_ms)
  }

  fn pkt_loss_scan_st(&mut self) {
    /* Datapath packet loss */
    let mut cur = self
      .active_rpcs_head_sentinel
      .borrow()
      .client_info()
      .unwrap()
      .next
      .clone();
    loop {
      if cur.is_none() {
        break;
      }
      let sslot = cur.as_ref().unwrap().clone();
      if sslot.borrow().client_info().unwrap().num_tx
        == sslot.borrow().client_info().unwrap().num_rx
      {
        cur = sslot.borrow().client_info().unwrap().next.clone();
        continue;
      }

      if self.ev_loop_tsc - sslot.borrow().client_info().unwrap().progress_tsc
        > self.rpc_rto_cycles
      {
        self.retrasmit_count += 1;
        self.pkt_loss_retransmit_st(sslot.clone());
        self.drain_tx_batch_and_dma_queue();
      }

      cur = sslot.borrow().client_info().unwrap().next.clone();
    }
  }

  fn pkt_loss_retransmit_st(&mut self, sslot: Rc<RefCell<SSlot>>) {
    assert!(sslot.borrow().tx_msgbuf.is_some());
    let delta = sslot.borrow().client_info().unwrap().num_tx
      - sslot.borrow().client_info().unwrap().num_rx;
    assert!(self.credits as usize + delta <= SESSION_CREDITS);

    if delta == 0 {
      trace!("False positive. Ingoring");
      return;
    }

    //assert!(!self.stall_q.contains(&sslot));
    trace!("Retransmitting");
    self.credits += delta as u32;
    let num_rx = sslot.borrow().client_info().unwrap().num_rx;
    sslot.borrow_mut().client_info_mut().unwrap().num_tx = num_rx;
    sslot.borrow_mut().client_info_mut().unwrap().progress_tsc =
      self.ev_loop_tsc;

    if self.req_pkts_pending(sslot.clone()) {
      self.kick_req_st(sslot);
    } else {
      self.kick_rfr_st(sslot);
    }
  }

  fn process_credit_stall_queue_st(&mut self) {
    loop {
      if self.stall_q.last().is_some() {
        if self.credits > 0 {
          let sslot = self.stall_q.pop().unwrap();
          if self.req_pkts_pending(sslot.clone()) {
            self.kick_req_st(sslot.clone());
          } else {
            self.kick_rfr_st(sslot.clone());
          }
        } else {
          break;
        }
      } else {
        break;
      }
    }
  }

  /// We are asked to send RFRs, which means we have recieved the first response packet,
  /// but not the entire response.
  fn kick_rfr_st(&mut self, sslot: Rc<RefCell<SSlot>>) {
    assert!(self.credits > 0);
    assert!(
      sslot.borrow().client_info().unwrap().num_rx
        >= sslot.borrow().tx_msgbuf.as_ref().unwrap().num_pkts()
    );
    let wire_pkts = sslot.borrow().tx_msgbuf.as_ref().unwrap().num_pkts()
      + sslot
        .borrow()
        .client_info()
        .unwrap()
        .resp_msgbuf
        .as_ref()
        .unwrap()
        .num_pkts()
      - 1;
    assert!(sslot.borrow().client_info().unwrap().num_rx < (wire_pkts));
    // TODO: Pace RFRs

    let rfr_pndng = wire_pkts - sslot.borrow().client_info().unwrap().num_tx;
    let sending = std::cmp::min(rfr_pndng, self.credits as usize);

    for _ in 0..sending {
      self.enqueue_rfr_st(
        sslot.clone(),
        &sslot
          .borrow()
          .client_info()
          .unwrap()
          .resp_msgbuf
          .as_ref()
          .unwrap()
          .get_pkthdr_0(),
      );
      sslot.borrow_mut().client_info_mut().unwrap().num_tx += 1;
      self.credits -= 1;
    }
  }

  fn enqueue_rfr_st(&mut self, sslot: Rc<RefCell<SSlot>>, pkt_hdr: &RpcHeader) {
    let ctrl_msgbuf = self.ctrl_msgbufs[self.ctrl_msg_head].clone();
    self.ctrl_msg_head += 1;
    if self.ctrl_msg_head == 2 * TTR_UNSIG_BATCH {
      self.ctrl_msg_head = 0;
    }

    //Fill in the RFR packet header. Avoid copying resp_pkthdr's headroom
    let rfr_pkthdr = ctrl_msgbuf.as_ref().unwrap().get_pkthdr_0();
    rfr_pkthdr.set_req_type(pkt_hdr.req_type());
    rfr_pkthdr.set_msg_size(0);
    rfr_pkthdr.set_pkt_type(PktType::RFR);
    rfr_pkthdr.set_pkt_num(sslot.borrow().client_info().unwrap().num_tx as u16);
    rfr_pkthdr.set_req_num(pkt_hdr.req_num());
    rfr_pkthdr.set_magic(11);
    rfr_pkthdr.set_ts(Instant::now().total_micros() as u64);

    self.enqueue_hdr_tx_burst_st(sslot, ctrl_msgbuf.unwrap());
  }

  fn enqueue_hdr_tx_burst_st(
    &mut self,
    _sslot: Rc<RefCell<SSlot>>,
    ctrl_msgbuf: MsgBuffer,
  ) {
    let item = TxBurstItem {
      msg_buffer: ctrl_msgbuf,
      pkt_idx: 0,
      drop: false,
    };
    trace!("enqueue header to tx burst");
    self.tx_burst_batch.push(item);
    if self.tx_burst_batch.is_full() {
      self.do_tx_burst_st();
    }
  }
  fn req_pkts_pending(&self, sslot: Rc<RefCell<SSlot>>) -> bool {
    sslot.borrow().client_info().unwrap().num_tx
      < sslot.borrow().tx_msgbuf.as_ref().unwrap().num_pkts()
  }

  fn process_comps_st(&mut self) {
    self.rxq.rx(&mut self.rx_ring);
    if self.rx_ring.is_empty() {
      return;
    }
    //let num_pkts=self.rx_ring.len();
    let batch_rx_tsc = self.ev_loop_tsc;
    let mut idx = 0;
    let mut rx_ring = self.rx_ring.take();

    for mut mbuf in rx_ring.drain(..) {
      let mut pbuf = Pbuf::new(&mut mbuf);
      let epkt = ether::EtherPacket::parse(pbuf).unwrap();
      if epkt.dest_mac() != self.local_mac {
        trace!(
          "ethernet packet dest mac {} is not here {}. Drop it",
          epkt.dest_mac(),
          self.local_mac
        );
        continue;
      }
      if epkt.ethertype() != EtherType::IPV4 {
        trace!("arrived packet is not a ipv4 packet. Drop it");
        continue;
      }
      let ippkt = ipv4::Ipv4Packet::parse(epkt.payload()).unwrap();
      if ippkt.dest_ip() != self.local_ipv4 {
        trace!(
          "ipv4 packet dest ip {} is not here {}. Drop it",
          ippkt.dest_ip(),
          self.local_ipv4
        );
        continue;
      }

      if ippkt.protocol() != IpProtocol::UDP {
        trace!("arrived packet is not a udp packet. Drop it");
        continue;
      }
      let udppkt = udp::UdpPacket::parse(ippkt.payload()).unwrap();
      if udppkt.dest_port() != self.local_port {
        trace!("udp packet dest port is not here.Drop it");
        continue;
      }
      pbuf = udppkt.payload();
      pbuf.move_back(42);
      let mut pkt_hdr = RpcHeader::from_slice(pbuf.chunk());

      pbuf.advance(HEADER_LEN);

      idx += 1;
      if idx == self.rx_ring.len() {
        break;
      }

      if pkt_hdr.magic() != 11 {
        trace!("Received a packet with invalid magic.Dropping");
        continue;
      }

      {
        let before = pkt_hdr.ts();
        let now = Instant::now().total_micros() as u64;
        self.avg_trans = (now - before + 4 + self.avg_trans * 3) / 4;
        pkt_hdr.set_ts(now);
      }

      // msg size can be zero
      assert!(pkt_hdr.msg_size() as usize <= MAX_MSG_SIZE);

      let sslot_i = pkt_hdr.req_num() as usize % SESSION_REQ_WINDOW;
      let sslot = self.sslot_arr[sslot_i].clone().unwrap();

      match pkt_hdr.pkt_type() {
        PktType::Req => {
          self.process_req_st(sslot, &pkt_hdr);
        }
        PktType::RFR => {
          self.process_rfr_st(sslot, &pkt_hdr);
        }

        PktType::ExplCR => {
          unimplemented!();
        }
        PktType::Resp => {
          self.process_resp_one_st(sslot, &pkt_hdr, pbuf, batch_rx_tsc)
        }
      };
    }
  }

  fn process_rfr_st(&mut self, sslot: Rc<RefCell<SSlot>>, pkt_hdr: &RpcHeader) {
    assert!(!sslot.borrow().is_client());

    assert!(pkt_hdr.req_num() as usize <= sslot.borrow().cur_req_num);

    let in_order = (pkt_hdr.req_num() as usize == sslot.borrow().cur_req_num)
      && (pkt_hdr.pkt_num() as usize
        == sslot.borrow().server_info().unwrap().num_rx);

    if !in_order {
      trace!("Received out-of-order RFR.");

      if (pkt_hdr.req_num() as usize) < sslot.borrow().cur_req_num
        || pkt_hdr.pkt_num() as usize
          > sslot.borrow().server_info().unwrap().num_rx
      {
        trace!(
          "Dropping {}, num_rx:{}",
          pkt_hdr,
          sslot.borrow().server_info().unwrap().num_rx
        );
        return;
      }

      trace!(
        "Re-sending response, {}, num_rx: {}",
        pkt_hdr,
        sslot.borrow().server_info().unwrap().num_rx
      );

      //assert!(false);
      let pkt_idx = pkt_hdr.pkt_num() as usize
        - sslot.borrow().server_info().unwrap().sav_num_req_pkts
        + 1;
      self.enqueue_pkt_tx_burst_st(sslot, pkt_idx);
      self.drain_tx_batch_and_dma_queue();
      return;
    }
    sslot.borrow_mut().server_info_mut().unwrap().num_rx += 1;

    let pkt_idx = pkt_hdr.pkt_num() as usize
      - sslot.borrow().server_info().unwrap().sav_num_req_pkts
      + 1;
    trace!(
      "Sending {}th response, {}, num_rx: {}",
      pkt_idx,
      pkt_hdr,
      sslot.borrow().server_info().unwrap().num_rx
    );
    self.enqueue_pkt_tx_burst_st(sslot, pkt_idx)
  }

  fn process_req_st(&mut self, sslot: Rc<RefCell<SSlot>>, pkt_hdr: &RpcHeader) {
    trace!(
      "Received a request, Req num:{} (pkt), {} (sslot).Action",
      pkt_hdr.req_num(),
      sslot.borrow().cur_req_num
    );
    //handle reordering
    if pkt_hdr.req_num() <= sslot.borrow().cur_req_num as u64 {
      trace!(
        "Received out-of-order request, Req num:{} (pkt), {} (sslot).Action",
        pkt_hdr.req_num(),
        sslot.borrow().cur_req_num
      );

      // This is a massively-delayed retransmission of an old request
      if pkt_hdr.req_num() < sslot.borrow().cur_req_num as u64 {
        return;
      } else {
        // This is a retransmission for the currently active request
        if sslot.borrow().tx_msgbuf.is_some() {
          self.enqueue_pkt_tx_burst_st(sslot, 0);
          self.drain_tx_batch_and_dma_queue();
          println!("retransmitting");
          return;
        }
        trace!("Response not available yet. Dropping.");
        return;
      }
    }

    // If we are here, this is the first(and only) packet of this new request
    assert!(
      pkt_hdr.req_num()
        == sslot.borrow().cur_req_num as u64 + SESSION_REQ_WINDOW as u64
    );
    assert!(!sslot.borrow().is_client());
    assert!(sslot.borrow().server_info().unwrap().req_msgbuf.is_none());

    // Bury the previous, possibly dynamic response (sslot->tx_msgbuf)
    self.bury_resp_msgbuf_server_st(sslot.clone());

    // Update sslot tracking
    sslot.borrow_mut().cur_req_num = pkt_hdr.req_num() as usize;
    sslot.borrow_mut().server_info_mut().unwrap().num_rx = 1;

    let req_func = self.req_funcs[pkt_hdr.req_type() as usize];
    assert!(
      sslot.borrow().server_info().unwrap().req_type as usize
        == INVALID_REQ_TYPE
    );
    sslot.borrow_mut().server_info_mut().unwrap().req_type =
      pkt_hdr.req_type() as u8;
    sslot.borrow_mut().server_info_mut().unwrap().req_msgbuf = Some(unsafe {
      MsgBuffer::from_pkthdr(pkt_hdr, pkt_hdr.msg_size() as usize)
    });

    (req_func.unwrap().req_func)(
      ReqHandle::from(sslot.clone()),
      self.context.clone(),
    );
    self.enqueue_response(sslot);
  }

  fn bury_resp_msgbuf_server_st(&mut self, sslot: Rc<RefCell<SSlot>>) {
    /* if sslot.borrow().tx_msgbuf.as_ref() == Some(&sslot.borrow().dyn_resp_msgbus) {
        // free msg buffer but not Box memery
        unimplemented!()
    } */

    sslot.borrow_mut().tx_msgbuf = None;
  }
  // drop the req_msgbuf to indicate the requestion has been dealed with
  fn bury_req_msgbuf_server_st(&mut self, sslot: Rc<RefCell<SSlot>>) {
    /* unsafe{
        sslot.borrow_mut().server_info_mut().unwrap().req_msgbuf.as_ref().unwrap().buried_buf();
    } */
    sslot.borrow_mut().server_info_mut().unwrap().req_msgbuf = None;
  }
  /// Complete transmission for all packets in the Rpc's TX batch and the
  /// transport's DMA queue
  fn drain_tx_batch_and_dma_queue(&mut self) {
    trace!("drain tx batch and dma queue");
    if !self.tx_burst_batch.is_empty() {
      self.do_tx_burst_st();
    }
    //self.transport.tx_flush()
  }

  fn process_resp_one_st(
    &mut self,
    sslot: Rc<RefCell<SSlot>>,
    pkt_hdr: &RpcHeader,
    mut payload: Pbuf,
    _rx_tsc: u64,
  ) {
    assert!(pkt_hdr.req_num() <= sslot.borrow().cur_req_num as u64);

    //handle reordering
    if !self.in_order_client(sslot.clone(), pkt_hdr) {
      self.out_of_order += 1;
      trace!(
                "Received out-of-order response. Rpc Header: {}, cur_req_num: {}, num_rx: {} num_tx: {}",
                pkt_hdr,sslot.borrow().cur_req_num,sslot.borrow().client_info().unwrap().num_rx,
                sslot.borrow().client_info().unwrap().num_tx
            );
      return;
    }
    trace!(
            "Received a response. Rpc Header: {}, cur_req_num: {}, num_rx: {} num_tx: {}",
            pkt_hdr,sslot.borrow().cur_req_num,sslot.borrow().client_info().unwrap().num_rx,
            sslot.borrow().client_info().unwrap().num_tx
        );
    self.credits += 1;
    sslot.borrow_mut().client_info_mut().unwrap().num_rx += 1;
    sslot.borrow_mut().client_info_mut().unwrap().progress_tsc =
      self.ev_loop_tsc;

    let req_msgbuf = sslot.borrow().tx_msgbuf.as_ref().unwrap().clone();

    if pkt_hdr.pkt_num() == req_msgbuf.num_pkts() as u16 - 1 {
      //This is the first response packet
      let mut sm = sslot.borrow_mut();
      let resp_msgbuf =
        sm.client_info_mut().unwrap().resp_msgbuf.as_mut().unwrap();
      resp_msgbuf.resize_msg_buffer(pkt_hdr.msg_size() as usize);
      resp_msgbuf
        .get_pkthdr_0()
        .buf_mut()
        .copy_from_slice(pkt_hdr.buf());
    }

    let wire_pkts = req_msgbuf.num_pkts()
      + sslot
        .borrow()
        .client_info()
        .unwrap()
        .resp_msgbuf
        .as_ref()
        .unwrap()
        .num_pkts()
      - 1;

    // Transmit remaining RFRs before response memcpy
    if sslot.borrow().client_info().unwrap().num_tx != wire_pkts {
      self.kick_rfr_st(sslot.clone());
    }

    //Hdr 0 was copied earlier, ohter headers are uneeded
    let pkt_idx = pkt_hdr.pkt_num() + 1 - req_msgbuf.num_pkts() as u16;

    //Copy data to msgbuffer
    sslot
      .borrow_mut()
      .client_info_mut()
      .unwrap()
      .resp_msgbuf
      .as_mut()
      .unwrap()
      .copy_data_from_buf(&mut payload, pkt_idx as usize);

    if sslot.borrow().client_info().unwrap().num_rx != wire_pkts {
      return;
    } // Else fall through to invoke continuation
      //}

    sslot.borrow_mut().tx_msgbuf = None;
    self.delete_from_active_rpc_list(sslot.clone());

    //Free-up this sslot by copying-out needed fields.
    self.sslot_free_vec.push(sslot.borrow().index);

    // Clear up one request from the backlog if needed
    if !self.enq_req_backlog.is_empty() {
      assert!(self.sslot_free_vec.len() == 1);
      let args = self.enq_req_backlog.pop_front().unwrap();
      self.enqueue_request(
        args.req_type,
        args.req_msgbuf,
        args.resp_msgbuf,
        args.cont_func,
        args.tag,
      );
    }
    //let tag=sslot.borrow().client_info().unwrap().tag.clone();
    let cont_func = sslot.borrow().client_info().unwrap().cont_func.unwrap();
    (cont_func)(
      sslot
        .borrow()
        .client_info()
        .unwrap()
        .resp_msgbuf
        .as_ref()
        .unwrap()
        .clone(),
    );
  }

  fn delete_from_active_rpc_list(&mut self, sslot: Rc<RefCell<SSlot>>) {
    let mut next = sslot.borrow().client_info().unwrap().next.clone();
    let prev = sslot.borrow().client_info().unwrap().prev.clone();
    next
      .as_mut()
      .unwrap()
      .borrow_mut()
      .client_info_mut()
      .unwrap()
      .prev = prev.clone();
    prev.unwrap().borrow_mut().client_info_mut().unwrap().next = next;
  }

  #[inline]
  fn in_order_client(
    &mut self,
    sslot: Rc<RefCell<SSlot>>,
    pkt_hdr: &RpcHeader,
  ) -> bool {
    if pkt_hdr.req_num() != sslot.borrow().cur_req_num as u64 {
      return false;
    }

    if pkt_hdr.pkt_num() != sslot.borrow().client_info().unwrap().num_rx as u16
    {
      return false;
    }

    if pkt_hdr.pkt_num() >= sslot.borrow().client_info().unwrap().num_tx as u16
    {
      return false;
    }

    true
  }

  pub fn create_session(&mut self, client: bool, max_data_size: usize) {
    if !client {
      for i in 0..self.sslot_arr.len() {
        self.sslot_arr[i]
          .as_mut()
          .unwrap()
          .borrow_mut()
          .pre_resp_msgbuf = MsgBuffer::ALLOCA_MSG(max_data_size);
      }
    }
  }

  pub fn is_connected(&self) -> bool {
    //
    true
  }

  /// Must call event_loop at least once before call this method.
  pub fn enqueue_request(
    &mut self,
    req_type: u8,
    req_msgbuf: MsgBuffer,
    resp_msgbuf: MsgBuffer,
    cont_func: fn(MsgBuffer),
    tag: Tag,
  ) {
    assert!(self.is_client);
    // if a free sslot is unavailable, save to backlog
    if self.sslot_free_vec.len() == 0 {
      let args = ReqArg {
        req_type,
        req_msgbuf,
        resp_msgbuf,
        cont_func,
        tag,
      };
      trace!("no enough sslot,enque req to back");
      if self.enq_req_backlog.len() < 64 {
        self.enq_req_backlog.push_back(args);
      }
      return;
    }

    //Fill in the sslot info
    let sslot_i = self.sslot_free_vec.pop().unwrap();
    let sslot = self.sslot_arr[sslot_i].clone().unwrap();

    // Previous response was received
    assert!(sslot.borrow().tx_msgbuf.is_none());

    // Mark the request as active/incomplete
    sslot.borrow_mut().tx_msgbuf = Some(req_msgbuf.clone());

    // Move to next request
    sslot.borrow_mut().cur_req_num += SESSION_REQ_WINDOW;

    //println!("{}",sslot.borrow_mut().cur_req_num);

    let mut ci = ClientInfo::default();
    ci.resp_msgbuf = Some(resp_msgbuf.clone());
    ci.cont_func = Some(cont_func);
    ci.tag = tag;
    ci.progress_tsc = self.ev_loop_tsc;
    sslot.borrow_mut().set_info(Info::Client(ci));
    self.add_to_active_rpc_list(sslot.clone());

    let req_num = sslot.borrow().cur_req_num as u64;
    // Fill in packet header
    let pkt_hdr = req_msgbuf.get_pkthdr_0();
    pkt_hdr.set_req_type(req_type as u8);
    pkt_hdr.set_msg_size(req_msgbuf.data_size() as u32);
    pkt_hdr.set_pkt_type(PktType::Req);
    pkt_hdr.set_pkt_num(0);
    pkt_hdr.set_magic(11);
    pkt_hdr.set_ts(Instant::now().total_micros() as u64);

    assert_eq!(pkt_hdr.magic(), 11);
    assert_eq!(pkt_hdr.pkt_num(), 0);
    assert_eq!(pkt_hdr.pkt_type(), PktType::Req);
    pkt_hdr.set_req_num(req_num);
    assert_eq!(pkt_hdr.req_num(), sslot.borrow().cur_req_num as u64);

    //Fill in any non-zeroth packet headers, using pkthdr_0 as the base
    if req_msgbuf.num_pkts() > 1 {
      unimplemented!()
    }

    if self.credits > 0 {
      trace!(
        "enqueue a request: 
            req num {}, 
            msg size {},
            pkt num {},
            credits {}",
        pkt_hdr.req_num(),
        pkt_hdr.msg_size(),
        pkt_hdr.pkt_num(),
        self.credits
      );
      self.kick_req_st(sslot);
    } else {
      trace!("no enough credits, stall request");
      self.stall_q.push(sslot);
    }
  }

  pub fn enqueue_response(&mut self, sslot: Rc<RefCell<SSlot>>) {
    assert!(!self.is_client);
    //The server remembers the number of packets in the request after
    //burying the request in enqueue_response().
    let resp_msgbuf = sslot.borrow().pre_resp_msgbuf.clone();

    let num_pkts = sslot
      .borrow()
      .server_info()
      .unwrap()
      .req_msgbuf
      .as_ref()
      .unwrap()
      .num_pkts();
    assert!(num_pkts == 1);

    sslot
      .borrow_mut()
      .server_info_mut()
      .unwrap()
      .sav_num_req_pkts = num_pkts;

    // Bury the possibly-dynamic req MsgBuffer
    self.bury_req_msgbuf_server_st(sslot.clone());

    // Fill in packet header
    let pkt_hdr = resp_msgbuf.get_pkthdr_0();
    pkt_hdr.set_req_type(sslot.borrow().server_info().unwrap().req_type as u8);
    pkt_hdr.set_req_num(sslot.borrow().cur_req_num as u64);
    pkt_hdr.set_msg_size(resp_msgbuf.data_size() as u32);

    pkt_hdr.set_pkt_num(
      sslot.borrow().server_info().unwrap().sav_num_req_pkts as u16 - 1,
    );
    pkt_hdr.set_magic(11);
    pkt_hdr.set_pkt_type(PktType::Resp);
    pkt_hdr.set_ts(Instant::now().total_micros() as u64);

    assert_eq!(pkt_hdr.pkt_type(), PktType::Resp);
    assert_eq!(pkt_hdr.magic(), 11);
    assert_eq!(
      pkt_hdr.pkt_num(),
      sslot.borrow().server_info().unwrap().sav_num_req_pkts as u16 - 1
    );
    assert_eq!(pkt_hdr.msg_size(), resp_msgbuf.data_size() as u32);
    assert_eq!(pkt_hdr.req_num(), sslot.borrow().cur_req_num as u64);

    // Fill in non-zeroth packet headers
    if resp_msgbuf.num_pkts() > 1 {
      for i in 1..resp_msgbuf.num_pkts() {
        /*  */
        let resp_hdr_i = resp_msgbuf.get_pkthdr_n(i);
        *resp_hdr_i = *pkt_hdr;
        resp_hdr_i.set_pkt_num(pkt_hdr.pkt_num() + i as u16);
      }
    }

    // Fill in the slot
    assert!(sslot.borrow().tx_msgbuf.is_none());
    sslot.borrow_mut().tx_msgbuf = Some(resp_msgbuf);

    // Mark enqueue_response() as completed
    assert!(
      sslot.borrow().server_info().unwrap().req_type as usize
        != INVALID_REQ_TYPE
    );
    sslot.borrow_mut().server_info_mut().unwrap().req_type =
      INVALID_REQ_TYPE as u8;

    self.enqueue_pkt_tx_burst_st(sslot, 0);
  }

  fn add_to_active_rpc_list(&self, sslot: Rc<RefCell<SSlot>>) {
    let prev_tail = self
      .active_rpcs_tail_sentinel
      .borrow_mut()
      .client_info_mut()
      .unwrap()
      .prev
      .clone()
      .unwrap();
    prev_tail.borrow_mut().client_info_mut().unwrap().next =
      Some(sslot.clone());
    sslot.borrow_mut().client_info_mut().unwrap().prev = Some(prev_tail);

    sslot.borrow_mut().client_info_mut().unwrap().next =
      Some(self.active_rpcs_tail_sentinel.clone());

    self
      .active_rpcs_tail_sentinel
      .borrow_mut()
      .client_info_mut()
      .unwrap()
      .prev = Some(sslot);
  }

  /// Enqueue client packets for a sslot that has at least one credit and
  /// request packets to send. Packets may be added to the timing wheel or the
  /// TX burst; credits are used in both cases.
  ///
  /// May be should increase the number of packets
  fn kick_req_st(&mut self, sslot: Rc<RefCell<SSlot>>) {
    let sending = std::cmp::min(
      self.credits as usize,
      sslot.borrow().tx_msgbuf.as_ref().unwrap().num_pkts()
        - sslot.borrow().client_info().unwrap().num_tx,
    );

    for i in 0..sending {
      self.enqueue_pkt_tx_burst_st(sslot.clone(), i);
      self.credits -= 1;
      sslot.borrow_mut().client_info_mut().unwrap().num_tx += 1;
    }
  }

  fn enqueue_pkt_tx_burst_st(
    &mut self,
    sslot: Rc<RefCell<SSlot>>,
    pkt_idx: usize,
  ) {
    let item = TxBurstItem {
      msg_buffer: sslot.borrow().tx_msgbuf.as_ref().unwrap().clone(),
      pkt_idx: pkt_idx,
      drop: false,
    };
    trace!("enqueue packet to tx burst");
    self.tx_burst_batch.push(item);
    if self.tx_burst_batch.is_full() {
      self.do_tx_burst_st();
    }
  }

  fn do_tx_burst_st(&mut self) {
    /*
        data path stat
    */
    let mut batch: ArrayVec<Mbuf, 32> = ArrayVec::new();
    for item in self.tx_burst_batch.drain(..) {
      let msg_buffer = &item.msg_buffer;
      let mut buf = msg_buffer.get_buf_n(item.pkt_idx);
      {
        let mut rpchdr = RpcHeader::from_slice(buf.chunk());
        let before = rpchdr.ts();
        let now = Instant::now().total_micros() as u64;
        if self.avg_tx == 0 {
          self.avg_tx = now - before;
        } else {
          self.avg_tx = (self.avg_tx * 3 + now - before + 4) / 4;
        }
        rpchdr.set_ts(self.avg_tx);
      }

      buf.advance(42);

      let mut udp_pkt = UdpPacket::prepend_header(buf, &UDP_HEADER_TEMPLATE);
      udp_pkt.set_dest_port(self.remote_port);
      udp_pkt.set_source_port(self.local_port);

      let mut ippkt =
        Ipv4Packet::prepend_header(udp_pkt.release(), &IPV4_HEADER_TEMPLATE);
      ippkt.set_protocol(IpProtocol::UDP);
      ippkt.set_dest_ip(self.remote_ipv4);
      ippkt.set_source_ip(self.local_ipv4);
      ippkt.set_time_to_live(64);

      let mut ethpkt =
        EtherPacket::prepend_header(ippkt.release(), &ETHER_HEADER_TEMPLATE);
      ethpkt.set_dest_mac(self.remote_mac);
      ethpkt.set_source_mac(self.local_mac);
      ethpkt.set_ethertype(EtherType::IPV4);

      buf = ethpkt.release();
      buf.advance(HEADER_LEN);
      let mut mbuf = Mbuf::from_slice(buf.chunk(), &self.mp).unwrap();
      buf.move_back(HEADER_LEN);
      mbuf.extend_front_from_slice(buf.chunk());

      let mut ol_flag = run_dpdk::offload::MbufTxOffload::ALL_DISABLED;
      ol_flag.set_l2_len(ETHER_HEADER_LEN as u64);
      ol_flag.set_l3_len(IPV4_HEADER_LEN as u64);
      ol_flag.enable_ip_cksum();

      mbuf.set_tx_offload(&ol_flag);
      batch.push(mbuf);
    }
    trace!("do send {} packet", batch.len());
    while !batch.is_empty() {
      self.txq.tx(&mut batch);
    }
  }
}
