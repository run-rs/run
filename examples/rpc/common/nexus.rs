use std::cell::RefCell;
use std::collections::VecDeque;
use std::rc::Rc;
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicBool, Ordering};


use arrayvec::ArrayVec;
use run_dpdk::{TxQueue, RxQueue, Mempool};
use run_packet::ether::MacAddr;
use run_packet::ipv4::Ipv4Addr;





use crate::common::constant::{RPC_REQUEST_TIMEOUT, SESSION_REQ_WINDOW, TTR_UNSIG_BATCH};
use crate::common::time::{us_to_cycles, ms_to_cycles};
use crate::common::msgbuffer::{MsgBuffer, HEADER_LEN};
use crate::common::sslot::SSlot;
use crate::common::rpc::{ReqFunc, Rpc, RpcContext};
use crate::common::{Error,Result};


use super::constant::{REQ_TYPE_ARRAY_SIZE};
use super::time::measure_rdtsc_freq;



struct NexusInner{
    freq_ghz:f64,
    req_funcs:Box<[Option<ReqFunc>;REQ_TYPE_ARRAY_SIZE]>,
    pad_:[u8;64],
    req_func_registration_allowed:AtomicBool,
}

pub struct Nexus{
    ptr:Arc<Mutex<Box<NexusInner>>>,
}


impl Clone for Nexus {
    fn clone(&self) -> Self {
        Self { ptr: self.ptr.clone() }
    }
}


impl Nexus {
    pub fn new()
    ->Result<Self>
    {
        let freq_ghz=measure_rdtsc_freq();

        let nexus_inner =Box::new(
            NexusInner{
                freq_ghz:freq_ghz,
                req_funcs:Box::new([None;REQ_TYPE_ARRAY_SIZE]),
                pad_:[0;64],
                req_func_registration_allowed:AtomicBool::new(true),
            }
        );

        let nexus=Self{
            ptr:Arc::new(Mutex::new(nexus_inner))
        };
        Ok(nexus)
    }
    pub fn freq_ghz(&self)->f64{
        self.ptr.lock().unwrap().freq_ghz
    }
    pub fn create_rpc(
        &self,
        client:bool,
        rpc_id:u8,
        txq:TxQueue,
        rxq:RxQueue,
        mp:Mempool,
        local_ipv4:Ipv4Addr, 
        local_port:u16, 
        local_mac:MacAddr,
        remote_ipv4:Ipv4Addr,
        remote_port:u16,
        remote_mac:MacAddr,
    )->Rpc{
        let nexus=self.ptr.lock().unwrap();
        let freq_ghz=nexus.freq_ghz;
        let rpc_rto_cycles=ms_to_cycles(RPC_REQUEST_TIMEOUT as f64, freq_ghz);
        let rpc_pkt_loss_scan_cycle = rpc_rto_cycles / 10;
        let mut sslot_arr:[Option<Rc<RefCell<SSlot>>>;SESSION_REQ_WINDOW]=unsafe{std::mem::zeroed()};
        let mut ctrl_msgbufs:[Option<MsgBuffer>;TTR_UNSIG_BATCH*2]=unsafe{std::mem::zeroed()};
        let mut sslot_free_vec=ArrayVec::new();
        for i in 0..SESSION_REQ_WINDOW {
            if client {
                sslot_arr[i]=Some(Rc::new(RefCell::new(
                    SSlot::client(i)
                )));
                sslot_free_vec.push(i);
            }
            else{
                sslot_arr[i]=Some(Rc::new(RefCell::new(
                    SSlot::server(i)
                )));
                sslot_free_vec.push(i);
            }
        } 

        for i in 0..TTR_UNSIG_BATCH*2{
            ctrl_msgbufs[i]=Some(MsgBuffer::ALLOCA_MSG(HEADER_LEN));
        }

        let req_funcs=nexus.req_funcs.clone();
        nexus.req_func_registration_allowed.store(false, Ordering::Relaxed);

        let rpc=Rpc {
            nexus:self.clone(),
            is_client:client,
            context:RpcContext::default(),
            rpc_id:rpc_id,
            txq:txq,
            rxq:rxq,
            mp:mp,
            local_ipv4:local_ipv4, 
            local_port:local_port, 
            local_mac:local_mac,
            remote_ipv4:remote_ipv4,
            remote_port:remote_port,
            remote_mac:remote_mac,
            freq_ghz:freq_ghz,
            ev_loop_tsc:0,
            pkt_loss_scan_tsc:0,
            rpc_pkt_loss_scan_cycles:rpc_pkt_loss_scan_cycle,
            rpc_rto_cycles:rpc_rto_cycles,
            credits:32,
            active_rpcs_tail_sentinel:Rc::new(RefCell::new(SSlot::client(0))),
            active_rpcs_head_sentinel:Rc::new(RefCell::new(SSlot::client(0))),
            sslot_free_vec:sslot_free_vec,
            enq_req_backlog:VecDeque::new(),
            req_funcs:req_funcs,
            sslot_arr:sslot_arr,
            stall_q:Vec::new(),
            rx_ring:ArrayVec::new(),
            tx_burst_batch:ArrayVec::new(),
            ctrl_msgbufs:ctrl_msgbufs,
            ctrl_msg_head:0,
            retrasmit_count:0,
            out_of_order:0,
            avg_tx:0,
            avg_deal:0,
            avg_trans:0,
        };
        let head=rpc.active_rpcs_head_sentinel.clone();
        let tail=rpc.active_rpcs_tail_sentinel.clone();
        rpc.active_rpcs_head_sentinel.borrow_mut().client_info_mut().unwrap().next=Some(tail);
        rpc.active_rpcs_tail_sentinel.borrow_mut().client_info_mut().unwrap().prev=Some(head);
        assert!(rpc.active_rpcs_head_sentinel.borrow().client_info().unwrap().prev.is_none());
        assert!(rpc.active_rpcs_tail_sentinel.borrow().client_info().unwrap().next.is_none());
        rpc
    }

    pub fn register_req_func(&mut self,req_type:u8,req_func:ReqFunc)->Result<()>{
        log::log!(log::Level::Trace,"Register a req handle function");
        let mut nexus=self.ptr.lock().unwrap();
        if nexus.req_func_registration_allowed.load(Ordering::Relaxed) {
            if nexus.req_funcs[req_type as usize].is_some() {
                return Err(Error::ReqFuncExisting);
            }
            nexus.req_funcs[req_type as usize]=Some(req_func);
            return Ok(());
        }
        return Err(Error::RegisterDisallow);
    }

}
