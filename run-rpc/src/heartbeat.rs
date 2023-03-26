/* use std::cmp::Ordering;
use std::collections::{
    binary_heap::BinaryHeap,
    HashMap
};

use packet::ipv4::Ipv4Addr;
use socket::wire::IpAddress;

use crate::session::SmPkt;
use crate::time::*;


/// A thread-safe heartbeat manager
///
/// It has two main task:
/// First, it sends heartbeat messages to remote process at fixed intervals
/// Second, it checks for timeouts, also at fixed intervals.
///
/// These tasks are scheduled using a time-based priority queue.
///
/// For efficiency, if a process has multiple sessions to a remote process, only one
/// instance of the remote URI is tracked
///
/// This heartbeat manger is designed to keep the CPU use of eRPC's management thread close to zero
/// in the steady state. An earlier version of eRPC's timeout detection
/// used a reliable UDP library called Enet, which had non-negligible CPU use.
pub struct HeartbeatMgr {
    hostname:IpAddress,
    sm_udp_port:u16,
    freq_ghz:f64,
    /// Time at which this manager was created
    creation_tsc:u64,
    /// Machine failure timeout in TSC cycles
    failure_timeout_tsc:u64,
    /// Send heartbeats every hb_send_delta_tsc cycles, this
    /// duration is around a tenth of the failure timeout
    hb_send_delta_tsc:u64,
    /// Check heartbeats every hb_check_delta_tsc cycles. This
    /// duration is around half of the failure timeout
    hb_check_delta_tsc:u64,

    hb_event_pqueue:BinaryHeap<Event>,

    /// This map servers two purposed:
    ///
    /// 1. Its value for a remote URI is the timestamp when we last receive a heartbeat from
    /// the remote URI
    ///
    /// 2. The set of remote URIs in the map is our remote tracking set. Since we
    /// cannot delete efficiently from the event priority queue, events for remote URIs not
    /// in this map are ignored when they are dequeued.
    map_last_hb_rx:HashMap<String,u64>,
    //hb_udp_client:UDPClient<SmPkt>,
}

#[repr(u8)]
enum EventType{
    Send,
    Check,
}

impl core::fmt::Display for EventType{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Check => write!(f,"check"),
            Self::Send => write!(f,"send")
        }
    }
}

pub struct Event{
    type_:EventType,
    rem_uri:String,
    tsc:u64,
}

impl core::cmp::PartialEq for Event {
    fn eq(&self, other: &Self) -> bool {
        self.tsc == other.tsc
    }
}

impl core::cmp::Eq for Event {

}

impl core::cmp::PartialOrd for Event {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        if self.tsc > other.tsc {
            Some(Ordering::Greater)
        }else if self.tsc == other.tsc {
            Some(Ordering::Equal)
        }else {
            Some(Ordering::Less)
        }
    }
}

impl core::cmp::Ord for Event{
    fn cmp(&self, other: &Self) -> Ordering {
        if self.tsc > other.tsc {
            Ordering::Greater
        }else if self.tsc == other.tsc {
            Ordering::Equal
        }else {
            Ordering::Less
        }
    }
}

impl HeartbeatMgr {
    pub(crate) fn new(hostname:IpAddress,sm_upd_port:u16,freq_ghz:f64,machine_failure_timeout_ms:u64)->Self{
        let failure_timeout_tsc=ms_to_cycles(machine_failure_timeout_ms as f64, freq_ghz);
        Self {
            hostname: hostname,
            sm_udp_port: sm_upd_port,
            freq_ghz: freq_ghz,
            creation_tsc: rdtsc(),
            failure_timeout_tsc:failure_timeout_tsc,
            hb_send_delta_tsc: failure_timeout_tsc/10,
            hb_check_delta_tsc: failure_timeout_tsc/2,
            hb_event_pqueue: BinaryHeap::new(),
            map_last_hb_rx: HashMap::new(),
            //hb_udp_client: UDPClient::new(),
        }
    }
    /// add a remote URI to the tracking set
    pub(crate) fn add_remote(&mut self, remote_uri:String){
        #[cfg(feature="Verbose")]
        {
            log::info!("heartbeat_mgr {} us: Starting tracking URI: {}",self.us_since_creation(rdtsc()),remote_uri)
        }

        let cur_tsc=rdtsc();
        self.map_last_hb_rx.insert(remote_uri.clone(), cur_tsc);
        self.schedule_hb_send(remote_uri.clone());
        self.schedule_hb_check(remote_uri.clone());
    }

    /* /// Receive a heartbeat
    pub(crate) fn receive_hb(&mut self,sm_pkt:&SmPkt){
        let client_uri=sm_pkt.client_uri();
        if !self.map_last_hb_rx.contains_key(&client_uri) {
            #[cfg(feature="Verbose")]
            {
                log::info!("heartbeat_mgr:{} us: Ignoring heartbeat from URI {}",
                    self.us_since_creation(rdtsc()),
                    client_uri
                );
            }
            return;
        }

        #[cfg(feature="Verbose")]
        {
            log::info!("heartbeat_mgr:{} us: Receiving heartbeat from URI {}",
                self.us_since_creation(rdtsc()),
                client_uri
            );
        }
        // update the value
        self.map_last_hb_rx.insert(client_uri, rdtsc());
    } */
    /// The main heartbeat work: Send heartbeats and check expired timers
    pub(crate) fn do_one(&mut self,failed_uris:&mut Vec<String>){
        loop{
            if self.hb_event_pqueue.is_empty() {
                break;
            }

            let next_ev = self.hb_event_pqueue.peek().unwrap();
            let cur_tsc=rdtsc();
            /// Stop processing the event queue when the top event is in the future
            if next_ev.tsc > cur_tsc {
                #[cfg(feature="Verbose")]
                {
                    log::info!("heartbeat_mgr {}us: Event {} is in the future",
                        self.us_since_creation(cur_tsc),
                        self.ev_to_string(next_ev)
                    );
                }
                break;
            }

            /// Why break?
            if !self.map_last_hb_rx.contains_key(&next_ev.rem_uri) {
                #[cfg(feature="Verbose")]
                {
                    log::info!(
                        "heartbeat_mgr:{}us:Remote URI for event {} is not in tracking set. Ignoring.",
                        self.us_since_creation(cur_tsc),
                        self.ev_to_string(next_ev)
                    );
                }
                break;
            }


            #[cfg(feature="Verbose")]
            {
                log::info!(
                    "heartbeat_mgr:{}us: Handling event {}",
                    self.us_since_creation(cur_tsc),
                    self.ev_to_string(next_ev)
                );
            }
            // consume the event
            let next_ev=self.hb_event_pqueue.pop().unwrap();

            match next_ev.type_ {
                EventType::Check => {
                    let last_ping_rx = self.map_last_hb_rx.get(&next_ev.rem_uri).unwrap();
                    if cur_tsc-last_ping_rx > self.failure_timeout_tsc {
                        failed_uris.push(next_ev.rem_uri.clone());
                        #[cfg(feature="Verbose")]
                        {
                            log::info!(
                                "heartbeat_mgr {}us: Remote URI {} failed",
                                self.us_since_creation(cur_tsc),
                                next_ev.rem_uri
                            );
                        }
                        self.map_last_hb_rx.remove(&next_ev.rem_uri);
                    }else{
                        self.schedule_hb_check(next_ev.rem_uri);
                    }
                    break;
                },
                EventType::Send => {
                    let heartbeat= self.make_heartbeat();
                    //self.hb_udp_client.send()
                    self.schedule_hb_send(next_ev.rem_uri);
                    break;
                }
            };

        }
    }
}

impl HeartbeatMgr {
    #[inline]
    fn us_since_creation(&self,tsc:u64)->f64{
        to_usec(tsc-self.creation_tsc, self.freq_ghz)
    }

    fn schedule_hb_send(&mut self,rem_uri:String){
        let e = Event{
            type_:EventType::Send,
            rem_uri:rem_uri,
            tsc:rdtsc()+self.hb_send_delta_tsc
        };

        #[cfg(feature="Verbose")]
        {
            log::info!("heartbeat_mgr {} us: Scheduling event: {}",self.us_since_creation(rdtsc()),self.ev_to_string(&e));
        }

        self.hb_event_pqueue.push(e);
    }

    fn schedule_hb_check(&mut self,rem_uri:String){
        let e = Event{
            type_:EventType::Check,
            rem_uri:rem_uri,
            tsc:rdtsc()+self.hb_check_delta_tsc
        };

        #[cfg(feature="Verbose")]
        {
            log::info!("heartbeat_mgr {} us: Scheduling event: {}",self.us_since_creation(rdtsc()),self.ev_to_string(&e));
        }

        self.hb_event_pqueue.push(e);
    }

    fn ev_to_string(&self,e:&Event)->String{
        format!("[Type:{},URI:{},time:{}us]",e.type_,e.rem_uri,self.us_since_creation(e.tsc))
    }

    fn make_heartbeat(&self)->SmPkt{
        unimplemented!()
    }
}

 */
