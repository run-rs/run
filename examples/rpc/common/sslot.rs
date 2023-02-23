use std::{cell::{RefCell}, rc::Rc};

use super::{msgbuffer::MsgBuffer, transport::RoutingInfo, rpc::Tag, constant::{SESSION_CREDITS, INVALID_REQ_TYPE}};


#[derive(Debug)]
pub struct SSlot{
    /// A preallocted msgbuf for single-packet responses
    pub pre_resp_msgbuf:MsgBuffer,
    pub(crate) index:usize,
    /// The request (client) or response (server) buffer. For client sslots, a
    /// non-null value indicates that the request is active/incomplete.
    pub(crate) tx_msgbuf:Option<MsgBuffer>,

    ///Info about the current request
    pub(crate) cur_req_num:usize,

    pub(crate) remote_routing_info:RoutingInfo,

    pub(crate) info:Info,
}



impl SSlot {
    pub fn client(index:usize)->Self{
        Self { 
            pre_resp_msgbuf: MsgBuffer::EMPTY(), 
            index: index, 
            tx_msgbuf: None, 
            cur_req_num: index, 
            remote_routing_info: RoutingInfo::default(), 
            info: Info::Client(ClientInfo::default()) 
        }
    }
    pub fn server(index:usize)->Self{
        Self { 
            pre_resp_msgbuf: MsgBuffer::EMPTY(), 
            index: index, 
            tx_msgbuf: None, 
            cur_req_num: index, 
            remote_routing_info: RoutingInfo::default(), 
            info: Info::Server(ServerInfo::default()) 
        }
    }

    pub fn is_client(&self)->bool{
        match self.info {
            Info::Client(_) => true,
            _ =>false,
        }
    }

    pub fn client_info_mut(&mut self)->Option<&mut ClientInfo>{
        match self.info {
            Info::Client(ref mut client)=>{
                Some(client)
            },
            _ => None
        }
    }

    pub fn server_info_mut(&mut self)->Option<&mut ServerInfo>{
        match self.info {
            Info::Server(ref mut server)=>{
                Some(server)
            },
            _ => None
        }
    }


    pub fn client_info(&self)->Option<&ClientInfo>{
        match self.info {
            Info::Client(ref client)=>{
                Some(client)
            },
            _ => None
        }
    }

    pub fn server_info(&self)->Option<& ServerInfo>{
        match self.info {
            Info::Server(ref server)=>{
                Some(server)
            },
            _ => None
        }
    }

    pub fn set_info(&mut self,info:Info){
        self.info=info
    }
}

#[derive(Debug)]
pub enum Info{
    Client(ClientInfo),
    Server(ServerInfo)
}

#[derive(Debug)]
pub struct ClientInfo{
    pub(crate) resp_msgbuf:Option<MsgBuffer>,
    pub(crate) cont_func:Option<fn(MsgBuffer)>,
    pub(crate) tag:Tag,
    pub(crate) tx_ts:[u64;SESSION_CREDITS],
    // Number of packets sent. Packets up to (num_tx -1) have been sent.
    pub(crate) num_tx:usize,
    pub(crate) num_rx:usize,
    pub(crate) progress_tsc:u64,
    pub(crate) prev:Option<Rc<RefCell<SSlot>>>,
    pub(crate) next:Option<Rc<RefCell<SSlot>>>,
}

impl Default for ClientInfo{
    fn default() -> Self {
        Self { 
            resp_msgbuf: None,
            cont_func:None,
            tag:Tag::default(),
            tx_ts:[0;SESSION_CREDITS],
            num_tx:0,
            num_rx:0,
            progress_tsc:0,
            prev:None,
            next:None
        }
    }
}

#[derive(Debug)]
pub struct ServerInfo{
    pub(crate)req_msgbuf:Option<MsgBuffer>,
    /// The request type. This is set to a valid value only while we are
    /// waiting for an enqueue_response(), from a foreground or a background
    /// thread. This property is needed to safely reset sessions, and it is
    /// difficult to establish with other members
    pub(crate)req_type:u8,
    pub(crate)num_rx:usize,
    pub(crate)sav_num_req_pkts:usize,
}

impl Default for ServerInfo{
    fn default() -> Self {
        Self { 
            req_msgbuf: None, 
            req_type: INVALID_REQ_TYPE as u8, 
            num_rx: 0, 
            sav_num_req_pkts: 0 
        }
    }
}
