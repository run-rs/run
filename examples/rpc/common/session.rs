



use std::fmt::Display;

use crate::transport::{RoutingInfo};
use byteorder::{NetworkEndian, ByteOrder};

#[derive(Debug,PartialEq, Eq)]
pub struct SmWorkItem {
    reset:bool,
    rpc_id:u8,
    sm_pk:SmPkt,
    reset_rem_hostname:String,
}

impl SmWorkItem{
    pub(crate) fn from_sm_pkt(rpc_id:u8,sm_pkt:SmPkt)->Self{
        Self { 
            reset: false, 
            rpc_id: rpc_id, 
            sm_pk: sm_pkt, 
            reset_rem_hostname: String::new() 
        }
    }

    pub(crate) fn sm_pkt(&self)->&SmPkt{
        &self.sm_pk
    }
}


pub(crate) type ConnReqUniqToken=u64;

mod field {
    use std::ops::Range;
    pub type Field=Range<usize>;
    pub const PKT_TYPE:Field =0..4;
    pub const ERR_TYPE:Field = 4..8;
    pub const UNIQ_TOKEN:Field = 8..16;
    pub const CLIENT_SESSION_NUM:Field=16..18;
    pub const SERVER_SESSION_NUM:Field=18..20;
    pub const CLIENT_RPC_ID:Field = 20..21;
    pub const SERVER_RPC_ID:Field =21..22;
    pub const CLIENT_UDP_PORT:Field=22..24;
    pub const SERVER_UDP_PORT:Field=24..26;
    pub const CLIENT_ROUTING_INFO:Field=26..74;
    pub const SERVER_ROUTING_INFO:Field=74 .. 122;
}


#[derive(Debug,PartialEq, Eq)]
// 120
pub struct SmPkt{
    buf_:[u8;128]
}



impl SmPkt{
    pub(crate) fn new()->Self{
        Self { buf_: unsafe{std::mem::zeroed()} }
    }

    pub(crate) fn buf(&self)->&[u8]{
        &self.buf_
    }

    pub(crate) fn buf_mut(&mut self)->&mut [u8]{
        &mut self.buf_
    }

    pub(crate) const fn buffer_len()->usize{
        128
    }

    pub(crate) fn set_pkt_type(&mut self,pkt_type:SmPktType){
        NetworkEndian::write_i32(
            &mut self.buf_[field::PKT_TYPE],
            pkt_type.into());
    }

    pub(crate) fn get_pkt_type(&self)->SmPktType {
        NetworkEndian::read_i32(&self.buf_[field::PKT_TYPE]).into()
    }

    pub(crate) fn set_err_type(&mut self,err_type:SmErrType){
        NetworkEndian::write_i32(
            &mut self.buf_[field::ERR_TYPE], 
            err_type.into());
    }

    pub(crate) fn get_err_type(&self)->SmErrType{
        NetworkEndian::read_i32(&self.buf_[field::ERR_TYPE]).into()
    }

    pub(crate) fn set_uniq_token(&mut self,uniq_token:u64){
        NetworkEndian::write_u64(&mut self.buf_[field::UNIQ_TOKEN], uniq_token)
    }

    pub(crate) fn get_uniq_token(&self)->u64{
        NetworkEndian::read_u64(&self.buf_[field::UNIQ_TOKEN])
    }

    pub(crate) fn set_client_info(&mut self,sep:&SessionEndpoint){
        (self.buf_[field::CLIENT_RPC_ID.start])=sep.rpc_id;
        NetworkEndian::write_u16(&mut self.buf_[field::CLIENT_SESSION_NUM], sep.session_num);
        NetworkEndian::write_u16(&mut self.buf_[field::CLIENT_UDP_PORT], sep.sm_udp_port);
        let _ = &mut self.buf_[field::CLIENT_ROUTING_INFO].copy_from_slice(sep.routing_info.buf());
    }

    pub(crate) fn set_server_info(&mut self,sep:&SessionEndpoint){
        (self.buf_[field::SERVER_RPC_ID.start])=sep.rpc_id;
        NetworkEndian::write_u16(&mut self.buf_[field::SERVER_SESSION_NUM], sep.session_num);
        NetworkEndian::write_u16(&mut self.buf_[field::SERVER_UDP_PORT], sep.sm_udp_port);
        let _ = &mut self.buf_[field::SERVER_ROUTING_INFO].copy_from_slice(sep.routing_info.buf());
    }

    pub(crate) fn set_client_rpc_id(&mut self,rpc_id:u8){
        self.buf_[field::CLIENT_RPC_ID.start]=rpc_id;
    }

    pub(crate) fn get_client_rpc_id(&self)->u8{
        self.buf_[field::CLIENT_RPC_ID.start]
    }

    pub(crate) fn set_server_rpc_id(&mut self,rpc_id:u8){
        self.buf_[field::SERVER_RPC_ID.start]=rpc_id;
    }

    pub(crate) fn get_server_rpc_id(&self)->u8{
        self.buf_[field::SERVER_RPC_ID.start]
    }

    pub(crate) fn set_client_session(&mut self,session:u16){
        NetworkEndian::write_u16(&mut self.buf_[field::CLIENT_SESSION_NUM], session)
    }

    pub(crate) fn set_server_session(&mut self,session:u16){
        NetworkEndian::write_u16(&mut self.buf_[field::SERVER_SESSION_NUM], session)
    }

    pub(crate) fn get_client_session(&self)->u16{
        NetworkEndian::read_u16(&self.buf_[field::CLIENT_SESSION_NUM])
    }

    pub(crate) fn get_server_session(&self)->u16{
        NetworkEndian::read_u16(&self.buf_[field::SERVER_SESSION_NUM])
    }

    pub(crate) fn set_client_sm_udp_port(&mut self,sm_udp_port:u16){
        NetworkEndian::write_u16(&mut self.buf_[field::CLIENT_UDP_PORT], sm_udp_port);
    }

    pub(crate) fn set_server_sm_udp_port(&mut self,sm_udp_port:u16){
        NetworkEndian::write_u16(&mut self.buf_[field::SERVER_UDP_PORT], sm_udp_port);
    }

    pub(crate) fn get_server_sm_udp_port(&self)->u16{
        NetworkEndian::read_u16(&self.buf_[field::SERVER_UDP_PORT])
    }
    pub(crate) fn get_client_sm_udp_port(&self)->u16{
        NetworkEndian::read_u16(&self.buf_[field::CLIENT_UDP_PORT])
    }

    pub(crate) fn set_client_routing_info(&mut self,routing_info:&RoutingInfo){
        self.buf_[field::CLIENT_ROUTING_INFO].copy_from_slice(routing_info.buf())
    }

    pub(crate) fn get_client_routing_info(&self)->&[u8]{
        &self.buf_[field::CLIENT_ROUTING_INFO]
    }

    pub(crate) fn set_server_routing_info(&mut self,routing_info:&RoutingInfo){
        self.buf_[field::SERVER_ROUTING_INFO].copy_from_slice(routing_info.buf())
    }

    pub(crate) fn get_server_routing_info(&self)->&[u8]{
        &self.buf_[field::SERVER_ROUTING_INFO]
    }

    pub(crate) fn is_req(&self)->bool{
        match self.get_pkt_type() {
            SmPktType::ConnectReq |
            SmPktType::DisconnectReq |
            SmPktType::PingReq =>true,
            _ =>false
        }
    }

    pub(crate) fn is_unkown(&self)->bool{
        match self.get_pkt_type() {
            SmPktType::Unkown(_) =>true,
            _ =>false
        }
    }

    pub(crate) fn is_resp(&self)->bool{
        match self.get_pkt_type() {
            SmPktType::ConnectResp |
            SmPktType::DisconnectResp |
            SmPktType::PingResp =>true,
            _ =>false
        }
    }

    pub(crate) fn pkt_type_req_to_resp(&self)->SmPktType{
        match self.get_pkt_type() {
            SmPktType::ConnectReq =>SmPktType::ConnectResp,
            SmPktType::DisconnectReq => SmPktType::DisconnectResp,
            SmPktType::PingReq => SmPktType::PingResp,
            _ => SmPktType::Unkown(0)
        }
    }

    pub(crate) fn construct_resp(&self,err_type:SmErrType)->Self{
        let mut resp_sm_pkt=Self::new();
        resp_sm_pkt.set_pkt_type(self.pkt_type_req_to_resp());
        resp_sm_pkt.set_err_type(err_type);
        resp_sm_pkt
    }

}


impl Display for SmPkt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f,"PKT_TYPE: {}",self.get_pkt_type())?;
        writeln!(f,"ERR_TYPE: {}", self.get_err_type())?;
        writeln!(f,"UNIQ_TOKEN: {}",self.get_uniq_token())?;
        writeln!(f,"CLIENT_INFO \n")?;
        writeln!(f,"    SM_UDP_PORT:{}",self.get_client_sm_udp_port())?;
        writeln!(f,"    SESSION_NUM:{}",self.get_client_session())?;
        writeln!(f,"    RPC_ID:{}",self.get_client_rpc_id())?;
        writeln!(f,"SERVER_INFO \n")?;
        writeln!(f,"    SM_UDP_PORT:{}",self.get_server_sm_udp_port())?;
        writeln!(f,"    SESSION_NUM:{}",self.get_server_session())?;
        writeln!(f,"    RPC_ID:{}",self.get_server_rpc_id())
    }
}

#[derive(Debug,PartialEq, Eq)]
pub enum SmPktType {
    /// Unblock the session management request blocked on recv()
    Unblock, 
    /// Heartbeat ping request
    PingReq,
    /// Heartbeat ping response
    PingResp,
    /// Request to connect an eRPC session
    ConnectReq,
    /// Response for the eRPC session connection request
    ConnectResp,
    /// Request to disconnect an eRPC session
    DisconnectReq,
    /// Response for the eRPC session disconnect request
    DisconnectResp,
    /// Unkown Type
    Unkown(i32),
}

impl Display for SmPktType{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unblock=> write!(f,"Unblock"),
            Self::PingReq=>write!(f,"PingReq"),
            Self::PingResp=>write!(f,"PingResp"),
            Self::ConnectReq=>write!(f,"ConnectReq"),
            Self::ConnectResp=>write!(f,"ConnectResp"),
            Self::DisconnectReq=>write!(f,"DisconnectReq"),
            Self::DisconnectResp=>write!(f,"DisconnectResp"),
            Self::Unkown(v)=>write!(f,"Unkown: {}",v)
        }
    }
}

impl From<i32> for SmPktType {
    fn from(v: i32) -> Self {
        match v {
            1 => Self::Unblock,
            2=> Self::PingReq,
            3=>Self::PingResp,
            4 => Self::ConnectReq,
            5 => Self::ConnectResp,
            6 => Self::DisconnectReq,
            7 => Self::DisconnectResp,
            _ => Self::Unkown(v)
        }
    }
}

impl Into<i32> for SmPktType {
    fn into(self) -> i32 {
        match self {
            Self::Unblock=>1,
            Self::PingReq=>2,
            Self::PingResp=>3,
            Self::ConnectReq=>4,
            Self::ConnectResp=>5,
            Self::DisconnectReq=>6,
            Self::DisconnectResp=>7,
            Self::Unkown(v)=>v
        }
    }
}


#[derive(Debug,PartialEq, Eq)]
pub enum SmErrType {
    NoError,
    SrvDisconnected,
    RingExhuasted,
    OutOfMemory,
    RoutingResolutionFailure,
    InvalidRemoteRpcId,
    InvalidTransport
}
impl Display for SmErrType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SrvDisconnected=>write!(f,"SrvDisconnected"),
            Self::RingExhuasted=>write!(f,"RingExhuasted"),
            Self::OutOfMemory=>write!(f,"OutOfMemory"),
            Self::RoutingResolutionFailure=>write!(f,"RoutingResolutionFailure"),
            Self::InvalidRemoteRpcId=>write!(f,"InvalidRemoteRpcId"),
            Self::InvalidTransport=>write!(f,"InvalidTransport"),
            Self::NoError=>write!(f,"NoError")
        }
    }
}

impl From<i32> for SmErrType{
    fn from(v: i32) -> Self {
        match v {
            1 => Self::SrvDisconnected,
            2 => Self::RingExhuasted,
            3 => Self::OutOfMemory,
            4 => Self::RoutingResolutionFailure,
            5 => Self::InvalidRemoteRpcId,
            6 => Self::InvalidTransport,
            _ => Self::NoError
        }
    }
}

impl Into<i32> for SmErrType {
    fn into(self) -> i32 {
        match self {
            Self::SrvDisconnected=>1,
            Self::RingExhuasted=>2,
            Self::OutOfMemory=>3,
            Self::RoutingResolutionFailure=>4,
            Self::InvalidRemoteRpcId=>5,
            Self::InvalidTransport=>6,
            Self::NoError=>0
        }
    }
}

#[derive(Debug,Default,PartialEq, Eq)]
pub(crate) struct SessionEndpoint{
    sm_udp_port:u16, 
    rpc_id:u8,
    session_num:u16,
    routing_info:RoutingInfo, // 48 bytes
}

pub(crate) struct Session{
    client:bool,
    uniq_token:ConnReqUniqToken,
    freq_ghz:f64,

}

#[cfg(test)]
mod test{
    use super::*;

    #[test]
    fn smpkt_bytes_conversion_test(){
        
    }
}
