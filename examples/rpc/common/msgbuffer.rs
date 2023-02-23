use std::{ptr::NonNull, cell::{RefCell}, rc::Rc, alloc::{Layout, alloc_zeroed,dealloc}, fmt::Display};

use bytes::Buf;
use log::trace;
use run_packet::{ether::ETHER_HEADER_LEN, udp::UDP_HEADER_LEN, ipv4::IPV4_HEADER_LEN, PktBuf, PktMut, CursorMut};

use super::constant::TTR_MAX_DATA_PER_PKT;

//use crate::hugealloc::Buffer;


pub const RPC_HEADER_LEN:usize=std::mem::size_of::<RpcHeader>()-42;
pub const HEADER_LEN:usize=ETHER_HEADER_LEN+UDP_HEADER_LEN+IPV4_HEADER_LEN+RPC_HEADER_LEN;






mod field {
    type Filed=std::ops::Range<usize>;
    //pub const HEADROOM:Filed=0..42;
    pub const REQ_TYPE:Filed=0..4; 
    pub const REQ_TYPE_MASK:u32=0xff;
    pub const MSG_SIZE:Filed=0..4;
    pub const MSG_SIZE_MASK:u32=0xffffff00;
    pub const MSG_SIZE_SHIFT:usize = 8;
    pub const DEST_SESSION_NUM:Filed=4..6;
    pub const PKT_TYPE:Filed = 6..14;
    pub const PKT_TYPE_MASK:u64=0x3;
    pub const PKT_NUM:Filed = 6..14;
    pub const PKT_NUM_MASK:u64=0xFFFC;
    pub const PKT_NUM_MASK_SHIFT:usize=2;
    pub const REQ_NUM:Filed = 6..14;
    pub const REQ_NUM_SHIFT:usize=16;
    pub const REQ_NUM_MASK:u64=0xFFFFFFFFFFF0000;
    // Magic from alloc_msg_buffer
    pub const MAGIC_SHIFT:usize=60;
}

#[derive(Debug,PartialEq, Eq,Clone, Copy)]
#[repr(u8)]
pub enum PktType{
    Req=0u8,
    RFR=1,
    ExplCR=3,
    Resp=4
}

impl Display for PktType{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ExplCR => write!(f,"ExplCR"),
            Self::RFR => write!(f,"RFR"),
            Self::Req => write!(f,"Req"),
            Self::Resp => write!(f,"Resp"),
        }
    }
}

#[repr(transparent)]
#[derive(Debug)]
pub struct MsgBuffer(Rc<RefCell<MsgBufferInner>>);
#[derive(Debug)]
struct MsgBufferInner{
    buf:Option<NonNull<u8>>,
    data_size:usize,
    max_data_size:usize, // multiple seg size
    max_num_pkts:usize,
    num_pkts:usize, 
    layout:Option<Layout>
}

impl Drop for MsgBufferInner{
    fn drop(&mut self) {
        if let Some(layout)=self.layout{
            assert!(self.buf.is_some());
            unsafe{
                dealloc(self.buf.unwrap().as_ptr().sub(HEADER_LEN), layout);
            }
        }
    }
}



impl MsgBuffer {
    #[allow(non_snake_case)]
    pub fn EMPTY()->Self{
        Self(
            Rc::new(RefCell::new(
                MsgBufferInner{
                    buf:None,
                    data_size:0,
                    max_data_size:0,
                    num_pkts:0,
                    max_num_pkts:0,
                    layout:None,
                }
            ))
        )
    }

    pub fn data_size_to_num_pkts(max_data_size:usize)->usize{
        if max_data_size<=TTR_MAX_DATA_PER_PKT{
            return 1;
        }
        else{
            (max_data_size+TTR_MAX_DATA_PER_PKT-1)/TTR_MAX_DATA_PER_PKT
        }
    }

    #[allow(non_snake_case)]
    pub fn ALLOCA_MSG(max_data_size:usize)->Self{
        assert!(max_data_size>0);
        let max_num_pkts=Self::data_size_to_num_pkts(max_data_size);
        let buf_size=max_data_size+(max_num_pkts*HEADER_LEN);
        let layout=Layout::from_size_align(buf_size, 64).unwrap();
        let buf_ptr=unsafe{NonNull::new_unchecked(alloc_zeroed(layout.clone()))};
        Self(
            Rc::new(RefCell::new(
                MsgBufferInner{
                    buf:unsafe{
                        Some(NonNull::new_unchecked(buf_ptr.as_ptr().add(HEADER_LEN)))
                    },
                    data_size:max_data_size,
                    max_data_size:max_data_size,
                    num_pkts:max_num_pkts,
                    max_num_pkts:max_num_pkts,
                    layout:Some(layout),
                }
            ))
        )
    }

    pub fn is_buried(&self)->bool{
        self.0.borrow().buf.is_none()
    }

    pub fn copy_data_from_buf<T:PktBuf>(&mut self,buf:&mut T,pkt_idx:usize){
        //println!("buf remaining {}",buf.remaining());
        assert!(buf.remaining() <= TTR_MAX_DATA_PER_PKT);
        let offset=pkt_idx*TTR_MAX_DATA_PER_PKT;
        let ptr=unsafe{
            self.0.borrow_mut().buf.as_mut().unwrap().as_ptr().add(offset)
        };
        let slice = unsafe{
            std::slice::from_raw_parts_mut(ptr, buf.remaining())
        };
        let mut dst_buf=CursorMut::new(slice);
        while buf.has_remaining() {
            let size=buf.chunk().len();
            dst_buf.chunk_mut()[0..size].copy_from_slice(buf.chunk());
            dst_buf.advance(size);
            buf.advance(size);
        }
    }
    pub unsafe fn from_pkthdr(header:&RpcHeader,max_data_size:usize)->Self{
        Self(
            Rc::new(RefCell::new(
                MsgBufferInner{
                    buf:Some(NonNull::new_unchecked((header as *const _ as *mut u8).add(HEADER_LEN))),
                    data_size:max_data_size,
                    max_data_size:max_data_size,
                    num_pkts:1,
                    max_num_pkts:1,
                    layout:None,
                }
            ))
        )
    }

    pub fn resize_msg_buffer(&mut self,new_data_size:usize){
        assert!(new_data_size<=self.0.borrow().max_data_size);
        let new_num_pkts= if new_data_size <= TTR_MAX_DATA_PER_PKT {
            1
        }else{
            (new_data_size + TTR_MAX_DATA_PER_PKT -1 ) / TTR_MAX_DATA_PER_PKT
        };
        self.0.borrow_mut().data_size=new_data_size;
        self.0.borrow_mut().num_pkts=new_num_pkts;
        trace!("Resize msg buffer: new data size :{} new num pkts:{}",new_data_size,(new_data_size + TTR_MAX_DATA_PER_PKT -1 ) / TTR_MAX_DATA_PER_PKT);
    }
    pub unsafe fn buried_buf(&self){
        self.0.borrow_mut().buf=None;
    }
    pub fn num_pkts(&self)->usize{
        self.0.borrow().num_pkts
    }

    pub fn data_size(&self)->usize{
        self.0.borrow().data_size
    }

    pub fn get_pkthdr_0(&self)->&mut RpcHeader{
        unsafe{
            &mut *(self.0.borrow_mut().buf.as_ref().unwrap().as_ptr().sub(HEADER_LEN) as *mut RpcHeader)
        }  
    }

    pub fn get_pkthdr_n(&self,idx:usize)->&mut RpcHeader{
        if idx==0 {
            return self.get_pkthdr_0()
        }
        unsafe{
            let max_data_size=self.0.borrow().max_data_size;

            let offset=self.0.borrow_mut().buf.as_ref()
                .unwrap().as_ptr().add(max_data_size + (idx-1)*HEADER_LEN);
            &mut *(offset as *mut RpcHeader)
        }
    }

    pub fn get_buf_n<'a>(&'a self,idx:usize)->MsgSegBuffer<'a> {
        assert!(idx < self.0.borrow().num_pkts);
        assert!(!self.is_buried());
        let offset=TTR_MAX_DATA_PER_PKT*idx;
        let buf_len=if idx +1 < self.0.borrow().num_pkts {
            TTR_MAX_DATA_PER_PKT
        }else{
            self.data_size() - offset
        };
        assert!(buf_len<=TTR_MAX_DATA_PER_PKT);
        let buf=unsafe{
            std::slice::from_raw_parts_mut(
                self.0.borrow().buf.unwrap().as_ptr().add(offset), 
                buf_len)
        };
        
        let header =if idx == 0 {
            unsafe{
                std::slice::from_raw_parts_mut(
                    self.0.borrow().buf.as_ref().unwrap().as_ptr().sub(HEADER_LEN), 
                    HEADER_LEN)
            }  
        }else{
            unsafe{
                let max_data_size=self.0.borrow().max_data_size;

                let offset=self.0.borrow().buf.as_ref()
                    .unwrap().as_ptr().add(max_data_size + (idx-1)*HEADER_LEN);
            
            std::slice::from_raw_parts_mut(
                    offset, 
                    HEADER_LEN)
            }
        };
        MsgSegBuffer { 
            header: header, 
            buf: buf, 
            cursor: 0 
        }
    }

    
}




pub struct MsgSegBuffer<'a>{
    header:&'a mut [u8],
    buf:&'a mut  [u8],
    cursor:usize,
}

impl<'a> Buf for MsgSegBuffer<'a>{
    fn advance(&mut self, cnt: usize) {
        let cnt=std::cmp::min(cnt, self.remaining());
        self.cursor+=cnt;
    }

    fn remaining(&self) -> usize {
        self.buf.len()+self.header.len() - self.cursor
    }

    fn chunk(&self) -> &[u8] {
        if self.cursor < self.header.len() {
            &self.header[self.cursor..]
        }
        else{
            &self.buf[self.cursor-self.header.len()..]
        }
    }
}

impl<'a> PktBuf for MsgSegBuffer<'a> {
    fn move_back(&mut self, cnt: usize) {
        self.cursor-=std::cmp::min(cnt,self.cursor);
    }

    fn trim_off(&mut self, cnt: usize) {
        assert!(cnt <=self.remaining());
        if cnt+self.cursor <= self.header.len() {
            self.header=unsafe{
                std::slice::from_raw_parts_mut(self.header.as_mut_ptr(), cnt+self.cursor)
            };
            self.buf=&mut [];
        }
        else {
            self.buf=unsafe{
                std::slice::from_raw_parts_mut(self.buf.as_mut_ptr(), cnt+self.cursor-self.header.len())
            };
        }
    }
}

impl<'a> PktMut for MsgSegBuffer<'a> {
    fn chunk_headroom(&self) -> usize {
        self.cursor
    }

    fn chunk_mut(&mut self) -> &mut [u8] {
        if self.cursor < self.header.len() {
            &mut self.header[self.cursor..]
        }
        else{
            &mut self.buf[self.cursor-self.header.len()..]
        }
    }
}



impl Clone for MsgBuffer{
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}



#[derive(Debug,Clone, Copy)]
#[repr(C)]
/// PktHeader: 42 + 4 +2 + 8 = 56
pub struct RpcHeader{
    headroom:[u8;42],
    req_type:u8,
    msg_size:u32,
    req_num:u64,
    pkt_num:u16,
    magic:u8,
    pkt_type:PktType
}


impl RpcHeader{
    pub fn headroom_mut(&mut self)->&mut [u8]{
        &mut self.headroom[..]
    }
    pub fn buf(&self)->&[u8]{
        unsafe{
            std::slice::from_raw_parts(
                self.headroom.as_ptr().add(42), 
                RPC_HEADER_LEN)
        }
    }
    pub fn buf_mut(&mut self)->&mut [u8]{
        unsafe{
            std::slice::from_raw_parts_mut(
                self.headroom.as_mut_ptr().add(42), 
                RPC_HEADER_LEN)
        }
    }
    pub fn new()->Self{
        unsafe{
            std::mem::zeroed()
        }
    }
    pub fn from_slice(slice:&[u8])->Self{
        let mut headroom=[0;42];
        headroom.copy_from_slice(&slice[0..42]);
        let mut ret=Self::new();
        ret.headroom=headroom;
        ret.buf_mut().copy_from_slice(&slice[42..std::mem::size_of::<Self>()]);
        ret
    }
    pub fn req_type(&self)->u8{
        self.req_type
    }

    pub fn msg_size(&self)->u32{
        self.msg_size
    }

    pub fn req_num(&self)->u64{
        self.req_num
    }

    pub fn pkt_num(&self)->u16{
        self.pkt_num
    }

    pub fn magic(&self)->u8{
        self.magic
    }

    pub fn pkt_type(&self)->PktType{
        self.pkt_type
    }

    pub fn set_pkt_type(&mut self,pkt_type:PktType){
        self.pkt_type = pkt_type
    }


    pub fn set_req_type(&mut self,req_type:u8){
        self.req_type=req_type
    }

    pub fn set_msg_size(&mut self,msg_size:u32){
        self.msg_size=msg_size
    }

    pub fn set_req_num(&mut self,req_num:u64){
        self.req_num=req_num
    }

    pub fn set_magic(&mut self,maigc:u8){
        self.magic=maigc
    }

    pub fn set_pkt_num(&mut self,pkt_num:u16){
        self.pkt_num=pkt_num
    } 
}

impl Display for RpcHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f,"REQ_TYPE: {}",self.req_type())?;
        writeln!(f,"MSG_SIZE: {}",self.msg_size())?;
        writeln!(f,"REQ_NUM: {}",self.req_num())?;
        writeln!(f,"PKT_NUM: {}",self.pkt_num())?;
        writeln!(f,"PKT_TYPE:{}",self.pkt_type())
    }
}


pub struct RpcPkt<T>{
    buf:T
}

impl<T:PktBuf> RpcPkt<T>{
    
    pub  fn parse(buf:T)->Self{
        assert!(buf.remaining() >=HEADER_LEN);
        Self { buf: buf }
    }

    pub fn payload(mut self)->T{
        self.buf.advance(HEADER_LEN);
        self.buf
    }

    pub fn owned_header(&self)->RpcHeader{
        let mut ret=RpcHeader::new();
        ret.buf_mut().copy_from_slice(&self.buf.chunk()[0..RPC_HEADER_LEN]);
        ret
    }
}

#[cfg(test)]
mod test{
    use super::*;

    #[test]
    fn rpc_header_api_test(){
        let mut msg_buf=MsgBuffer::ALLOCA_MSG(HEADER_LEN);
        let pkt_hdr=msg_buf.get_pkthdr_0();
        pkt_hdr.set_magic(11);
        assert_eq!(pkt_hdr.magic(),11);
        pkt_hdr.set_msg_size(102);
        assert_eq!(pkt_hdr.msg_size(),102);
        pkt_hdr.set_pkt_num(133);
        assert_eq!(pkt_hdr.pkt_num(),133);
        pkt_hdr.set_pkt_type(PktType::RFR);
        assert_eq!(pkt_hdr.pkt_type(),PktType::RFR);
        pkt_hdr.set_req_num(15);
        assert_eq!(pkt_hdr.req_num(),20);
        pkt_hdr.set_req_type(2);
        assert_eq!(pkt_hdr.req_type(),2);

        let pkt_hdr=msg_buf.get_pkthdr_n(0);
        assert_eq!(pkt_hdr.magic(),11);
        assert_eq!(pkt_hdr.msg_size(),102);
        assert_eq!(pkt_hdr.pkt_num(),133);
        assert_eq!(pkt_hdr.pkt_type(),PktType::RFR);
        assert_eq!(pkt_hdr.req_num(),20);
        assert_eq!(pkt_hdr.req_type(),2);
    }
}