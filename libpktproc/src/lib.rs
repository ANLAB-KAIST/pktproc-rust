extern crate libc;
use libc::*;
use std::slice;
use std::mem;
use std::cell::RefCell;

#[repr(C)]
struct PortInfo {
    port_id: u16,
    mac_addr: [u8; 6],
}

struct Context<'a> {
    thread_id: u64,
    installed_ports: &'a [PortInfo],
}

#[repr(C)]
struct Packet {
//struct rte_mbuf
    //cacheline0

    buf_addr: *mut u8,
    buf_physaddr: u64,
    buf_len: u16,

    //rearm_data: u8,

    data_off: u16,
    refcnt: u16,
    nb_segs: u8,
    port: u8,

    ol_flags: u64,

    //rx_desc_fields

    packet_type: u16,
    data_len: u16,
    pkt_len: u32,
    vlan_tci: u16,
    reserved: u16,

    hash: u64,

    seqn: u32,

    //cacheline1

    userdata: u64,

    pool: *mut u8,  // struct rte_mempool*
    next: *mut u8,  // struct rte_mbuf*

    tx_offload: u64,

    priv_size: u16,

    _unused0: u64,
    _unused1: u64,
    _unused2: u64,

//struct Packet
    result: i32,
}

#[repr(packed)]
struct EthernetPacket {
    dst_mac: [u8; 6],
    src_mac: [u8; 6],
    proto:   u16,
}

impl EthernetPacket {
    pub fn from_packet(p: &Packet) -> &mut EthernetPacket {
        unsafe { mem::transmute(p.buf_addr.offset(p.data_off as isize)) }
    }
}

thread_local!(static CONTEXT: RefCell<Option<Context<'static>>> = RefCell::new(None));

#[no_mangle]
pub extern fn pktproc_init(thread_id: u64, raw_ports: *mut libc::c_void, port_count: u32) {
    let ports: &[PortInfo] = unsafe {
        mem::transmute(slice::from_raw_parts_mut(raw_ports, port_count as usize))
    };
    CONTEXT.with(|ref ctx| {
        let mut ctx = ctx.borrow_mut();
        if ctx.is_none() {
            *ctx = Some(Context {
                thread_id: thread_id,
                installed_ports: ports,
            });
        }
    });
}

#[no_mangle]
pub extern fn pktproc_process(thread_id: u64, packets: *mut *mut libc::c_void, count: u32) {
    CONTEXT.with(|ref context| {
        if let Some(ref ctx) = *context.borrow() {
            assert_eq!(ctx.thread_id, thread_id);
            let pkts: &mut [&mut Packet] = unsafe {
                mem::transmute(slice::from_raw_parts_mut(packets, count as usize))
            };
            for p in pkts {
                let mut result = -1i32;
                {
                    let ethh = EthernetPacket::from_packet(p);
                    if ethh.dst_mac[0] & 0x01 == 0 {  // if unicast address
                        ethh.dst_mac = ethh.src_mac;
                        ethh.src_mac = ctx.installed_ports[p.port as usize].mac_addr;
                        result = p.port as i32
                    }
                }
                (*p).result = result;
            }
        };
    });
}
