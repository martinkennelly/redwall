#![no_std]
#![no_main]
#![allow(nonstandard_style, dead_code)]

use aya_bpf::{
    bindings::xdp_action,
    macros::{xdp,map},
    maps::{HashMap, PerfEventArray},
    programs::XdpContext,
};
use core::mem;
use memoffset::offset_of;

mod bindings;
use bindings::{ethhdr, iphdr};
use redwall_common::PacketLog;

const MAX_EVENT_ENTRIES: u32 = 1024;
const MAX_BLOCKLIST_ENTRIES: u32 = 1024;
const ETH_P_IP: u16 = 0x0800;
const ETH_HDR_LEN: usize = mem::size_of::<ethhdr>();

#[map(name = "EVENTS")]
static mut EVENTS: PerfEventArray<PacketLog> = PerfEventArray::<PacketLog>::with_max_entries(MAX_EVENT_ENTRIES,0);

#[map(name = "IPV4_BLOCKLIST")]
static mut BLOCKLIST: HashMap<u32, u32> = HashMap::<u32, u32>::with_max_entries(MAX_BLOCKLIST_ENTRIES, 0);

#[xdp(name="redwall")]
pub fn redwall(ctx: XdpContext) -> u32 {
    match unsafe { xdp_firewall(ctx) } {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

unsafe fn xdp_firewall(ctx: XdpContext) -> Result<u32, ()> {
    let h_proto = u16::from_be({
        *ptr_at(&ctx, offset_of!(ethhdr, h_proto))?
    });

    if h_proto != ETH_P_IP {
        return Ok(xdp_action::XDP_PASS);
    };

    let source = u32::from_be({
        *ptr_at(&ctx, ETH_HDR_LEN + offset_of!(iphdr, saddr))?
    });

    let action = if block_ip(source) {
        xdp_action::XDP_DROP
    } else {
        xdp_action::XDP_PASS
    };

    let log_event = PacketLog{
        ipv4_address: source,
        action: action,
    };
    
    EVENTS.output(&ctx, &log_event, 0);


    Ok(action)   
}

unsafe fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }
    Ok((start + offset) as *const T)
}

fn block_ip(address: u32) -> bool {
    unsafe { BLOCKLIST.get(&address).is_some()}
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
