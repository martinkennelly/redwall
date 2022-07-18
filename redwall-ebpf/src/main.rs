#![no_std]
#![no_main]
#![allow(nonstandard_style, dead_code)]
use core::mem;
use memoffset::offset_of;

use redwall_common::PacketLog;

use aya_bpf::{
    bindings::xdp_action,
    macros::{xdp,map},
    maps::{PerfEventArray, LpmTrie, lpm_trie::Key},
    programs::XdpContext, helpers::bpf_loop,
};
mod bindings;
use bindings::{ethhdr, iphdr, tcphdr};


const MAX_EVENT_ENTRIES: u32 = 1024;
const MAX_BLOCKLIST_ENTRIES: u32 = 1024;
const ETH_P_IP: u16 = 0x0800;
const ETH_HDR_LEN: usize = mem::size_of::<ethhdr>();

const L3_OFF: usize = ETH_HDR_LEN;
const L4_OFF: usize = L3_OFF + mem::size_of::<iphdr>();
const L7_OFF: usize = L4_OFF + mem::size_of::<tcphdr>();


#[map(name = "EVENTS")]
static mut EVENTS: PerfEventArray<PacketLog> = PerfEventArray::<PacketLog>::with_max_entries(MAX_EVENT_ENTRIES,0);

#[map(name = "IPV4_BLOCKLIST")]
static mut BLOCKLIST: LpmTrie<u32, [redwall_common::Rules; redwall_common::RULES_MAX_SIZE]> = LpmTrie::<u32, [redwall_common::Rules; redwall_common::RULES_MAX_SIZE]>::with_max_entries(MAX_BLOCKLIST_ENTRIES, 1);

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

    let source_ip_address = u32::from_be({
        *ptr_at(&ctx, L3_OFF + offset_of!(iphdr, saddr))?
    });

    let protocol = u8::from_be({
        *ptr_at(&ctx, L3_OFF + offset_of!(iphdr, protocol))?
    });

    let protocol = match protocol {
        1 => redwall_common::Protocol::ICMP,
        6 => redwall_common::Protocol::TCP,
        17 => redwall_common::Protocol::UDP,
        _ => redwall_common::Protocol::Unsupported,
    };

    let dest_port = u16::from_be({
        *ptr_at(&ctx, L4_OFF + offset_of!(tcphdr, dest))?
    });

    let action = if is_blocked(source_ip_address, protocol, dest_port) {
        xdp_action::XDP_DROP
    } else {
        xdp_action::XDP_PASS
    };

    let log_event = PacketLog{
        ipv4_address: source_ip_address,
        protocol: protocol,
        action: action,
        dest_port: dest_port.try_into().unwrap(),
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

fn is_blocked(source_addr: u32, protocol: redwall_common::Protocol, dest_port: u16) -> bool {    
    let key = Key::new(32, source_addr.to_be());
    unsafe {
        let rules = BLOCKLIST.get(&key);

        if rules.is_none() {
            // didn't find any entry so we allow by default
            return false;
        }

        for rule in rules.unwrap() {
            // we need this ugly valid check because we must know at compile time the size of the array
            //TODO(mk): investigate a linked list or other data struct that we don't need to know at compile time
            if !rule.valid {
                continue;
            }

            if rule.proto != protocol {
                continue;
            }

            let mut empty_port_count = 0;
            let mut found = false;
            for port in rule.dest_port {
                if port == dest_port {
                    found = true;
                    break;
                }
                // we assume any ports that are zero are invalid and they represent null or not a port. If all elements in array are 0, no ports were defined.
                if port == redwall_common::EMPTY_PORT {
                    empty_port_count += 1;
                }
            }
            if !found && empty_port_count != rule.dest_port.len() {
                continue;
            }

            if rule.action == redwall_common::Action::Deny {
                return true;
            }

            if rule.action == redwall_common::Action::Allow {
                return false;
            }
        }
    };

    //allow by default
    false
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
