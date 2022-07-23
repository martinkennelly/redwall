#![no_std]
#![no_main]
#![allow(nonstandard_style, dead_code)]
use core::mem;
use memoffset::offset_of;

use redwall_common::{PacketLog, FALSE};

use aya_bpf::{
    bindings::xdp_action,
    macros::{xdp,map},
    maps::{PerfEventArray, LpmTrie, lpm_trie::Key},
    programs::XdpContext, helpers::bpf_ktime_get_ns,
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
    let start = bpf_ktime_get_ns();

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

    let mut action = xdp_action::XDP_DROP;
    let mut prefix_hit = 32;
    for prefix_len in (0..33).rev() {
        prefix_hit = prefix_len;
        if let Some(v) = is_allowed(prefix_len, source_ip_address, protocol, dest_port) {
            if v {
                action = xdp_action::XDP_PASS;
                prefix_hit = prefix_len;          
            }
            break;
        }
    }

    let duration = bpf_ktime_get_ns() - start;

    let log_event = PacketLog{
        ipv4_address: source_ip_address,
        protocol: protocol,
        dest_port: dest_port.try_into().unwrap(),
        action: action,
        process_time: duration,
        prefix_hit: prefix_hit.into(),
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

fn is_allowed(prefix_len: u32, source_addr: u32, protocol: redwall_common::Protocol, dest_port: u16) -> Option<bool> {

    let key = Key::new(prefix_len, source_addr.to_be());
    unsafe {
        let rules = BLOCKLIST.get(&key);

        if rules.is_none() {
            return None;
        }

        let rules = rules.unwrap();

        return get_rules_result(protocol, dest_port, rules);

    };
    None
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

fn get_rules_result(protocol: redwall_common::Protocol, dest_port: u16, rules: &[redwall_common::Rules; redwall_common::RULES_MAX_SIZE]) -> Option<bool> {
    for rule in rules {
        // we need this ugly valid check because we must know at compile time the size of the array
        //TODO(mk): investigate a linked list or other data struct that we don't need to know at compile time
        if !rule.valid {
            break;
        }

        if rule.proto != protocol {
            continue;
        }

        if protocol != redwall_common::Protocol::ICMP {
            if rule.ports.is_empty == FALSE {
                if !rule.ports.dest_port.contains(&dest_port) {
                    continue;
                }
            }
        }

        if rule.action == redwall_common::Action::Deny {
            return Some(false);
        }

        if rule.action == redwall_common::Action::Allow {
            return Some(true);
        }
    }
    None
}