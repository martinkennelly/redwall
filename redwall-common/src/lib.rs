#![no_std]

pub const IPV4_BLOCKLIST_HASHMAP_NAME: &str = "IPV4_BLOCKLIST";
pub const EVENTS_ARRAY_NAME: &str = "EVENTS";

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PacketLog {
    pub ipv4_address: u32,
    pub action: u32,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for PacketLog {}