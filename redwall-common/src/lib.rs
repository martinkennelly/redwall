#![no_std]
#[repr(C)]
#[derive(Clone, Copy)]
pub struct PacketLog {
    pub ipv4_address: u32,
    pub protocol: Protocol,
    pub action: u32,
    pub dest_port: u32,
    pub process_time: u64,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for PacketLog {}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Protocol {
    ICMP = 1,
    TCP = 6,
    UDP = 17,
    Unsupported = 9999,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Action {
    Allow,
    Deny,
}

#[derive(Clone, Copy, Debug)]
pub struct Rules {
    pub order: u64,
    pub proto: Protocol,
    pub action: Action,
    pub dest_port: [u16; PORTS_MAX_SIZE],
    pub valid: bool,
}

impl Rules {
    pub fn new() -> Rules {
        Rules { order: u64::MAX, proto: Protocol::Unsupported, action: Action::Allow, dest_port: [EMPTY_PORT; PORTS_MAX_SIZE], valid: false }
    }
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for Rules {}

pub const RULES_MAX_SIZE: usize = 8;
pub const PORTS_MAX_SIZE: usize = 4;
pub const EMPTY_PORT: u16 = 0;