use std::{fs, str::FromStr};
use std::error::Error;
use std::net;

use redwall_common::PacketLog;

use aya::{include_bytes_aligned, Bpf, maps::{HashMap, perf::AsyncPerfEventArray}};
use aya::programs::{Xdp, XdpFlags};
use aya::util::online_cpus;
use anyhow::Context;
use clap::Parser;
use tokio::{signal, task};
extern crate yaml_rust;
use yaml_rust::{YamlLoader, Yaml};
use bytes::BytesMut;
use cidr::Ipv4Cidr;
use cidr;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value= "blocklist.yaml")]
    filename: String,  
}

fn main() -> Result<(), Box<dyn Error>> {
    let opt = Opt::parse();
    run(&opt)
}

fn run(opt: &Opt) -> Result<(), Box<dyn Error>> {   
   let file_contents: String = fs::read_to_string(&opt.filename)?;  
   let yamls: Vec<Yaml> = YamlLoader::load_from_str(&file_contents)?;

   if yamls.is_empty() {
       panic!("Empty YAML supplied");
   }

   let yaml: &Yaml = yamls.get(0).unwrap();

   if !is_yaml_valid(yaml) {
    panic!("YAML file supplied is not valid");
   }

   let interfaces: Vec<&str> = get_interfaces(yaml);

   let mut bpf_prog = load_bpf_prog();
   attach_bpf_prog(&mut bpf_prog, &interfaces)?;

   insert_ipv4_hashmap(&bpf_prog, yaml, "IPV4_BLOCKLIST")?;

   watch_perf_event_array(&bpf_prog, "EVENTS")?;
   
   Ok(())
}

fn is_yaml_valid(doc: &Yaml) -> bool {    
    if !at_least_one_fromcidrs_exists(&doc) {
        return false
    }

    if !at_least_one_interface_exists(&doc) {
        return false;
    }
    true
}

fn get_interfaces(yaml: &Yaml) -> Vec<&str> {
    return yaml["interfaces"].as_vec()
    .unwrap()
    .iter()
    .map(|i| { i.as_str().unwrap()})
    .collect();
}

fn at_least_one_fromcidrs_exists(doc: &Yaml) -> bool {
      // this will not panic if any of the indexs are not found
    if doc["ingress"][0]["fromCIDRS"].is_badvalue() {
        return false;
    }

    match doc["ingress"][0]["fromCIDRS"].as_vec() {
        Some(v) => return v.len() > 0,
        None => return false
    };
}

fn at_least_one_interface_exists(doc: &Yaml) -> bool {
    if doc["interfaces"].is_badvalue() {
        return false
    }
    match doc["interfaces"].as_vec() {
        Some(v) => return v.len() > 0,
        None => return false,
    };
}

fn get_ipv4_fromcidrs_as_ints(doc: &Yaml) -> Vec<u32> {
    let fromcidrs_raw = doc["ingress"][0]["fromCIDRS"].as_vec().unwrap_or_else(|| {
        panic!("Expected fromCIDRS to be valid");
    });

    if fromcidrs_raw.len() == 0 {
        panic!("Expected one or more fromCIDRS to be defined");
    }

    let mut v: Vec<u32> = Vec::new();

    for fromcidr_raw in fromcidrs_raw {     
        let ipv4_cidr_result = Ipv4Cidr::from_str(fromcidr_raw.as_str().unwrap());
        if ipv4_cidr_result.is_err() {
            eprintln!("Unexpected error processing an expected IPv4 fromCIDR field. Ignoring.");
            continue;
        }
        let ipv4_cidr_result = ipv4_cidr_result.unwrap();

        for ipv4_cidr in ipv4_cidr_result.iter() {
            v.push(ipv4_cidr.address().into());
        }
    }
    v
}

fn load_bpf_prog() -> Bpf {
        // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    #[cfg(debug_assertions)]
    let bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/redwall"
    )).unwrap();
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/redwall"
    )).unwrap();
    bpf
}

fn attach_bpf_prog(bpf: &mut Bpf, interfaces: &Vec<&str>) -> Result<(), anyhow::Error> {
     //BpfLogger::init(&mut bpf)?;
     let program: &mut Xdp = bpf.program_mut("redwall").unwrap().try_into().unwrap();
     program.load()?;
     for &interface in interfaces {
        program.attach(interface, XdpFlags::default())
         .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;
     }

     Ok(())
}

fn insert_ipv4_hashmap(bpf_prog: &Bpf, yaml: &Yaml, hashmap_name: &str) -> Result<(), anyhow::Error> {
    let mut blocklist: HashMap<_, u32, u32> = HashMap::try_from(bpf_prog.map_mut(hashmap_name)?)?;

    for ipv4_cidr in get_ipv4_fromcidrs_as_ints(&yaml) {
        blocklist.insert(ipv4_cidr, 0, 0)?;
    }

    Ok(())
}

#[tokio::main]
async fn watch_perf_event_array(bpf_prog: &Bpf, array_name: &str) -> Result<(), anyhow::Error> {
    let mut perf_array = AsyncPerfEventArray::try_from(bpf_prog.map_mut(array_name)?)?;

    for cpu_id in online_cpus()? {
        let mut buf = perf_array.open(cpu_id, None)?;
 
        task::spawn(async move {
            let mut buffers = (0..10)
            .map(|_| BytesMut::with_capacity(1024))
            .collect::<Vec<_>>();
 
            loop {
                let events = buf.read_events(&mut buffers).await.unwrap();
 
                for i in 0..events.read {
                    let buf = &mut buffers[i];
                    let ptr = buf.as_ptr() as *const PacketLog;
                    let data = unsafe { ptr.read_unaligned() };
                    let src_address = net::Ipv4Addr::from(data.ipv4_address);
                    println!("SRC {}, ACTION {}", src_address, data.action);
                }
            }
        });
    }

    signal::ctrl_c().await.expect("failed to listen for events");

    Ok(()) 
}
