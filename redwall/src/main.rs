use std::fmt::Debug;
use std::{fs, str::FromStr};
use std::error::Error;
use std::net;
use std::collections::HashMap as stdHashMap;
use std::sync::mpsc::channel;
use std::time::Duration;

use redwall_common::PacketLog;

use notify::{Watcher, RecursiveMode, watcher};
use aya::{include_bytes_aligned, Bpf, util::online_cpus, maps::{lpm_trie::{LpmTrie,Key}, perf::AsyncPerfEventArray}, programs::{Xdp, XdpFlags, xdp::XdpLinkId}};
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

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let opt = Opt::parse();

    let yamls = get_yaml_file(&opt.filename)?;
    if yamls.is_empty() {
        Err("Empty YAML supplied")?;
    };
    let yaml = yamls.get(0).unwrap();

    //todo: dont bother validing and then processing, keep the validation close to the processing
    //todo: remove this validation and use strictyaml
    is_yaml_valid(yaml)?;

    let interfaces: Vec<&str> = process_interfaces(yaml);
    let cidr_rule_map = process_fromcidrs_rules(yaml)?;
    let mut bpf_prog = get_bpf_prog();
    load_bpf_prog(&mut bpf_prog)?;
    let mut link_ids = attach_bpf_interfaces(&mut bpf_prog, &interfaces)?;
    add_fromcidr_rules_bpf_map(&bpf_prog, &cidr_rule_map, "IPV4_BLOCKLIST")?;

    let (sender, receiver) = channel();
    let mut watcher = watcher(sender, Duration::from_secs(5))?;
    watcher.watch(&opt.filename, RecursiveMode::NonRecursive)?;

    let mut perf_array = AsyncPerfEventArray::try_from(bpf_prog.map_mut("EVENTS")?)?;
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
                    match data.action {
                        1 => println!("PROCESS TIME: {}, SRC {}, PROTOCOL {:?}, DESTINATION PORT {}: deny", data.process_time, src_address, data.protocol, data.dest_port),
                        2 => println!("PROCESS TIME: {}, SRC {}, PROTOCOL {:?}, DESTINATION PORT {}: allow", data.process_time, src_address, data.protocol, data.dest_port),
                        _ => println!("Unexpected ACTION"),
                    }
                }
            }
        });
    }

    let mut old_rules = cidr_rule_map.clone();

    task::spawn(async move {
        loop {
            match receiver.recv() {
                Ok(_) => {                    
                    let yamls = get_yaml_file(&opt.filename);
                    if yamls.is_err() {
                        eprintln!("Error retrieving file: {}", yamls.err().unwrap().to_string());
                        continue;
                    }
                    let yamls = yamls.unwrap();
                    if yamls.is_empty() {
                        eprintln!("Empty YAML supplied");
                        continue;
                    };
                    let yaml = yamls.get(0).unwrap();
                    //todo: dont bother validing and then processing, keep the validation close to the processing
                    //todo: remove this validation and use strictyaml
                    let valid_yaml = is_yaml_valid(yaml);
                    if valid_yaml.is_err() {
                        eprintln!("YAML is not valid: {}", valid_yaml.err().unwrap().to_string());
                        continue;
                    }

                    if link_ids.len() > 0 {
                        if let Err(e) = detach_bpf_interfaces(&mut bpf_prog, link_ids) {
                            eprint!("Unable to detach BPF program: {}", e.to_string());
                            link_ids = Vec::new();
                            continue;
                        }
                        link_ids = Vec::new();
                    }
                    link_ids.clear();

                    let interfaces: Vec<&str> = process_interfaces(yaml);

                    let cidr_rule_map = match process_fromcidrs_rules(yaml) {
                        Ok(v) => v,
                        Err(_) => {
                            eprintln!("Unable to process fromcidrs and/or rules");
                            continue;
                        }
                    };

                    link_ids = match attach_bpf_interfaces(&mut bpf_prog, &interfaces) {
                        Ok(v) => v,
                        Err(e) => {
                            panic!("Unable to attach BPF program: {}", e.to_string());
                        }
                    };

                    if let Err(e) = del_fromcidr_rules_bpf_map(&bpf_prog, &old_rules, "IPV4_BLOCKLIST") {
                        panic!("Encountered errors deleting entries in BPF map: {}", e.to_string());
                    }
                    old_rules = cidr_rule_map.clone();

                    if let Err(e) = add_fromcidr_rules_bpf_map(&bpf_prog, &cidr_rule_map, "IPV4_BLOCKLIST") {
                        panic!("Encountered errors updating BPF map: {}", e.to_string());
                    }
                },
                Err(e) => {
                    eprintln!("Error watching file: {}", e.to_string());
                    return;
                }
            }
        }
    });

    signal::ctrl_c().await.expect("failed to listen for events");
   
    Ok(())
}

fn get_yaml_file(filename: &String) -> Result<Vec<Yaml>, Box<dyn Error>> {
    if filename.is_empty() {
        return Err("Empty filename. Unable to get yaml")?
    }
    let file_contents: String = fs::read_to_string(filename)?;
    let yamls = YamlLoader::load_from_str(&file_contents)?;
    Ok(yamls)
}

fn is_yaml_valid(doc: &Yaml) -> Result<bool, &str> {
    let (ok, msg) = valid_interfaces(&doc);
    if !ok {
        return Err(msg);
    }

    if doc["ingress"].is_badvalue() {
        // no ingress yaml key means we dont have to verify anything else
        return Ok(true)
    };

    let (ok, msg) = valid_ingress(&doc);
    if !ok {
        return Err(msg);
    }

    // check to see for each fromcidrs, there are rules
    let (ok, msg) = valid_fromcidrs_and_rules_block(&doc);
    if !ok {
        return Err(msg);
    }

    let (ok, msg) = valid_rules(&doc);
    if !ok {
        return Err(msg);
    }

    Ok(true)
}

fn process_fromcidrs_rules(doc: &Yaml) -> Result<stdHashMap<Ipv4Cidr, [redwall_common::Rules;redwall_common::RULES_MAX_SIZE]>, Box<dyn Error>> {
    let mut fromcidr_rule_Map: stdHashMap<Ipv4Cidr, [redwall_common::Rules; redwall_common::RULES_MAX_SIZE]> = stdHashMap::new();
    let total_ingress_entries = match doc["ingress"].as_vec() {
        Some(v) => v.len(),
        None => {
            0
        },
    };

    for ingress_entry_index in 0..total_ingress_entries {
        let v4s = process_fromcidr(&doc["ingress"][ingress_entry_index]["fromCIDRS"])?;
        let rules = process_rules(&doc["ingress"][ingress_entry_index]["rules"])?;

        for cidr in v4s {
            fromcidr_rule_Map.insert(cidr.clone(), rules.clone());
        }
    }

    Ok(fromcidr_rule_Map)
}

fn process_fromcidr(yaml: &Yaml) -> Result<Vec<Ipv4Cidr>, Box<dyn Error>> {
    let fromcidrs = match yaml.as_vec() {
        Some(v) => v,
        None => return Err("Expected fromCIDRS definition but did not find it".into()),
    };

    if fromcidrs.len() == 0 {
        return Err("Expected one or more fromCIDRS to be defined".into());
    };

    let mut v4s: Vec<Ipv4Cidr> = Vec::new();

    for fromcidr in fromcidrs {
        let v4 = match fromcidr.as_str() {
            Some(v) => v,
            None => return Err("Unexpected fromCIDRS encountered.".into()),
        };

        let v4 = match Ipv4Cidr::from_str(v4) {
            Ok(v) => v,
            Err(_) => return Err("Unable to convert string to IPV4 CIDR".into()),
        };

        v4s.push(v4);
    };

    Ok(v4s)
}

fn process_rules(yaml: &Yaml) -> Result<[redwall_common::Rules; redwall_common::RULES_MAX_SIZE], Box<dyn Error>> {
    let rules = match yaml.as_vec() {
        Some(v) => v,
        None => return Err("Unable to convert rules to a vector. Are rules an array?".into()),
    };

    let mut rules_arr = [redwall_common::Rules::new(); redwall_common::RULES_MAX_SIZE];
    let mut rules_arr_index = 0;

    for rule in rules {
        let order = match rule["order"].as_i64() {
            Some(v) => v as u64,
            None => return Err("Unable to convert order to an integer. Is it an integer?".into()),
        };

        let proto_str = match rule["protocol"].as_str() {
            Some(v) => v,
            None => return Err("Unable to convert protocol. Is it a string?".into()),
        };

        let mut proto = redwall_common::Protocol::Unsupported;
        if proto_str == "udp" {
            proto = redwall_common::Protocol::UDP;
        } else if proto_str == "tcp" {
            proto = redwall_common::Protocol::TCP;
        } else if proto_str == "icmp" {
            proto = redwall_common::Protocol::ICMP;
        } else {
            return Err("Unexpected protocol defined. Supported protocols are udp,tcp or icmp.".into());
        };

        let mut dest_ports: &Vec<Yaml> = &Vec::new();
        let dest_ports_vec = rule["ports"].as_vec();
        if dest_ports_vec.is_some() {
            dest_ports = dest_ports_vec.unwrap();
        }

        if dest_ports.len() > redwall_common::PORTS_MAX_SIZE {
            return Err("Number of ports supplied exceeded maximum allowed".into());
        };

        let mut ports_arr = [redwall_common::EMPTY_PORT; redwall_common::PORTS_MAX_SIZE];
        let mut ports_arr_index = 0;

        for entry in dest_ports {
            let entry = match entry.as_i64() {
                Some(v) => v,
                None => return Err("Failed to convert a port to an integer")?,
            };

            let port = match i64_to_u16(entry) {
                Ok(v) => v,
                Err(_) => return Err("Failed to convert 64 bit integer to unsigned 16 bits. Is the port you've specified invalid?".into()),
            };

            ports_arr[ports_arr_index] = port;
            ports_arr_index += 1;
        }

        let action_raw = match rule["action"].as_str() {
            Some(v) => v,
            None => return Err("Unable to convert an action to a string. Are the actions string?".into()),
        };

        let mut action = redwall_common::Action::Allow;
        if action_raw.eq_ignore_ascii_case("allow") {
            action = redwall_common::Action::Allow;
        } else if action_raw.eq_ignore_ascii_case("deny") {
            action = redwall_common::Action::Deny;
        } else {
            return Err("Unexpected action defined in rule".into());
        };

        rules_arr[rules_arr_index] = redwall_common::Rules{
            order: order,
            proto: proto,
            dest_port: ports_arr,
            action: action,
            valid: true,
        };
        rules_arr_index += 1;
    }
    rules_arr.sort_by(|a, b| a.order.cmp(&b.order));
    Ok(rules_arr)
}

fn process_interfaces(yaml: &Yaml) -> Vec<&str> {
    return yaml["interfaces"].as_vec()
    .unwrap()
    .iter()
    .map(|i| { i.as_str().unwrap()})
    .collect();
}

fn valid_ingress(doc: &Yaml) -> (bool, &str) {
    match doc["ingress"].as_vec() {
        Some(v) => (v.len() > 0, "Expected fromCIDRS to be defined"),
        None => (false, "Expected ingress value to be an array"),
    }
}

fn valid_fromcidrs_and_rules_block(doc: &Yaml) -> (bool, &str) {
    // for each array defined beneath ingress, each array must contain a fromCIDRS and rules.
    if doc["ingress"].is_badvalue() {
        eprintln!("No ingress defined");
        return (true, "");
    };

    match doc["ingress"].as_vec() {
        Some(v) => {
            for block in v {
                let fromcidr = &block["fromCIDRS"];
                if fromcidr.is_badvalue() {
                    return (false, "Expected fromCIDRS but found something else. Ensure for each fromCIDR, rules are defined.");
                }

                let rules = &block["rules"];
                if rules.is_badvalue() {
                    return (false, "Expected rules but found something else. Ensure for each fromCIDR, rules are defined.");
                }
            }
            (true, "")
        },
        None => (false, "Expected an array to be defined beneath ingress but it wasn't found"),
    }
}

fn valid_rules(doc: &Yaml) -> (bool, &str) {
    let ingress_vec: &Vec<Yaml> = match doc["ingress"].as_vec() {
        Some(v) => v,
        None => return (false, "Expected ingress to be defined"),
    };

    for ingress_entry in ingress_vec {
        let rules_vec = match ingress_entry["rules"].as_vec() {
            Some(v) => v,
            None => return (false, "Expected at least one rule to be defined"),
        };

        if rules_vec.len() == 0 {
            return (false, "Expect at least one rule to be defined");
        }

        if rules_vec.len() > redwall_common::RULES_MAX_SIZE {
            return (false, "Too many rules defined. Reduce it.");
        }

        for rule in rules_vec {
            let order = rule["order"].as_i64();
            if order.is_none() {
                return (false, "Rule order was not found or is not an integer");
            };

            let protocol = rule["protocol"].as_str();
            if protocol.is_none() {
                return (false, "Rule protocol is not defined");
            }

            let protocol = protocol.unwrap();
            if protocol != "tcp" && protocol != "udp" && protocol != "icmp" {
                return (false, "Unexpected protocol found. We support only tcp, udp and icmp");
            }


            let ports_vec = rule["ports"].as_vec();
            let ports_exist = ports_vec.is_some();

            if ports_exist {
                let ports_vec = ports_vec.unwrap();
                if ports_vec.len() > redwall_common::PORTS_MAX_SIZE {
                    return (false, "Too many ports defined. Reduced the amount of ports defined");
                }

                let bad_ports = ports_vec.iter()
                .filter(|yaml| {
                    match yaml.as_i64() {
                        Some(i) => i <= u16::MIN.into() || i > u16::MAX.into(),
                        None => true,
                    }
                })
                .count();
                if bad_ports > 0 {
                    return (false, "Expected ports within rules that are greater than 0 and less or equal than 65535");
                }
            }

            let action = rule["action"].as_str();
            if action.is_none() {
                return (false, "Expected action to be define for all rules");
            };
            let action = action.unwrap();
            if action != "allow" && action != "deny" {
                return (false, "Expected action to either be allow or deny");
            };
        }
    }

    (true, "")
}

fn valid_interfaces(doc: &Yaml) -> (bool, &str) {
    if doc["interfaces"].is_badvalue() {
        return (false, "No interfaces defined");
    }

    let interfaces = match doc["interfaces"].as_vec() {
        Some(v) => v,
        None => return (false, "Expected interfaces to be an array"),
    };

    for interface in interfaces {
        let interface = interface.as_str();
        if interface.is_none() {
            return (false, "Expected interface to be a string");
        }
    }

    (true, "")
}

fn get_bpf_prog() -> Bpf {
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

fn load_bpf_prog(bpf: &mut Bpf) -> Result<(), anyhow::Error> {
    let program: &mut Xdp = bpf.program_mut("redwall").unwrap().try_into()?;
    program.load()?;
    Ok(())
}

fn attach_bpf_interfaces(bpf: &mut Bpf, interfaces: &Vec<&str>) -> Result<Vec<XdpLinkId>, anyhow::Error> {
     let mut link_ids: Vec<XdpLinkId> = Vec::new();
     let program: &mut Xdp = bpf.program_mut("redwall").unwrap().try_into()?;
     for &interface in interfaces {
        link_ids.push(program.attach(interface, XdpFlags::default())?);
     }

     Ok(link_ids)
}

fn detach_bpf_interfaces(bpf: &mut Bpf, link_ids: Vec<XdpLinkId>) -> Result<(), anyhow::Error> {
    let program: &mut Xdp = bpf.program_mut("redwall").unwrap().try_into()?;
    for link_id in link_ids {
        program.detach(link_id)?;
    }

    Ok(())
}

fn add_fromcidr_rules_bpf_map(bpf_prog: &Bpf, cidr_rules: &stdHashMap<Ipv4Cidr, [redwall_common::Rules; redwall_common::RULES_MAX_SIZE]>, hashmap_name: &str) -> Result<(), anyhow::Error> {
    let blocklist: LpmTrie<_, u32, [redwall_common::Rules; redwall_common::RULES_MAX_SIZE]> = LpmTrie::try_from(bpf_prog.map_mut(hashmap_name)?)?;

    for (cidr, rules) in *&cidr_rules {
        let key = Key::new(cidr.network_length().into(), u32::from(cidr.first_address()).to_be());

        match blocklist.insert(&key, rules.clone(), 0) {
            Ok(_) => {},
            Err(e) => panic!("Inserting rules caused error {:?}", e),
        }
    }

    Ok(())
}

fn del_fromcidr_rules_bpf_map(bpf_prog: &Bpf, cidr_rules: &stdHashMap<Ipv4Cidr, [redwall_common::Rules; redwall_common::RULES_MAX_SIZE]>, hashmap_name: &str) -> Result<(), anyhow::Error> {
    let blocklist: LpmTrie<_, u32, [redwall_common::Rules; redwall_common::RULES_MAX_SIZE]> = LpmTrie::try_from(bpf_prog.map_mut(hashmap_name)?)?;

    for (cidr, rules) in *&cidr_rules {
        let key = Key::new(cidr.network_length().into(), u32::from(cidr.first_address()).to_be());

        match blocklist.remove(&key) {
            Ok(_) => {},
            Err(e) => panic!("Deleting rules caused error when deleting cidr {}: {:?}", cidr.to_string(), e),
        }
    }

    Ok(())

}

fn i64_to_u16(i: i64) -> Result<u16, Box<dyn Error>> {
    if i > u16::MAX as i64 {
        Err("Unable to convert i64 to u16 because value is larger than what the type can hold")?
    }
    Ok(i as u16)
}
