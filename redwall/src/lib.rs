extern crate strict_yaml_rust;
use std::{cmp::Ordering, collections::HashMap, error::Error, fs, str::FromStr};

use strict_yaml_rust::{StrictYaml, StrictYamlEmitter, StrictYamlLoader};

pub struct NodeFirewallDocs {
    pub raw: String,
    pub raw_docs: Vec<String>,
    pub docs: Vec<StrictYaml>,
}

impl NodeFirewallDocs {
    pub fn new(filename: &String) -> Result<NodeFirewallDocs, Box<dyn Error>> {
        let raw: String = fs::read_to_string(filename)?;
        let docs = StrictYamlLoader::load_from_str(&raw)?;

        let mut raw_docs = Vec::new();
        for doc in &docs {
            // Dump the YAML object
            let mut raw_doc = String::new();
            {
                let mut emitter = StrictYamlEmitter::new(&mut raw_doc);
                emitter.dump(doc)?;
                raw_docs.push(raw_doc);
            }
        }
        Ok(NodeFirewallDocs {
            raw,
            raw_docs,
            docs,
        })
    }

    pub fn validate(&self) -> Result<(), &'static str> {
        if self.docs.is_empty() {
            return Err("Empty YAML supplied");
        }

        for doc in &self.docs {
            if doc["kind"].is_badvalue() {
                return Err("Unexpected yaml doc: no kind");
            }
            match doc["kind"].as_str().unwrap() {
                "NodeEndpoint" => return NodeEndpoint::validate(doc),
                other_kind => {
                    eprintln!("Kind {} is not supported", other_kind);
                    return Err("Unexpected kind in yaml");
                }
            }
        }

        Ok(())
    }

    pub fn get_eps_and_fws(
        &self,
    ) -> (
        HashMap<String, NodeEndpoint>,
        HashMap<String, IngressNodeFirewall>,
    ) {
        let mut eps = HashMap::new();
        let mut fws = HashMap::new();

        for doc in &self.docs {
            if doc["kind"].is_badvalue() {
                continue;
            }
            match doc["kind"].as_str().unwrap() {
                "NodeEndpoint" => {
                    match NodeEndpoint::new(doc) {
                        Some(ep) => {
                            eps.insert(ep.name.clone(), ep);
                        }
                        None => (),
                    };
                }
                "IngressNodeFirewall" => {
                    match IngressNodeFirewall::new(doc) {
                        Some(fw) => {
                            fws.insert(fw.name.clone(), fw);
                        }
                        None => (),
                    };
                }
                other_kind => {
                    eprintln!("Skiping kind {}: not supported", other_kind);
                }
            }
        }

        (eps, fws)
    }
}

pub struct NodeEndpoint {
    pub name: String,
    pub labels: HashMap<String, String>,
    pub interfaces: Vec<String>,
}

impl NodeEndpoint {
    pub fn new(doc: &StrictYaml) -> Option<NodeEndpoint> {
        match NodeEndpoint::validate(doc) {
            Ok(_) => (),
            Err(e) => {
                eprintln!("failed to parse ep: {}", e);
                return None;
            }
        }

        let name = String::from_str(doc["metadata"]["name"].as_str().unwrap()).unwrap();

        let mut labels = HashMap::new();
        match doc["metadata"]["labels"] {
            StrictYaml::Hash(ref h) => {
                for (k, v) in h {
                    let label_key = String::from_str(k.as_str().unwrap()).unwrap().clone();
                    let label_value = String::from_str(v.as_str().unwrap()).unwrap().clone();
                    labels.insert(label_key, label_value);
                }
            }
            _ => {}
        }

        let interfaces = doc["spec"]["interfaces"]
            .as_vec()
            .unwrap()
            .iter()
            .map(|i| String::from_str(i.as_str().unwrap()).unwrap().clone())
            .collect();

        Some(NodeEndpoint {
            name,
            labels,
            interfaces,
        })
    }

    pub fn validate(doc: &StrictYaml) -> Result<(), &'static str> {
        if doc["kind"].is_badvalue() {
            return Err("Unexpected yaml doc: no kind");
        }
        if doc["kind"].as_str().unwrap() != "NodeEndpoint" {
            return Err("Unexpected kind in yaml");
        }
        if doc["metadata"]["name"].is_badvalue() {
            return Err("Name not found in NodeEndpoint");
        }
        if doc["spec"]["interfaces"].is_badvalue() {
            return Err("Interfaces not found in NodeEndpoint");
        }
        if doc["spec"]["interfaces"].as_vec().unwrap().is_empty() {
            // TODO(FF): maybe this should be ok
            return Err("Interfaces empty in NodeEndpoint");
        }
        Ok(())
    }
}

pub struct Ingress {
    pub from_cidr: Vec<String>,
    pub rules: Vec<HashMap<String, String>>,
}

pub struct IngressNodeFirewall {
    pub name: String,
    pub node_endpoint: String,
    pub ingresses: Vec<Ingress>,
}

impl IngressNodeFirewall {
    pub fn new(doc: &StrictYaml) -> Option<IngressNodeFirewall> {
        match IngressNodeFirewall::validate(doc) {
            Ok(_) => (),
            Err(e) => {
                eprintln!("failed to parse fw: {}", e);
                return None;
            }
        }

        let name = String::from_str(doc["metadata"]["name"].as_str().unwrap()).unwrap();
        let node_endpoint = String::from_str(
            doc["metadata"]["annotations"]["node-endpoint"]
                .as_str()
                .unwrap(),
        )
        .unwrap();

        let mut ingresses = Vec::new();
        match doc["spec"]["ingress"] {
            StrictYaml::Array(ref v) => {
                for x in v {
                    match IngressNodeFirewall::parse_ingress(x) {
                        Some(ingress) => {
                            ingresses.push(ingress);
                        }
                        _ => {}
                    }
                }
            }
            _ => {}
        }

        Some(IngressNodeFirewall {
            name,
            node_endpoint,
            ingresses,
        })
    }

    fn parse_ingress(doc: &StrictYaml) -> Option<Ingress> {
        let mut from_cidr = Vec::new();
        match doc["fromCIDRS"] {
            StrictYaml::Array(ref v) => {
                for cidr_yaml in v {
                    let cidr = String::from_str(cidr_yaml.as_str().unwrap())
                        .unwrap()
                        .clone();

                    from_cidr.push(cidr);
                }
            }
            // fromCIDRS should be present
            _ => return None,
        }
        // fromCIDRS should have one or more prefixes
        if from_cidr.is_empty() {
            return None;
        }

        let mut rules = Vec::new();
        match doc["rules"] {
            StrictYaml::Array(ref v) => {
                for rule_yaml in v {
                    match IngressNodeFirewall::parse_ingress_rule(rule_yaml) {
                        Some(rule_dict) => {
                            if !rule_dict.is_empty() {
                                rules.push(rule_dict);
                            }
                        }
                        _ => {}
                    }
                }
            }
            _ => {}
        }
        rules.sort_by(|a, b| IngressNodeFirewall::compare_ingress_rule_order(a, b));

        Some(Ingress { from_cidr, rules })
    }

    fn compare_ingress_rule_order(
        a: &HashMap<String, String>,
        b: &HashMap<String, String>,
    ) -> Ordering {
        let a_order = match a.get("order") {
            Some(value) => value.parse::<u64>().unwrap(),
            _ => 0,
        };
        let b_order = match b.get("order") {
            Some(value) => value.parse::<u64>().unwrap(),
            _ => 0,
        };
        a_order.cmp(&b_order)
    }

    fn parse_ingress_rule(doc: &StrictYaml) -> Option<HashMap<String, String>> {
        let mut rules_dict = HashMap::new();
        match doc {
            StrictYaml::Hash(ref h) => {
                for (k, v) in h {
                    let rule_key = String::from_str(k.as_str().unwrap()).unwrap().clone();
                    let rule_value = String::from_str(v.as_str().unwrap()).unwrap().clone();
                    rules_dict.insert(rule_key, rule_value);
                }
            }
            // TODO(FF): rule is not a dictionary. Should we complain about that?
            _ => return None,
        }
        Some(rules_dict)
    }

    pub fn validate(doc: &StrictYaml) -> Result<(), &'static str> {
        if doc["kind"].is_badvalue() {
            return Err("Unexpected yaml doc: no kind");
        }
        if doc["kind"].as_str().unwrap() != "IngressNodeFirewall" {
            return Err("Unexpected kind in yaml");
        }
        if doc["metadata"]["name"].is_badvalue() {
            return Err("Name not found in IngressNodeFirewall");
        }
        if doc["metadata"]["annotations"]["node-endpoint"].is_badvalue() {
            return Err("node-endpoint not found in IngressNodeFirewall annotations");
        }

        Ok(())
    }
}
