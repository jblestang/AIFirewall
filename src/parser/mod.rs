use pest::Parser;
use pest_derive::Parser;
use crate::firewall::{FirewallRule, Action, Layer2Match, Layer3Match, Layer4Match};
use alloc::vec::Vec;

#[derive(Parser)]
#[grammar = "parser/grammar.pest"]
pub struct FirewallRuleParser;

#[derive(Debug, Clone)]
pub struct ParsedMacAddress {
    pub bytes: Option<[u8; 6]>,
}

#[derive(Debug, Clone)]
pub struct ParsedIpAddress {
    pub addr: Option<[u8; 4]>, // IPv4 address as bytes
    pub cidr: Option<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    ParseFailed,
    UnknownAction,
    UnknownProtocol,
    InvalidMacFormat,
    InvalidIpFormat,
    InvalidCidr,
    InvalidNumber,
}

pub fn parse_firewall_rules(input: &str) -> Result<Vec<FirewallRule>, ParseError> {
    let pairs = FirewallRuleParser::parse(Rule::rule, input)
        .map_err(|_| ParseError::ParseFailed)?;
    
    let mut rules = Vec::new();
    
    for pair in pairs {
        if pair.as_rule() == Rule::rule {
            for inner_pair in pair.into_inner() {
                if inner_pair.as_rule() == Rule::rule_line {
                    let rule = parse_rule_line(inner_pair)?;
                    rules.push(rule);
                }
            }
        }
    }
    
    Ok(rules)
}

fn parse_rule_line(pair: pest::iterators::Pair<'_, Rule>) -> Result<FirewallRule, ParseError> {
    let mut action = Action::Drop;
    let mut l2_match = None;
    let mut l3_match = None;
    let mut l4_match = None;
    
    for inner_pair in pair.into_inner() {
        match inner_pair.as_rule() {
            Rule::action => {
                action = match inner_pair.as_str() {
                    "ACCEPT" => Action::Accept,
                    "DROP" => Action::Drop,
                    "REJECT" => Action::Reject,
                    _ => return Err(ParseError::UnknownAction),
                };
            }
            Rule::l2_match => {
                l2_match = Some(parse_l2_match(inner_pair)?);
            }
            Rule::l3_match => {
                l3_match = Some(parse_l3_match(inner_pair)?);
            }
            Rule::l4_match => {
                l4_match = Some(parse_l4_match(inner_pair)?);
            }
            Rule::combined_match => {
                let mut inner = inner_pair.into_inner();
                while let Some(p) = inner.next() {
                    match p.as_rule() {
                        Rule::l2_match => l2_match = Some(parse_l2_match(p)?),
                        Rule::l3_match => l3_match = Some(parse_l3_match(p)?),
                        Rule::l4_match => l4_match = Some(parse_l4_match(p)?),
                        _ => {}
                    }
                }
            }
            Rule::comment => {} // Ignore comments
            _ => {}
        }
    }
    
    Ok(FirewallRule {
        action,
        l2_match: l2_match.unwrap_or(Layer2Match::Any),
        l3_match: l3_match.unwrap_or(Layer3Match::Any),
        l4_match: l4_match.unwrap_or(Layer4Match::Any),
    })
}

fn parse_l2_match(pair: pest::iterators::Pair<'_, Rule>) -> Result<Layer2Match, ParseError> {
    let mut src_mac = None;
    let mut dst_mac = None;
    let mut ethertype = None;
    let mut vlan_id = None;
    let mut is_any = false;
    
    for inner_pair in pair.into_inner() {
        match inner_pair.as_rule() {
            Rule::src_mac => {
                let mac = parse_mac_address(inner_pair.into_inner().next().ok_or(ParseError::ParseFailed)?)?;
                src_mac = mac.bytes;
            }
            Rule::dst_mac => {
                let mac = parse_mac_address(inner_pair.into_inner().next().ok_or(ParseError::ParseFailed)?)?;
                dst_mac = mac.bytes;
            }
            Rule::ethertype => {
                let hex_str = inner_pair.into_inner().next().ok_or(ParseError::ParseFailed)?.as_str();
                let hex_val = u16::from_str_radix(&hex_str[2..], 16).map_err(|_| ParseError::InvalidNumber)?;
                ethertype = Some(hex_val);
            }
            Rule::vlan_id => {
                let vlan_pair = inner_pair.into_inner().next().ok_or(ParseError::ParseFailed)?;
                match vlan_pair.as_rule() {
                    Rule::vlan_number => {
                        let vlan_str = vlan_pair.as_str();
                        if vlan_str == "*" {
                            // "*" means match any VLAN (including no VLAN)
                            vlan_id = None;
                        } else {
                            let vid = vlan_str.parse::<u16>().map_err(|_| ParseError::InvalidNumber)?;
                            if vid > 4095 {
                                return Err(ParseError::InvalidNumber);
                            }
                            vlan_id = Some(vid);
                        }
                    }
                    _ => return Err(ParseError::ParseFailed),
                }
            }
            Rule::l2_all => {
                is_any = true;
            }
            _ => {}
        }
    }
    
    if is_any {
        Ok(Layer2Match::Any)
    } else {
        Ok(Layer2Match::Match {
            src_mac,
            dst_mac,
            ethertype,
            vlan_id,
        })
    }
}

fn parse_l3_match(pair: pest::iterators::Pair<'_, Rule>) -> Result<Layer3Match, ParseError> {
    let mut src_ip = None;
    let mut dst_ip = None;
    let mut protocol = None;
    let mut is_any = false;
    
    for inner_pair in pair.into_inner() {
        match inner_pair.as_rule() {
            Rule::src_ip => {
                let ip = parse_ip_address(inner_pair.into_inner().next().ok_or(ParseError::ParseFailed)?)?;
                src_ip = ip.addr.map(|addr| crate::firewall::IpMatch { addr, cidr: ip.cidr });
            }
            Rule::dst_ip => {
                let ip = parse_ip_address(inner_pair.into_inner().next().ok_or(ParseError::ParseFailed)?)?;
                dst_ip = ip.addr.map(|addr| crate::firewall::IpMatch { addr, cidr: ip.cidr });
            }
            Rule::protocol => {
                let proto_pair = inner_pair.into_inner().next().ok_or(ParseError::ParseFailed)?;
                protocol = Some(match proto_pair.as_rule() {
                    Rule::protocol_name => {
                        match proto_pair.as_str() {
                            "tcp" => 6,
                            "udp" => 17,
                            "icmp" => 1,
                            "igmp" => 2,
                            "icmpv6" => 58,
                            _ => return Err(ParseError::UnknownProtocol),
                        }
                    }
                    Rule::number => {
                        proto_pair.as_str().parse().map_err(|_| ParseError::InvalidNumber)?
                    }
                    _ => return Err(ParseError::ParseFailed),
                });
            }
            Rule::l3_all => {
                is_any = true;
            }
            _ => {}
        }
    }
    
    if is_any {
        Ok(Layer3Match::Any)
    } else {
        Ok(Layer3Match::Match {
            src_ip,
            dst_ip,
            protocol,
        })
    }
}

fn parse_l4_match(pair: pest::iterators::Pair<'_, Rule>) -> Result<Layer4Match, ParseError> {
    let protocol_type = pair.as_str().split_whitespace().next().ok_or(ParseError::ParseFailed)?;
    let mut src_port = None;
    let mut dst_port = None;
    let mut one_way = false;
    let mut is_any = false;
    
    for inner_pair in pair.into_inner() {
        match inner_pair.as_rule() {
            Rule::src_port => {
                let port_str = inner_pair.into_inner().next().ok_or(ParseError::ParseFailed)?.as_str();
                if port_str != "*" {
                    src_port = Some(port_str.parse().map_err(|_| ParseError::InvalidNumber)?);
                }
            }
            Rule::dst_port => {
                let port_str = inner_pair.into_inner().next().ok_or(ParseError::ParseFailed)?.as_str();
                if port_str != "*" {
                    dst_port = Some(port_str.parse().map_err(|_| ParseError::InvalidNumber)?);
                }
            }
            Rule::one_way => {
                one_way = true;
            }
            Rule::l4_all => {
                is_any = true;
            }
            _ => {}
        }
    }
    
    let proto = match protocol_type {
        "tcp" => 6,
        "udp" => 17,
        "icmp" => 1,
        _ => return Err(ParseError::UnknownProtocol),
    };
    
    if is_any && src_port.is_none() && dst_port.is_none() {
        Ok(Layer4Match::Any)
    } else {
        Ok(Layer4Match::Match {
            protocol: proto,
            src_port,
            dst_port,
            one_way,
        })
    }
}

fn parse_mac_address(pair: pest::iterators::Pair<'_, Rule>) -> Result<ParsedMacAddress, ParseError> {
    let mac_str = pair.as_str();
    if mac_str == "*" {
        return Ok(ParsedMacAddress { bytes: None });
    }
    
    let parts: Vec<&str> = mac_str.split(':').collect();
    if parts.len() != 6 {
        return Err(ParseError::InvalidMacFormat);
    }
    
    let mut bytes = [0u8; 6];
    for (i, part) in parts.iter().enumerate() {
        bytes[i] = u8::from_str_radix(part, 16).map_err(|_| ParseError::InvalidNumber)?;
    }
    
    Ok(ParsedMacAddress { bytes: Some(bytes) })
}

fn parse_ip_address(pair: pest::iterators::Pair<'_, Rule>) -> Result<ParsedIpAddress, ParseError> {
    let ip_str = pair.as_str();
    
    if ip_str == "*" {
        return Ok(ParsedIpAddress { addr: None, cidr: None });
    }
    
    if let Some(cidr_pos) = ip_str.find('/') {
        let (addr_str, cidr_str) = ip_str.split_at(cidr_pos);
        let addr = parse_ipv4_bytes(addr_str)?;
        let cidr = cidr_str[1..].parse::<u8>().map_err(|_| ParseError::InvalidNumber)?;
        
        if cidr > 32 {
            return Err(ParseError::InvalidCidr);
        }
        
        Ok(ParsedIpAddress {
            addr: Some(addr),
            cidr: Some(cidr),
        })
    } else {
        let addr = parse_ipv4_bytes(ip_str)?;
        Ok(ParsedIpAddress {
            addr: Some(addr),
            cidr: None,
        })
    }
}

fn parse_ipv4_bytes(ip_str: &str) -> Result<[u8; 4], ParseError> {
    let parts: Vec<&str> = ip_str.split('.').collect();
    if parts.len() != 4 {
        return Err(ParseError::InvalidIpFormat);
    }
    
    let mut bytes = [0u8; 4];
    for (i, part) in parts.iter().enumerate() {
        bytes[i] = part.parse::<u8>().map_err(|_| ParseError::InvalidNumber)?;
    }
    
    Ok(bytes)
}

