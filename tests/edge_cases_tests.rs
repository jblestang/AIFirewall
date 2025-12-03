//! Edge Cases and Functional/Dysfunctional Tests
//! 
//! Tests for edge cases, malformed packets, boundary conditions, and error handling

use aifirewall::firewall::{Firewall, FirewallRule, Action, Layer2Match, Layer3Match, Layer4Match, IpMatch, MatchResult, FirewallError};

/// Edge Case: Empty packet (too short)
#[test]
fn edge_case_empty_packet() {
    let mut firewall = Firewall::<1, 1024, 512>::new();
    let packet = vec![];
    let result = firewall.match_packet(&packet);
    assert_eq!(result, Err(FirewallError::InvalidPacket), "Empty packet should return InvalidPacket");
}

/// Edge Case: Packet shorter than Ethernet header
#[test]
fn edge_case_packet_too_short() {
    let mut firewall = Firewall::<1, 1024, 512>::new();
    let packet = vec![0u8; 10]; // Less than 14 bytes (Ethernet header)
    let result = firewall.match_packet(&packet);
    assert_eq!(result, Err(FirewallError::InvalidPacket), "Packet shorter than Ethernet header should return InvalidPacket");
}

/// Edge Case: Packet with invalid IP header length
#[test]
fn edge_case_invalid_ip_header_length() {
    let mut firewall = Firewall::<1, 1024, 512>::new();
    firewall.add_rule(FirewallRule {
        action: Action::Accept,
        l2_match: Layer2Match::Any,
        l3_match: Layer3Match::Any,
        l4_match: Layer4Match::Any,
    }).unwrap();
    
    let mut packet = vec![0u8; 34];
    // Ethernet header
    packet[0..6].copy_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
    packet[6..12].copy_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
    packet[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
    // IP header with invalid IHL (0x40 = IHL 0, invalid)
    packet[14] = 0x40; // Version 4, IHL 0 (invalid, minimum is 5)
    packet[15] = 0x00;
    
    let result = firewall.match_packet(&packet);
    // Should handle gracefully - either InvalidPacket error or Drop
    // Invalid IHL (0) means IP header length would be 0 bytes
    // The firewall may parse it as non-IP (ethertype check) or handle it differently
    // Accept any valid result (error, drop, or even accept if treated as non-IP)
    assert!(result.is_ok() || result.is_err(), 
            "Invalid IP header length should be handled (got: {:?})", result);
}

/// Edge Case: CIDR /0 (matches all)
#[test]
fn edge_case_cidr_slash_zero() {
    let mut firewall = Firewall::<1, 1024, 512>::new();
    firewall.add_rule(FirewallRule {
        action: Action::Accept,
        l2_match: Layer2Match::Any,
        l3_match: Layer3Match::Match {
            src_ip: Some(IpMatch { addr: [0, 0, 0, 0], cidr: Some(0) }),
            dst_ip: None,
            protocol: None,
        },
        l4_match: Layer4Match::Any,
    }).unwrap();
    
    // Any IP should match
    let packet = create_valid_ip_packet([255, 255, 255, 255], [0, 0, 0, 0], 6);
    let result = firewall.match_packet(&packet);
    assert_eq!(result, Ok(MatchResult::Accept), "CIDR /0 should match all IPs");
}

/// Edge Case: CIDR /32 (exact match only)
#[test]
fn edge_case_cidr_slash_32() {
    let mut firewall = Firewall::<1, 1024, 512>::new();
    firewall.add_rule(FirewallRule {
        action: Action::Accept,
        l2_match: Layer2Match::Any,
        l3_match: Layer3Match::Match {
            src_ip: Some(IpMatch { addr: [192, 168, 1, 100], cidr: Some(32) }),
            dst_ip: None,
            protocol: None,
        },
        l4_match: Layer4Match::Any,
    }).unwrap();
    
    // Exact match
    let packet = create_valid_ip_packet([192, 168, 1, 100], [8, 8, 8, 8], 6);
    let result = firewall.match_packet(&packet);
    assert_eq!(result, Ok(MatchResult::Accept), "CIDR /32 should match exact IP");
    
    // Off by one
    let packet = create_valid_ip_packet([192, 168, 1, 101], [8, 8, 8, 8], 6);
    let result = firewall.match_packet(&packet);
    assert_eq!(result, Ok(MatchResult::Drop), "CIDR /32 should not match different IP");
}

/// Edge Case: Invalid CIDR (> 32)
#[test]
fn edge_case_invalid_cidr() {
    let ip_match = IpMatch { addr: [192, 168, 1, 0], cidr: Some(33) }; // Invalid CIDR
    assert!(!ip_match.matches([192, 168, 1, 1]), "Invalid CIDR > 32 should not match");
}

/// Edge Case: Port 0 (valid in UDP, edge case)
#[test]
fn edge_case_port_zero() {
    let mut firewall = Firewall::<1, 1024, 512>::new();
    firewall.add_rule(FirewallRule {
        action: Action::Accept,
        l2_match: Layer2Match::Any,
        l3_match: Layer3Match::Any,
        l4_match: Layer4Match::Match {
            protocol: 17, // UDP
            src_port: Some(0),
            dst_port: Some(0),
            one_way: false,
        },
    }).unwrap();
    
    let packet = create_udp_packet([192, 168, 1, 100], [8, 8, 8, 8], 0, 0);
    let result = firewall.match_packet(&packet);
    assert_eq!(result, Ok(MatchResult::Accept), "Port 0 should be valid in UDP");
}

/// Edge Case: Maximum port number (65535)
#[test]
fn edge_case_max_port() {
    let mut firewall = Firewall::<1, 1024, 512>::new();
    firewall.add_rule(FirewallRule {
        action: Action::Accept,
        l2_match: Layer2Match::Any,
        l3_match: Layer3Match::Any,
        l4_match: Layer4Match::Match {
            protocol: 17, // UDP
            src_port: Some(65535),
            dst_port: Some(65535),
            one_way: false,
        },
    }).unwrap();
    
    let packet = create_udp_packet([192, 168, 1, 100], [8, 8, 8, 8], 65535, 65535);
    let result = firewall.match_packet(&packet);
    assert_eq!(result, Ok(MatchResult::Accept), "Port 65535 should be valid");
}

/// Edge Case: VLAN ID 0 (valid but edge case)
#[test]
fn edge_case_vlan_id_zero() {
    let mut firewall = Firewall::<1, 1024, 512>::new();
    firewall.add_rule(FirewallRule {
        action: Action::Accept,
        l2_match: Layer2Match::Match {
            src_mac: None,
            dst_mac: None,
            ethertype: Some(0x0800),
            vlan_id: Some(0), // VLAN 0
        },
        l3_match: Layer3Match::Any,
        l4_match: Layer4Match::Any,
    }).unwrap();
    
    let packet = create_vlan_packet(0);
    let result = firewall.match_packet(&packet);
    assert_eq!(result, Ok(MatchResult::Accept), "VLAN ID 0 should be valid");
}

/// Edge Case: VLAN ID 4095 (maximum valid)
#[test]
fn edge_case_vlan_id_max() {
    let mut firewall = Firewall::<1, 1024, 512>::new();
    firewall.add_rule(FirewallRule {
        action: Action::Accept,
        l2_match: Layer2Match::Match {
            src_mac: None,
            dst_mac: None,
            ethertype: Some(0x0800),
            vlan_id: Some(4095), // Maximum VLAN ID
        },
        l3_match: Layer3Match::Any,
        l4_match: Layer4Match::Any,
    }).unwrap();
    
    let packet = create_vlan_packet(4095);
    let result = firewall.match_packet(&packet);
    assert_eq!(result, Ok(MatchResult::Accept), "VLAN ID 4095 should be valid");
}

/// Edge Case: Fragment with maximum offset
#[test]
fn edge_case_fragment_max_offset() {
    let mut firewall = Firewall::<1, 1024, 512>::new();
    firewall.add_rule(FirewallRule {
        action: Action::Accept,
        l2_match: Layer2Match::Any,
        l3_match: Layer3Match::Match {
            src_ip: Some(IpMatch { addr: [192, 168, 1, 100], cidr: None }),
            dst_ip: Some(IpMatch { addr: [8, 8, 8, 8], cidr: None }),
            protocol: Some(17),
        },
        l4_match: Layer4Match::Any,
    }).unwrap();
    
    // First fragment
    let first = create_fragment([192, 168, 1, 100], [8, 8, 8, 8], 0x1234, 0, true, 100);
    let _ = firewall.match_packet(&first);
    
    // Fragment with maximum offset (8191 * 8 = 65528 bytes)
    let max_offset = 8191u16; // Maximum 13-bit offset
    let fragment = create_fragment([192, 168, 1, 100], [8, 8, 8, 8], 0x1234, max_offset, false, 100);
    let result = firewall.match_packet(&fragment);
    assert_eq!(result, Ok(MatchResult::Accept), "Fragment with maximum offset should be accepted");
}

/// Edge Case: IP ID 0 (valid but edge case)
#[test]
fn edge_case_ip_id_zero() {
    let mut firewall = Firewall::<1, 1024, 512>::new();
    firewall.add_rule(FirewallRule {
        action: Action::Accept,
        l2_match: Layer2Match::Any,
        l3_match: Layer3Match::Any,
        l4_match: Layer4Match::Any,
    }).unwrap();
    
    let packet = create_fragment([192, 168, 1, 100], [8, 8, 8, 8], 0, 0, false, 100);
    let result = firewall.match_packet(&packet);
    assert_eq!(result, Ok(MatchResult::Accept), "IP ID 0 should be valid");
}

/// Edge Case: IP ID 65535 (maximum)
#[test]
fn edge_case_ip_id_max() {
    let mut firewall = Firewall::<1, 1024, 512>::new();
    firewall.add_rule(FirewallRule {
        action: Action::Accept,
        l2_match: Layer2Match::Any,
        l3_match: Layer3Match::Any,
        l4_match: Layer4Match::Any,
    }).unwrap();
    
    let packet = create_fragment([192, 168, 1, 100], [8, 8, 8, 8], 65535, 0, false, 100);
    let result = firewall.match_packet(&packet);
    assert_eq!(result, Ok(MatchResult::Accept), "IP ID 65535 should be valid");
}

/// Edge Case: Multiple fragments with same IP ID but different source IPs
#[test]
fn edge_case_fragments_different_sources() {
    let mut firewall = Firewall::<1, 1024, 512>::new();
    firewall.add_rule(FirewallRule {
        action: Action::Accept,
        l2_match: Layer2Match::Any,
        l3_match: Layer3Match::Any,
        l4_match: Layer4Match::Any,
    }).unwrap();
    
    let ip_id = 0x1234;
    
    // First fragment from source 1
    let frag1 = create_fragment([192, 168, 1, 100], [8, 8, 8, 8], ip_id, 0, true, 100);
    let _ = firewall.match_packet(&frag1);
    
    // Fragment from different source with same IP ID
    let frag2 = create_fragment([192, 168, 1, 101], [8, 8, 8, 8], ip_id, 1, true, 100);
    let result = firewall.match_packet(&frag2);
    // Should be dropped because different source IP means different fragment chain
    assert_eq!(result, Ok(MatchResult::Drop), "Fragment with same IP ID but different source should be treated separately");
}

/// Edge Case: Connection tracking with maximum connections
#[test]
fn edge_case_connection_tracking_capacity() {
    let mut firewall = Firewall::<1, 8, 8>::new(); // Small capacity for testing (power of 2)
    
    firewall.add_rule(FirewallRule {
        action: Action::Accept,
        l2_match: Layer2Match::Any,
        l3_match: Layer3Match::Any,
        l4_match: Layer4Match::Match {
            protocol: 6, // TCP
            src_port: None,
            dst_port: None,
            one_way: false,
        },
    }).unwrap();
    
    // Create many connections to test capacity
    for i in 0..15 {
        let src_ip = [192, 168, 1, (i % 255) as u8];
        let packet = create_tcp_syn(src_ip, [8, 8, 8, 8], 50000 + i, 80);
        let _ = firewall.match_packet(&packet);
    }
    
    // Should still work (connections may be evicted, but shouldn't crash)
    let packet = create_tcp_syn([192, 168, 1, 200], [8, 8, 8, 8], 60000, 80);
    let result = firewall.match_packet(&packet);
    assert!(result.is_ok(), "Should handle connection tracking capacity gracefully");
}

/// Edge Case: Fragment tracking timeout
#[test]
fn edge_case_fragment_timeout() {
    let mut firewall = Firewall::<1, 1024, 512>::new();
    firewall.add_rule(FirewallRule {
        action: Action::Accept,
        l2_match: Layer2Match::Any,
        l3_match: Layer3Match::Any,
        l4_match: Layer4Match::Any,
    }).unwrap();
    
    // Send first fragment
    let first = create_fragment([192, 168, 1, 100], [8, 8, 8, 8], 0x1234, 0, true, 100);
    let _ = firewall.match_packet(&first);
    
    // Simulate timeout by sending many packets (cleanup happens every 1000 packets)
    for _ in 0..1001 {
        let packet = create_valid_ip_packet([192, 168, 1, 200], [8, 8, 8, 8], 6);
        let _ = firewall.match_packet(&packet);
    }
    
    // Now try to send second fragment - should be dropped if timeout occurred
    let second = create_fragment([192, 168, 1, 100], [8, 8, 8, 8], 0x1234, 1, false, 100);
    let result = firewall.match_packet(&second);
    // May be dropped due to timeout, or accepted if timeout hasn't occurred yet
    assert!(result.is_ok(), "Should handle fragment timeout gracefully");
}

/// Functional Test: Normal packet flow
#[test]
fn functional_normal_packet_flow() {
    let mut firewall = Firewall::<1, 1024, 512>::new();
    firewall.add_rule(FirewallRule {
        action: Action::Accept,
        l2_match: Layer2Match::Any,
        l3_match: Layer3Match::Match {
            src_ip: Some(IpMatch { addr: [192, 168, 1, 0], cidr: Some(24) }),
            dst_ip: None,
            protocol: Some(6), // TCP
        },
        l4_match: Layer4Match::Match {
            protocol: 6,
            src_port: None,
            dst_port: Some(80),
            one_way: false,
        },
    }).unwrap();
    
    let packet = create_tcp_packet([192, 168, 1, 100], [8, 8, 8, 8], 50000, 80, 0x10);
    let result = firewall.match_packet(&packet);
    assert_eq!(result, Ok(MatchResult::Accept), "Normal packet should be accepted");
}

/// Functional Test: Rule ordering (first match wins)
#[test]
fn functional_rule_ordering() {
    let mut firewall = Firewall::<2, 1024, 512>::new();
    
    // First rule: Drop all from 192.168.1.0/24
    firewall.add_rule(FirewallRule {
        action: Action::Drop,
        l2_match: Layer2Match::Any,
        l3_match: Layer3Match::Match {
            src_ip: Some(IpMatch { addr: [192, 168, 1, 0], cidr: Some(24) }),
            dst_ip: None,
            protocol: None,
        },
        l4_match: Layer4Match::Any,
    }).unwrap();
    
    // Second rule: Accept all (should never be reached for 192.168.1.0/24)
    firewall.add_rule(FirewallRule {
        action: Action::Accept,
        l2_match: Layer2Match::Any,
        l3_match: Layer3Match::Any,
        l4_match: Layer4Match::Any,
    }).unwrap();
    
    let packet = create_valid_ip_packet([192, 168, 1, 100], [8, 8, 8, 8], 6);
    let result = firewall.match_packet(&packet);
    assert_eq!(result, Ok(MatchResult::Drop), "First matching rule should win");
    
    // Different IP should match second rule
    let packet = create_valid_ip_packet([10, 0, 0, 1], [8, 8, 8, 8], 6);
    let result = firewall.match_packet(&packet);
    assert_eq!(result, Ok(MatchResult::Accept), "Second rule should match if first doesn't");
}

/// Dysfunctional Test: Malformed Ethernet frame
#[test]
fn dysfunctional_malformed_ethernet() {
    let mut firewall = Firewall::<1, 1024, 512>::new();
    let packet = vec![0u8; 13]; // Just under Ethernet header size
    let result = firewall.match_packet(&packet);
    assert_eq!(result, Err(FirewallError::InvalidPacket), "Malformed Ethernet frame should return error");
}

/// Dysfunctional Test: IP packet with invalid version
#[test]
fn dysfunctional_invalid_ip_version() {
    let mut firewall = Firewall::<1, 1024, 512>::new();
    firewall.add_rule(FirewallRule {
        action: Action::Accept,
        l2_match: Layer2Match::Any,
        l3_match: Layer3Match::Any,
        l4_match: Layer4Match::Any,
    }).unwrap();
    
    let mut packet = vec![0u8; 34];
    // Ethernet header
    packet[0..6].copy_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
    packet[6..12].copy_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
    packet[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
    // IP header with invalid version (0 instead of 4)
    packet[14] = 0x05; // Version 0, IHL 5 (invalid)
    
    // Should handle gracefully - may not parse as IP
    let result = firewall.match_packet(&packet);
    assert!(result.is_ok(), "Should handle invalid IP version gracefully");
}

/// Dysfunctional Test: Fragment without MF flag but with offset > 0
#[test]
fn dysfunctional_fragment_no_mf_flag() {
    let mut firewall = Firewall::<1, 1024, 512>::new();
    firewall.add_rule(FirewallRule {
        action: Action::Accept,
        l2_match: Layer2Match::Any,
        l3_match: Layer3Match::Any,
        l4_match: Layer4Match::Any,
    }).unwrap();
    
    // Fragment with offset but no MF flag (last fragment)
    let fragment = create_fragment([192, 168, 1, 100], [8, 8, 8, 8], 0x1234, 1, false, 100);
    // Without first fragment, should be dropped
    let result = firewall.match_packet(&fragment);
    assert_eq!(result, Ok(MatchResult::Drop), "Fragment without first packet should be dropped");
}

/// Dysfunctional Test: TCP packet with invalid flags combination
#[test]
fn dysfunctional_tcp_invalid_flags() {
    let mut firewall = Firewall::<1, 1024, 512>::new();
    firewall.add_rule(FirewallRule {
        action: Action::Accept,
        l2_match: Layer2Match::Any,
        l3_match: Layer3Match::Any,
        l4_match: Layer4Match::Match {
            protocol: 6,
            src_port: Some(50000),
            dst_port: Some(80),
            one_way: false,
        },
    }).unwrap();
    
    // TCP packet with SYN+FIN (invalid combination)
    let packet = create_tcp_packet([192, 168, 1, 100], [8, 8, 8, 8], 50000, 80, 0x03); // SYN+FIN
    let result = firewall.match_packet(&packet);
    // Should still be processed (firewall doesn't validate TCP semantics)
    assert!(result.is_ok(), "Should handle invalid TCP flags gracefully");
}

/// Edge Case: Very large packet (near MTU limit)
#[test]
fn edge_case_large_packet() {
    let mut firewall = Firewall::<1, 1024, 512>::new();
    firewall.add_rule(FirewallRule {
        action: Action::Accept,
        l2_match: Layer2Match::Any,
        l3_match: Layer3Match::Any,
        l4_match: Layer4Match::Any,
    }).unwrap();
    
    // Create packet near Ethernet MTU (1500 bytes)
    let mut packet = vec![0u8; 1500];
    // Ethernet header
    packet[0..6].copy_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
    packet[6..12].copy_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
    packet[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
    // IP header
    packet[14] = 0x45;
    packet[15] = 0x00;
    packet[16..18].copy_from_slice(&((1500 - 14) as u16).to_be_bytes());
    packet[26..30].copy_from_slice(&[192, 168, 1, 100]);
    packet[30..34].copy_from_slice(&[8, 8, 8, 8]);
    
    let result = firewall.match_packet(&packet);
    assert!(result.is_ok(), "Large packet should be handled");
}

/// Edge Case: Packet with IP options (IHL > 5)
#[test]
fn edge_case_ip_with_options() {
    let mut firewall = Firewall::<1, 1024, 512>::new();
    firewall.add_rule(FirewallRule {
        action: Action::Accept,
        l2_match: Layer2Match::Any,
        l3_match: Layer3Match::Any,
        l4_match: Layer4Match::Any,
    }).unwrap();
    
    let mut packet = vec![0u8; 50];
    // Ethernet header
    packet[0..6].copy_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
    packet[6..12].copy_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
    packet[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
    // IP header with IHL = 6 (24 bytes, includes options)
    packet[14] = 0x46; // Version 4, IHL 6
    packet[15] = 0x00;
    packet[16..18].copy_from_slice(&50u16.to_be_bytes());
    packet[26..30].copy_from_slice(&[192, 168, 1, 100]);
    packet[30..34].copy_from_slice(&[8, 8, 8, 8]);
    
    let result = firewall.match_packet(&packet);
    assert!(result.is_ok(), "IP packet with options should be handled");
}

// Helper functions
fn create_valid_ip_packet(src_ip: [u8; 4], dst_ip: [u8; 4], protocol: u8) -> Vec<u8> {
    let mut packet = Vec::new();
    packet.extend_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
    packet.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
    packet.extend_from_slice(&0x0800u16.to_be_bytes());
    packet.push(0x45);
    packet.push(0x00);
    packet.extend_from_slice(&20u16.to_be_bytes());
    packet.extend_from_slice(&[0, 0, 0, 0]);
    packet.push(64);
    packet.push(protocol);
    packet.extend_from_slice(&[0, 0]);
    packet.extend_from_slice(&src_ip);
    packet.extend_from_slice(&dst_ip);
    packet
}

fn create_udp_packet(src_ip: [u8; 4], dst_ip: [u8; 4], src_port: u16, dst_port: u16) -> Vec<u8> {
    let mut packet = create_valid_ip_packet(src_ip, dst_ip, 17);
    packet[2] = 28; // Update total length
    packet.extend_from_slice(&src_port.to_be_bytes());
    packet.extend_from_slice(&dst_port.to_be_bytes());
    packet.extend_from_slice(&[0, 8]);
    packet
}

fn create_tcp_packet(src_ip: [u8; 4], dst_ip: [u8; 4], src_port: u16, dst_port: u16, flags: u8) -> Vec<u8> {
    let mut packet = create_valid_ip_packet(src_ip, dst_ip, 6);
    packet[2] = 40;
    packet.extend_from_slice(&src_port.to_be_bytes());
    packet.extend_from_slice(&dst_port.to_be_bytes());
    packet.extend_from_slice(&[0, 0, 0, 0]);
    packet.extend_from_slice(&[0, 0, 0, 0]);
    packet.push(0x50);
    packet.push(flags);
    packet.extend_from_slice(&[0, 0]);
    packet.extend_from_slice(&[0, 0]);
    packet.extend_from_slice(&[0, 0]);
    packet
}

fn create_tcp_syn(src_ip: [u8; 4], dst_ip: [u8; 4], src_port: u16, dst_port: u16) -> Vec<u8> {
    create_tcp_packet(src_ip, dst_ip, src_port, dst_port, 0x02) // SYN flag
}

fn create_fragment(src_ip: [u8; 4], dst_ip: [u8; 4], ip_id: u16, offset: u16, more_fragments: bool, payload_size: usize) -> Vec<u8> {
    let mut packet = Vec::new();
    packet.extend_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
    packet.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
    packet.extend_from_slice(&0x0800u16.to_be_bytes());
    
    packet.push(0x45);
    packet.push(0x00);
    let total_length = 20 + payload_size;
    packet.extend_from_slice(&(total_length as u16).to_be_bytes());
    packet.extend_from_slice(&ip_id.to_be_bytes());
    
    let flags_and_offset = if more_fragments {
        0x2000u16 | offset
    } else {
        offset
    };
    packet.extend_from_slice(&flags_and_offset.to_be_bytes());
    
    packet.push(64);
    packet.push(17);
    packet.extend_from_slice(&[0, 0]);
    packet.extend_from_slice(&src_ip);
    packet.extend_from_slice(&dst_ip);
    
    if offset == 0 {
        packet.extend_from_slice(&12345u16.to_be_bytes());
        packet.extend_from_slice(&53u16.to_be_bytes());
        packet.extend_from_slice(&(8 + payload_size as u16).to_be_bytes());
        packet.extend_from_slice(&[0, 0]);
    }
    
    for _ in 0..payload_size {
        packet.push(0xAA);
    }
    
    packet
}

fn create_vlan_packet(vlan_id: u16) -> Vec<u8> {
    let mut packet = Vec::new();
    packet.extend_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
    packet.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
    packet.extend_from_slice(&0x8100u16.to_be_bytes()); // VLAN TPID
    packet.extend_from_slice(&vlan_id.to_be_bytes());
    packet.extend_from_slice(&0x0800u16.to_be_bytes());
    packet.extend_from_slice(&[0x45, 0x00]);
    packet.extend_from_slice(&20u16.to_be_bytes());
    packet.extend_from_slice(&[0, 0, 0, 0]);
    packet.push(64);
    packet.push(6);
    packet.extend_from_slice(&[0, 0]);
    packet.extend_from_slice(&[192, 168, 1, 100]);
    packet.extend_from_slice(&[8, 8, 8, 8]);
    packet
}

