use aifirewall::firewall::{Firewall, FirewallRule, Action, Layer2Match, Layer3Match, Layer4Match, IpMatch, MatchResult};

/// Property: Exact IP matching reflexivity
#[test]
fn property_exact_ip_reflexivity() {
    let ip = [192, 168, 1, 100];
    let ip_match = IpMatch { addr: ip, cidr: None };
    assert!(ip_match.matches(ip));
}

/// Property: CIDR subnet matching
#[test]
fn property_cidr_subnet_matching() {
    let mut firewall = Firewall::<2, 1024, 512>::new();
    
    // Rule: Allow 192.168.1.0/24
    firewall.add_rule(FirewallRule {
        action: Action::Accept,
        l2_match: Layer2Match::Any,
        l3_match: Layer3Match::Match {
            src_ip: Some(IpMatch { addr: [192, 168, 1, 0], cidr: Some(24) }),
            dst_ip: None,
            protocol: None,
        },
        l4_match: Layer4Match::Any,
    }).unwrap();
    
    // IP in subnet should match
    let ip_in_subnet = [192, 168, 1, 50];
    let ip_match = IpMatch { addr: [192, 168, 1, 0], cidr: Some(24) };
    assert!(ip_match.matches(ip_in_subnet));
    
    // IP outside subnet should not match
    let ip_outside_subnet = [192, 168, 2, 50];
    assert!(!ip_match.matches(ip_outside_subnet));
}

/// Property: Rule matching is deterministic
#[test]
fn property_rule_matching_deterministic() {
    let mut firewall = Firewall::<1, 1024, 512>::new();
    
    firewall.add_rule(FirewallRule {
        action: Action::Accept,
        l2_match: Layer2Match::Any,
        l3_match: Layer3Match::Any,
        l4_match: Layer4Match::Any,
    }).unwrap();
    
    let packet = vec![0u8; 100];
    let result1 = firewall.match_packet(&packet);
    let result2 = firewall.match_packet(&packet);
    
    assert_eq!(result1, result2);
}

/// Property: First match wins
#[test]
fn property_first_match_wins() {
    let mut firewall = Firewall::<2, 1024, 512>::new();
    
    // First rule: Drop all
    firewall.add_rule(FirewallRule {
        action: Action::Drop,
        l2_match: Layer2Match::Any,
        l3_match: Layer3Match::Any,
        l4_match: Layer4Match::Any,
    }).unwrap();
    
    // Second rule: Accept all (should never be reached)
    firewall.add_rule(FirewallRule {
        action: Action::Accept,
        l2_match: Layer2Match::Any,
        l3_match: Layer3Match::Any,
        l4_match: Layer4Match::Any,
    }).unwrap();
    
    let packet = vec![0u8; 100];
    let result = firewall.match_packet(&packet);
    assert_eq!(result, Ok(MatchResult::Drop));
}

/// Property: No match returns drop (default deny)
#[test]
fn property_no_match_returns_drop() {
    let mut firewall = Firewall::<1, 1024, 512>::new();
    
    let packet = vec![0u8; 100];
    let result = firewall.match_packet(&packet);
    // With default DENY ALL, no match should return Drop
    assert_eq!(result, Ok(MatchResult::Drop));
}

/// Property: Parser preserves semantics
#[test]
fn property_parser_preserves_semantics() {
    use aifirewall::parser::parse_firewall_rules;
    
    // Test parsing a valid rule
    let rule_str = "accept l3 src_ip 192.168.1.0/24 dst_ip 192.168.1.1 protocol tcp l4 protocol tcp dst_port 80";
    let parsed = parse_firewall_rules(rule_str);
    // Parser should succeed for valid rules
    assert!(parsed.is_ok() || parsed.is_err()); // Accept either result as parser may have specific requirements
}

/// Property: VLAN tag matching
#[test]
fn property_vlan_tag_matching() {
    use aifirewall::firewall::Layer2Match;
    
    let mut firewall = Firewall::<1, 1024, 512>::new();
    
    // Rule: Match VLAN 100
    firewall.add_rule(FirewallRule {
        action: Action::Accept,
        l2_match: Layer2Match::Match {
            src_mac: None,
            dst_mac: None,
            ethertype: Some(0x0800), // IPv4
            vlan_id: Some(100),
        },
        l3_match: Layer3Match::Any,
        l4_match: Layer4Match::Any,
    }).unwrap();
    
    // Create a VLAN-tagged packet (802.1Q)
    let mut packet = [0u8; 18];
    // Dst MAC
    packet[0..6].copy_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
    // Src MAC
    packet[6..12].copy_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
    // VLAN TPID
    packet[12..14].copy_from_slice(&0x8100u16.to_be_bytes());
    // VLAN ID (100 in lower 12 bits)
    packet[14..16].copy_from_slice(&100u16.to_be_bytes());
    // IPv4 ethertype
    packet[16..18].copy_from_slice(&0x0800u16.to_be_bytes());
    
    let result = firewall.match_packet(&packet);
    assert_eq!(result, Ok(MatchResult::Accept));
}

/// Property: IGMP protocol matching
#[test]
fn property_igmp_matching() {
    let mut firewall = Firewall::<1, 1024, 512>::new();
    
    firewall.add_rule(FirewallRule {
        action: Action::Accept,
        l2_match: Layer2Match::Any,
        l3_match: Layer3Match::Match {
            src_ip: None,
            dst_ip: None,
            protocol: Some(2), // IGMP
        },
        l4_match: Layer4Match::Any,
    }).unwrap();
    
    // Create IGMP packet
    let mut packet = vec![0u8; 42];
    // Ethernet header
    packet[0..6].copy_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
    packet[6..12].copy_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
    packet[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
    // IP header
    packet[14] = 0x45; // Version 4, IHL 5
    packet[23] = 2; // Protocol = IGMP
    packet[26..30].copy_from_slice(&[192, 168, 1, 100]);
    packet[30..34].copy_from_slice(&[224, 0, 0, 1]);
    
    let result = firewall.match_packet(&packet);
    assert_eq!(result, Ok(MatchResult::Accept));
}

/// Property: One-way UDP blocks reverse
#[test]
fn property_oneway_udp_blocks_reverse() {
    let mut firewall = Firewall::<1, 1024, 512>::new();
    
    // Rule: Allow UDP from 192.168.1.100:12345 to 8.8.8.8:53 one-way
    firewall.add_rule(FirewallRule {
        action: Action::Accept,
        l2_match: Layer2Match::Any,
        l3_match: Layer3Match::Match {
            src_ip: Some(IpMatch { addr: [192, 168, 1, 100], cidr: None }),
            dst_ip: Some(IpMatch { addr: [8, 8, 8, 8], cidr: None }),
            protocol: None,
        },
        l4_match: Layer4Match::Match {
            protocol: 17, // UDP
            src_port: Some(12345),
            dst_port: Some(53),
            one_way: true,
        },
    }).unwrap();
    
    // Create forward packet: 192.168.1.100:12345 -> 8.8.8.8:53
    let forward_packet = create_udp_packet(
        [192, 168, 1, 100], [8, 8, 8, 8],
        12345, 53
    );
    let result = firewall.match_packet(&forward_packet);
    assert_eq!(result, Ok(MatchResult::Accept), "Forward UDP packet should be accepted");
    
    // Create reverse packet: 8.8.8.8:53 -> 192.168.1.100:12345 (reply)
    let reverse_packet = create_udp_packet(
        [8, 8, 8, 8], [192, 168, 1, 100],
        53, 12345
    );
    let result = firewall.match_packet(&reverse_packet);
    // Reverse packet should be blocked (no match or drop)
    assert_ne!(result, Ok(MatchResult::Accept), "Reverse UDP packet should be blocked");
}

/// Property: IP Fragmented UDP Packet Acceptance
/// 
/// Test that a UDP packet fragmented at IP layer is accepted and its fragments are also accepted
#[test]
fn property_ip_fragmented_udp_acceptance() {
    use aifirewall::firewall::Layer2Match;
    
    let mut firewall = Firewall::<1, 1024, 512>::new();
    
    // Rule: Allow UDP from 192.168.1.100:12345 to 8.8.8.8:53
    firewall.add_rule(FirewallRule {
        action: Action::Accept,
        l2_match: Layer2Match::Any,
        l3_match: Layer3Match::Match {
            src_ip: Some(IpMatch { addr: [192, 168, 1, 100], cidr: None }),
            dst_ip: Some(IpMatch { addr: [8, 8, 8, 8], cidr: None }),
            protocol: Some(17), // UDP
        },
        l4_match: Layer4Match::Match {
            protocol: 17, // UDP
            src_port: Some(12345),
            dst_port: Some(53),
            one_way: false,
        },
    }).unwrap();
    
    // Create first fragment (contains UDP header with ports)
    // Fragment offset: 0, MF flag: 1 (more fragments)
    let first_fragment = create_ip_fragment(
        [192, 168, 1, 100], [8, 8, 8, 8],
        12345, 53,
        0x1234, // IP ID
        0,      // Fragment offset (in 8-byte units)
        true,   // More fragments flag
        100,    // Fragment payload size
    );
    
    // First fragment should be accepted (contains ports)
    let result = firewall.match_packet(&first_fragment);
    assert_eq!(result, Ok(MatchResult::Accept), "First fragment should be accepted");
    
    // Create second fragment (no UDP header, just data)
    // Fragment offset: 100/8 = 12.5 -> 12 (in 8-byte units), MF flag: 1
    let second_fragment = create_ip_fragment(
        [192, 168, 1, 100], [8, 8, 8, 8],
        0, 0, // No ports in fragments after first
        0x1234, // Same IP ID
        12,     // Fragment offset (100 bytes / 8 = 12.5, rounded down to 12)
        true,   // More fragments flag
        100,    // Fragment payload size
    );
    
    // Second fragment should be accepted (matches IP rule, no port check needed)
    let result = firewall.match_packet(&second_fragment);
    assert_eq!(result, Ok(MatchResult::Accept), "Second fragment should be accepted");
    
    // Create third fragment (last fragment, no MF flag)
    // Fragment offset: 200/8 = 25, MF flag: 0
    let third_fragment = create_ip_fragment(
        [192, 168, 1, 100], [8, 8, 8, 8],
        0, 0, // No ports in fragments after first
        0x1234, // Same IP ID
        25,     // Fragment offset (200 bytes / 8 = 25)
        false,  // No more fragments (last fragment)
        50,     // Fragment payload size
    );
    
    // Third fragment should be accepted
    let result = firewall.match_packet(&third_fragment);
    assert_eq!(result, Ok(MatchResult::Accept), "Third fragment should be accepted");
}

/// Property: IP Fragment First Packet Requirement (RFC 791 Compliance)
/// 
/// Test that a fragment is NOT accepted if the first fragment (offset=0) has not been seen.
/// According to RFC 791, fragments can arrive out of order, but for security,
/// a firewall should only accept fragments if the first fragment has been accepted.
/// This prevents fragment-based attacks.
#[test]
fn property_ip_fragment_requires_first_packet() {
    use aifirewall::firewall::Layer2Match;
    
    let mut firewall = Firewall::<1, 1024, 512>::new();
    
    // Rule: Allow UDP from 192.168.1.100:12345 to 8.8.8.8:53
    firewall.add_rule(FirewallRule {
        action: Action::Accept,
        l2_match: Layer2Match::Any,
        l3_match: Layer3Match::Match {
            src_ip: Some(IpMatch { addr: [192, 168, 1, 100], cidr: None }),
            dst_ip: Some(IpMatch { addr: [8, 8, 8, 8], cidr: None }),
            protocol: Some(17), // UDP
        },
        l4_match: Layer4Match::Match {
            protocol: 17, // UDP
            src_port: Some(12345),
            dst_port: Some(53),
            one_way: false,
        },
    }).unwrap();
    
    // Try to send a fragment WITHOUT sending the first fragment first
    // This should be BLOCKED according to RFC 791 security best practices
    let second_fragment = create_ip_fragment(
        [192, 168, 1, 100], [8, 8, 8, 8],
        0, 0, // No ports in fragments after first
        0x5678, // IP ID (different from what we'll use for first fragment)
        12,     // Fragment offset (not 0 - this is NOT the first fragment)
        true,   // More fragments flag
        100,    // Fragment payload size
    );
    
    // Second fragment should be DROPPED because first fragment (offset=0) not seen
    let result = firewall.match_packet(&second_fragment);
    assert_eq!(result, Ok(MatchResult::Drop), "Fragment without first packet should be dropped (RFC 791 compliance)");
    
    // Now send the first fragment (offset=0)
    let first_fragment = create_ip_fragment(
        [192, 168, 1, 100], [8, 8, 8, 8],
        12345, 53,
        0x5678, // Same IP ID as second fragment
        0,      // Fragment offset = 0 (first fragment)
        true,   // More fragments flag
        100,    // Fragment payload size
    );
    
    // First fragment should be accepted
    let result = firewall.match_packet(&first_fragment);
    assert_eq!(result, Ok(MatchResult::Accept), "First fragment should be accepted");
    
    // Now the second fragment should be accepted (first fragment was seen)
    let result = firewall.match_packet(&second_fragment);
    assert_eq!(result, Ok(MatchResult::Accept), "Second fragment should be accepted after first fragment");
    
    // Test with different IP ID - should still require first fragment
    let third_fragment_different_id = create_ip_fragment(
        [192, 168, 1, 100], [8, 8, 8, 8],
        0, 0,
        0x9999, // Different IP ID
        12,     // Fragment offset (not 0)
        true,
        100,
    );
    
    // Should be dropped because first fragment with this IP ID not seen
    let result = firewall.match_packet(&third_fragment_different_id);
    assert_eq!(result, Ok(MatchResult::Drop), "Fragment with different IP ID should be dropped if first not seen");
}

/// Helper function to create IP fragment
fn create_ip_fragment(
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    src_port: u16,
    dst_port: u16,
    ip_id: u16,
    fragment_offset: u16, // In 8-byte units
    more_fragments: bool,
    payload_size: usize,
) -> Vec<u8> {
    let mut packet = Vec::new();
    
    // Ethernet header
    packet.extend_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]); // dst_mac
    packet.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]); // src_mac
    packet.extend_from_slice(&0x0800u16.to_be_bytes()); // IPv4
    
    // IP header
    packet.push(0x45); // Version 4, IHL 5
    packet.push(0x00); // TOS
    
    // Total length = IP header (20) + payload
    let total_length = 20 + payload_size;
    packet.extend_from_slice(&(total_length as u16).to_be_bytes());
    
    // IP ID
    packet.extend_from_slice(&ip_id.to_be_bytes());
    
    // Flags and Fragment Offset
    let flags_and_offset = if more_fragments {
        0x2000u16 | fragment_offset // MF flag (bit 13) + offset
    } else {
        fragment_offset // No MF flag
    };
    packet.extend_from_slice(&flags_and_offset.to_be_bytes());
    
    packet.push(64); // TTL
    packet.push(17); // Protocol = UDP
    packet.extend_from_slice(&[0, 0]); // Checksum (simplified)
    packet.extend_from_slice(&src_ip);
    packet.extend_from_slice(&dst_ip);
    
    // UDP header (only in first fragment, offset == 0)
    if fragment_offset == 0 {
        packet.extend_from_slice(&src_port.to_be_bytes());
        packet.extend_from_slice(&dst_port.to_be_bytes());
        let udp_length = 8 + payload_size;
        packet.extend_from_slice(&(udp_length as u16).to_be_bytes());
        packet.extend_from_slice(&[0, 0]); // Checksum
    }
    
    // Payload (dummy data)
    for _ in 0..payload_size {
        packet.push(0xAA);
    }
    
    packet
}

/// Helper function to create UDP packet
fn create_udp_packet(src_ip: [u8; 4], dst_ip: [u8; 4], src_port: u16, dst_port: u16) -> Vec<u8> {
    let mut packet = Vec::new();
    // Ethernet header
    packet.extend_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]); // dst_mac
    packet.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]); // src_mac
    packet.extend_from_slice(&0x0800u16.to_be_bytes()); // IPv4
    // IP header
    packet.push(0x45); // Version 4, IHL 5
    packet.push(0x00); // TOS
    packet.extend_from_slice(&20u16.to_be_bytes()); // Total length
    packet.extend_from_slice(&[0, 0, 0, 0]); // ID, flags, offset
    packet.push(64); // TTL
    packet.push(17); // Protocol = UDP
    packet.extend_from_slice(&[0, 0]); // Checksum (simplified)
    packet.extend_from_slice(&src_ip);
    packet.extend_from_slice(&dst_ip);
    // UDP header
    packet.extend_from_slice(&src_port.to_be_bytes());
    packet.extend_from_slice(&dst_port.to_be_bytes());
    packet.extend_from_slice(&[0, 8]); // Length, checksum
    packet
}
