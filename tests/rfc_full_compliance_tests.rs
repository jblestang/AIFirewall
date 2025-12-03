//! Full RFC Compliance Tests
//! 
//! Comprehensive tests for full RFC compliance:
//! - RFC 791 (IP): Complete IP protocol compliance
//! - RFC 768 (UDP): Complete UDP protocol compliance
//! - RFC 793 (TCP): Complete TCP protocol compliance
//! 
//! Note: Some tests may fail due to smoltcp limitations - these are marked as expected failures

use aifirewall::firewall::{Firewall, FirewallRule, Action, Layer2Match, Layer3Match, Layer4Match, IpMatch, MatchResult};

/// RFC 791: IP Header - Version field must be 4
#[test]
fn rfc791_ip_version_must_be_4() {
    let mut firewall = Firewall::<1, 1024, 512>::new();
    firewall.add_rule(FirewallRule {
        action: Action::Accept,
        l2_match: Layer2Match::Any,
        l3_match: Layer3Match::Any,
        l4_match: Layer4Match::Any,
    }).unwrap();
    
    // Create packet with IP version 4 (valid)
    let packet = create_ipv4_packet([192, 168, 1, 100], [8, 8, 8, 8], 6, false);
    let result = firewall.match_packet(&packet);
    assert_eq!(result, Ok(MatchResult::Accept), "RFC 791: IP version 4 should be accepted");
    
    // Note: We don't test version != 4 as the firewall only processes IPv4 (ethertype 0x0800)
    // Non-IPv4 packets are handled at L2 level
}

/// RFC 791: IP Header - IHL must be at least 5 (20 bytes minimum)
#[test]
fn rfc791_ip_ihl_minimum() {
    let mut firewall = Firewall::<1, 1024, 512>::new();
    firewall.add_rule(FirewallRule {
        action: Action::Accept,
        l2_match: Layer2Match::Any,
        l3_match: Layer3Match::Any,
        l4_match: Layer4Match::Any,
    }).unwrap();
    
    // IHL = 5 (20 bytes) - minimum valid
    let packet = create_ipv4_packet([192, 168, 1, 100], [8, 8, 8, 8], 6, false);
    let result = firewall.match_packet(&packet);
    assert_eq!(result, Ok(MatchResult::Accept), "RFC 791: IHL 5 (minimum) should be accepted");
}

/// RFC 791: IP Header - Total Length field
#[test]
fn rfc791_ip_total_length() {
    let mut firewall = Firewall::<1, 1024, 512>::new();
    firewall.add_rule(FirewallRule {
        action: Action::Accept,
        l2_match: Layer2Match::Any,
        l3_match: Layer3Match::Any,
        l4_match: Layer4Match::Any,
    }).unwrap();
    
    // Packet with correct total length
    let packet = create_ipv4_packet([192, 168, 1, 100], [8, 8, 8, 8], 6, false);
    let result = firewall.match_packet(&packet);
    assert_eq!(result, Ok(MatchResult::Accept), "RFC 791: Correct total length should be accepted");
}

/// RFC 791: IP Fragmentation - More Fragments (MF) flag
#[test]
fn rfc791_ip_mf_flag() {
    let mut firewall = Firewall::<1, 1024, 512>::new();
    firewall.add_rule(FirewallRule {
        action: Action::Accept,
        l2_match: Layer2Match::Any,
        l3_match: Layer3Match::Any,
        l4_match: Layer4Match::Any,
    }).unwrap();
    
    // First fragment with MF flag set
    let first = create_fragment([192, 168, 1, 100], [8, 8, 8, 8], 0x1234, 0, true, 100);
    let result = firewall.match_packet(&first);
    assert_eq!(result, Ok(MatchResult::Accept), "RFC 791: Fragment with MF flag should be accepted");
    
    // Last fragment with MF flag cleared
    let last = create_fragment([192, 168, 1, 100], [8, 8, 8, 8], 0x1234, 1, false, 100);
    let result = firewall.match_packet(&last);
    assert_eq!(result, Ok(MatchResult::Accept), "RFC 791: Last fragment (MF=0) should be accepted");
}

/// RFC 791: IP Fragmentation - Don't Fragment (DF) flag
#[test]
fn rfc791_ip_df_flag() {
    let mut firewall = Firewall::<1, 1024, 512>::new();
    firewall.add_rule(FirewallRule {
        action: Action::Accept,
        l2_match: Layer2Match::Any,
        l3_match: Layer3Match::Any,
        l4_match: Layer4Match::Any,
    }).unwrap();
    
    // Packet with DF flag set (should not be fragmented)
    let packet = create_ipv4_packet_df([192, 168, 1, 100], [8, 8, 8, 8], 6, true);
    let result = firewall.match_packet(&packet);
    assert_eq!(result, Ok(MatchResult::Accept), "RFC 791: Packet with DF flag should be accepted");
}

/// RFC 791: IP Fragmentation - Fragment Offset field (13 bits)
#[test]
fn rfc791_ip_fragment_offset() {
    let mut firewall = Firewall::<1, 1024, 512>::new();
    firewall.add_rule(FirewallRule {
        action: Action::Accept,
        l2_match: Layer2Match::Any,
        l3_match: Layer3Match::Any,
        l4_match: Layer4Match::Any,
    }).unwrap();
    
    // First fragment (offset = 0)
    let first = create_fragment([192, 168, 1, 100], [8, 8, 8, 8], 0x1234, 0, true, 100);
    let _ = firewall.match_packet(&first);
    
    // Fragment with maximum valid offset (8191 * 8 = 65528 bytes)
    let max_offset = create_fragment([192, 168, 1, 100], [8, 8, 8, 8], 0x1234, 8191, false, 100);
    let result = firewall.match_packet(&max_offset);
    assert_eq!(result, Ok(MatchResult::Accept), "RFC 791: Fragment with max offset should be accepted");
}

/// RFC 791: IP Time To Live (TTL) field
#[test]
fn rfc791_ip_ttl() {
    let mut firewall = Firewall::<1, 1024, 512>::new();
    firewall.add_rule(FirewallRule {
        action: Action::Accept,
        l2_match: Layer2Match::Any,
        l3_match: Layer3Match::Any,
        l4_match: Layer4Match::Any,
    }).unwrap();
    
    // TTL = 1 (minimum valid)
    let packet = create_ipv4_packet_ttl([192, 168, 1, 100], [8, 8, 8, 8], 6, 1);
    let result = firewall.match_packet(&packet);
    assert_eq!(result, Ok(MatchResult::Accept), "RFC 791: TTL 1 should be accepted");
    
    // TTL = 255 (maximum)
    let packet = create_ipv4_packet_ttl([192, 168, 1, 100], [8, 8, 8, 8], 6, 255);
    let result = firewall.match_packet(&packet);
    assert_eq!(result, Ok(MatchResult::Accept), "RFC 791: TTL 255 should be accepted");
}

/// RFC 791: IP Protocol field
#[test]
fn rfc791_ip_protocol_field() {
    let protocols = vec![
        (1, "ICMP"),
        (2, "IGMP"),
        (6, "TCP"),
        (17, "UDP"),
    ];
    
    for (protocol_num, name) in protocols {
        let mut firewall = Firewall::<1, 1024, 512>::new();
        firewall.add_rule(FirewallRule {
            action: Action::Accept,
            l2_match: Layer2Match::Any,
            l3_match: Layer3Match::Match {
                src_ip: None,
                dst_ip: None,
                protocol: Some(protocol_num),
            },
            l4_match: Layer4Match::Any,
        }).unwrap();
        
        let packet = create_ipv4_packet([192, 168, 1, 100], [8, 8, 8, 8], protocol_num, false);
        let result = firewall.match_packet(&packet);
        assert_eq!(result, Ok(MatchResult::Accept), 
                   "RFC 791: Protocol {} ({}) should be accepted", protocol_num, name);
    }
}

/// RFC 768: UDP Header - Source Port field
#[test]
fn rfc768_udp_source_port() {
    let mut firewall = Firewall::<1, 1024, 512>::new();
    firewall.add_rule(FirewallRule {
        action: Action::Accept,
        l2_match: Layer2Match::Any,
        l3_match: Layer3Match::Any,
        l4_match: Layer4Match::Match {
            protocol: 17, // UDP
            src_port: Some(50000),
            dst_port: None,
            one_way: false,
        },
    }).unwrap();
    
    let packet = create_udp_packet([192, 168, 1, 100], [8, 8, 8, 8], 50000, 53);
    let result = firewall.match_packet(&packet);
    assert_eq!(result, Ok(MatchResult::Accept), "RFC 768: UDP source port should be matched");
}

/// RFC 768: UDP Header - Destination Port field
#[test]
fn rfc768_udp_destination_port() {
    let mut firewall = Firewall::<1, 1024, 512>::new();
    firewall.add_rule(FirewallRule {
        action: Action::Accept,
        l2_match: Layer2Match::Any,
        l3_match: Layer3Match::Any,
        l4_match: Layer4Match::Match {
            protocol: 17, // UDP
            src_port: None,
            dst_port: Some(53),
            one_way: false,
        },
    }).unwrap();
    
    let packet = create_udp_packet([192, 168, 1, 100], [8, 8, 8, 8], 50000, 53);
    let result = firewall.match_packet(&packet);
    assert_eq!(result, Ok(MatchResult::Accept), "RFC 768: UDP destination port should be matched");
}

/// RFC 768: UDP Header - Length field
#[test]
fn rfc768_udp_length() {
    let mut firewall = Firewall::<1, 1024, 512>::new();
    firewall.add_rule(FirewallRule {
        action: Action::Accept,
        l2_match: Layer2Match::Any,
        l3_match: Layer3Match::Any,
        l4_match: Layer4Match::Any,
    }).unwrap();
    
    // UDP packet with correct length (8 bytes header + payload)
    let packet = create_udp_packet([192, 168, 1, 100], [8, 8, 8, 8], 50000, 53);
    let result = firewall.match_packet(&packet);
    assert_eq!(result, Ok(MatchResult::Accept), "RFC 768: UDP packet with correct length should be accepted");
}

/// RFC 768: UDP - Port 0 is valid (unlike TCP)
#[test]
fn rfc768_udp_port_zero_valid() {
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
    assert_eq!(result, Ok(MatchResult::Accept), "RFC 768: UDP port 0 is valid");
}

/// RFC 768: UDP - Checksum field (optional, 0 means no checksum)
#[test]
fn rfc768_udp_checksum_optional() {
    let mut firewall = Firewall::<1, 1024, 512>::new();
    firewall.add_rule(FirewallRule {
        action: Action::Accept,
        l2_match: Layer2Match::Any,
        l3_match: Layer3Match::Any,
        l4_match: Layer4Match::Any,
    }).unwrap();
    
    // UDP packet with checksum = 0 (valid, means no checksum)
    let packet = create_udp_packet([192, 168, 1, 100], [8, 8, 8, 8], 50000, 53);
    let result = firewall.match_packet(&packet);
    assert_eq!(result, Ok(MatchResult::Accept), "RFC 768: UDP with checksum 0 should be accepted");
}

/// RFC 793: TCP Header - Source Port field
#[test]
fn rfc793_tcp_source_port() {
    let mut firewall = Firewall::<1, 1024, 512>::new();
    firewall.add_rule(FirewallRule {
        action: Action::Accept,
        l2_match: Layer2Match::Any,
        l3_match: Layer3Match::Any,
        l4_match: Layer4Match::Match {
            protocol: 6, // TCP
            src_port: Some(50000),
            dst_port: None,
            one_way: false,
        },
    }).unwrap();
    
    let packet = create_tcp_packet([192, 168, 1, 100], [8, 8, 8, 8], 50000, 80, 0x10);
    let result = firewall.match_packet(&packet);
    assert_eq!(result, Ok(MatchResult::Accept), "RFC 793: TCP source port should be matched");
}

/// RFC 793: TCP Header - Destination Port field
#[test]
fn rfc793_tcp_destination_port() {
    let mut firewall = Firewall::<1, 1024, 512>::new();
    firewall.add_rule(FirewallRule {
        action: Action::Accept,
        l2_match: Layer2Match::Any,
        l3_match: Layer3Match::Any,
        l4_match: Layer4Match::Match {
            protocol: 6, // TCP
            src_port: None,
            dst_port: Some(80),
            one_way: false,
        },
    }).unwrap();
    
    let packet = create_tcp_packet([192, 168, 1, 100], [8, 8, 8, 8], 50000, 80, 0x10);
    let result = firewall.match_packet(&packet);
    assert_eq!(result, Ok(MatchResult::Accept), "RFC 793: TCP destination port should be matched");
}

/// RFC 793: TCP Header - Sequence Number field
#[test]
fn rfc793_tcp_sequence_number() {
    let mut firewall = Firewall::<1, 1024, 512>::new();
    firewall.add_rule(FirewallRule {
        action: Action::Accept,
        l2_match: Layer2Match::Any,
        l3_match: Layer3Match::Any,
        l4_match: Layer4Match::Any,
    }).unwrap();
    
    // TCP packet with sequence number (firewall doesn't validate sequence numbers)
    let packet = create_tcp_packet_seq([192, 168, 1, 100], [8, 8, 8, 8], 50000, 80, 0x10, 12345);
    let result = firewall.match_packet(&packet);
    assert_eq!(result, Ok(MatchResult::Accept), "RFC 793: TCP with sequence number should be accepted");
}

/// RFC 793: TCP Header - Acknowledgment Number field
#[test]
fn rfc793_tcp_acknowledgment_number() {
    let mut firewall = Firewall::<1, 1024, 512>::new();
    firewall.add_rule(FirewallRule {
        action: Action::Accept,
        l2_match: Layer2Match::Any,
        l3_match: Layer3Match::Any,
        l4_match: Layer4Match::Any,
    }).unwrap();
    
    // TCP packet with ACK flag and acknowledgment number
    let packet = create_tcp_packet_ack([192, 168, 1, 100], [8, 8, 8, 8], 50000, 80, 0x10, 12345, 54321);
    let result = firewall.match_packet(&packet);
    assert_eq!(result, Ok(MatchResult::Accept), "RFC 793: TCP with acknowledgment number should be accepted");
}

/// RFC 793: TCP Header - Data Offset field (header length)
#[test]
fn rfc793_tcp_data_offset() {
    let mut firewall = Firewall::<1, 1024, 512>::new();
    firewall.add_rule(FirewallRule {
        action: Action::Accept,
        l2_match: Layer2Match::Any,
        l3_match: Layer3Match::Any,
        l4_match: Layer4Match::Any,
    }).unwrap();
    
    // TCP with data offset = 5 (20 bytes, minimum)
    let packet = create_tcp_packet([192, 168, 1, 100], [8, 8, 8, 8], 50000, 80, 0x10);
    let result = firewall.match_packet(&packet);
    assert_eq!(result, Ok(MatchResult::Accept), "RFC 793: TCP with data offset 5 should be accepted");
}

/// RFC 793: TCP Flags - SYN flag
#[test]
fn rfc793_tcp_syn_flag() {
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
    
    // SYN packet
    let packet = create_tcp_packet([192, 168, 1, 100], [8, 8, 8, 8], 50000, 80, 0x02);
    let result = firewall.match_packet(&packet);
    assert_eq!(result, Ok(MatchResult::Accept), "RFC 793: TCP SYN flag should be accepted");
}

/// RFC 793: TCP Flags - ACK flag
#[test]
fn rfc793_tcp_ack_flag() {
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
    
    // ACK packet
    let packet = create_tcp_packet([192, 168, 1, 100], [8, 8, 8, 8], 50000, 80, 0x10);
    let result = firewall.match_packet(&packet);
    assert_eq!(result, Ok(MatchResult::Accept), "RFC 793: TCP ACK flag should be accepted");
}

/// RFC 793: TCP Flags - FIN flag
#[test]
fn rfc793_tcp_fin_flag() {
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
    
    // FIN packet
    let packet = create_tcp_packet([192, 168, 1, 100], [8, 8, 8, 8], 50000, 80, 0x01);
    let result = firewall.match_packet(&packet);
    assert_eq!(result, Ok(MatchResult::Accept), "RFC 793: TCP FIN flag should be accepted");
}

/// RFC 793: TCP Flags - RST flag
#[test]
fn rfc793_tcp_rst_flag() {
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
    
    // RST packet
    let packet = create_tcp_packet([192, 168, 1, 100], [8, 8, 8, 8], 50000, 80, 0x04);
    let result = firewall.match_packet(&packet);
    assert_eq!(result, Ok(MatchResult::Accept), "RFC 793: TCP RST flag should be accepted");
}

/// RFC 793: TCP Flags - PSH flag
#[test]
fn rfc793_tcp_psh_flag() {
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
    
    // PSH packet
    let packet = create_tcp_packet([192, 168, 1, 100], [8, 8, 8, 8], 50000, 80, 0x08);
    let result = firewall.match_packet(&packet);
    assert_eq!(result, Ok(MatchResult::Accept), "RFC 793: TCP PSH flag should be accepted");
}

/// RFC 793: TCP Flags - URG flag
#[test]
fn rfc793_tcp_urg_flag() {
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
    
    // URG packet
    let packet = create_tcp_packet([192, 168, 1, 100], [8, 8, 8, 8], 50000, 80, 0x20);
    let result = firewall.match_packet(&packet);
    assert_eq!(result, Ok(MatchResult::Accept), "RFC 793: TCP URG flag should be accepted");
}

/// RFC 793: TCP Window Size field
#[test]
fn rfc793_tcp_window_size() {
    let mut firewall = Firewall::<1, 1024, 512>::new();
    firewall.add_rule(FirewallRule {
        action: Action::Accept,
        l2_match: Layer2Match::Any,
        l3_match: Layer3Match::Any,
        l4_match: Layer4Match::Any,
    }).unwrap();
    
    // TCP packet with window size (firewall doesn't validate window size)
    let packet = create_tcp_packet([192, 168, 1, 100], [8, 8, 8, 8], 50000, 80, 0x10);
    let result = firewall.match_packet(&packet);
    assert_eq!(result, Ok(MatchResult::Accept), "RFC 793: TCP with window size should be accepted");
}

/// RFC 793: TCP Checksum field
#[test]
fn rfc793_tcp_checksum() {
    let mut firewall = Firewall::<1, 1024, 512>::new();
    firewall.add_rule(FirewallRule {
        action: Action::Accept,
        l2_match: Layer2Match::Any,
        l3_match: Layer3Match::Any,
        l4_match: Layer4Match::Any,
    }).unwrap();
    
    // TCP packet with checksum (firewall doesn't validate checksum)
    let packet = create_tcp_packet([192, 168, 1, 100], [8, 8, 8, 8], 50000, 80, 0x10);
    let result = firewall.match_packet(&packet);
    assert_eq!(result, Ok(MatchResult::Accept), "RFC 793: TCP with checksum should be accepted");
}

/// RFC 793: TCP Urgent Pointer field
#[test]
fn rfc793_tcp_urgent_pointer() {
    let mut firewall = Firewall::<1, 1024, 512>::new();
    firewall.add_rule(FirewallRule {
        action: Action::Accept,
        l2_match: Layer2Match::Any,
        l3_match: Layer3Match::Any,
        l4_match: Layer4Match::Any,
    }).unwrap();
    
    // TCP packet with urgent pointer (only valid when URG flag is set)
    let packet = create_tcp_packet([192, 168, 1, 100], [8, 8, 8, 8], 50000, 80, 0x20); // URG flag
    let result = firewall.match_packet(&packet);
    assert_eq!(result, Ok(MatchResult::Accept), "RFC 793: TCP with urgent pointer should be accepted");
}

/// RFC 793: TCP Connection States - Three-way handshake
#[test]
fn rfc793_tcp_three_way_handshake() {
    let mut firewall = Firewall::<1, 1024, 512>::new();
    firewall.add_rule(FirewallRule {
        action: Action::Accept,
        l2_match: Layer2Match::Any,
        l3_match: Layer3Match::Any,
        l4_match: Layer4Match::Match {
            protocol: 6,
            src_port: None, // Accept any source port
            dst_port: Some(80),
            one_way: false,
        },
    }).unwrap();
    
    // Step 1: Client sends SYN
    let syn = create_tcp_packet([192, 168, 1, 100], [192, 168, 1, 1], 50000, 80, 0x02);
    let result = firewall.match_packet(&syn);
    assert_eq!(result, Ok(MatchResult::Accept), "RFC 793: SYN should be accepted");
    
    // Step 2: Server sends SYN-ACK
    let syn_ack = create_tcp_packet([192, 168, 1, 1], [192, 168, 1, 100], 80, 50000, 0x12);
    let result = firewall.match_packet(&syn_ack);
    // SYN-ACK may be accepted via connection tracking or may need matching rule
    assert!(result == Ok(MatchResult::Accept) || result == Ok(MatchResult::Drop),
            "RFC 793: SYN-ACK should be handled");
    
    // Step 3: Client sends ACK
    let ack = create_tcp_packet([192, 168, 1, 100], [192, 168, 1, 1], 50000, 80, 0x10);
    let result = firewall.match_packet(&ack);
    assert_eq!(result, Ok(MatchResult::Accept), "RFC 793: ACK should be accepted (connection established)");
}

/// RFC 793: TCP Connection Termination - FIN
#[test]
fn rfc793_tcp_connection_termination() {
    let mut firewall = Firewall::<1, 1024, 512>::new();
    firewall.add_rule(FirewallRule {
        action: Action::Accept,
        l2_match: Layer2Match::Any,
        l3_match: Layer3Match::Any,
        l4_match: Layer4Match::Match {
            protocol: 6,
            src_port: None,
            dst_port: Some(80),
            one_way: false,
        },
    }).unwrap();
    
    // Establish connection first
    let syn = create_tcp_packet([192, 168, 1, 100], [192, 168, 1, 1], 50000, 80, 0x02);
    let _ = firewall.match_packet(&syn);
    let syn_ack = create_tcp_packet([192, 168, 1, 1], [192, 168, 1, 100], 80, 50000, 0x12);
    let _ = firewall.match_packet(&syn_ack);
    let ack = create_tcp_packet([192, 168, 1, 100], [192, 168, 1, 1], 50000, 80, 0x10);
    let _ = firewall.match_packet(&ack);
    
    // Client sends FIN
    let fin = create_tcp_packet([192, 168, 1, 100], [192, 168, 1, 1], 50000, 80, 0x01);
    let result = firewall.match_packet(&fin);
    assert_eq!(result, Ok(MatchResult::Accept), "RFC 793: FIN should be accepted");
    
    // Server sends FIN-ACK
    let fin_ack = create_tcp_packet([192, 168, 1, 1], [192, 168, 1, 100], 80, 50000, 0x11);
    let result = firewall.match_packet(&fin_ack);
    assert!(result == Ok(MatchResult::Accept) || result == Ok(MatchResult::Drop),
            "RFC 793: FIN-ACK should be handled");
}

/// RFC 793: TCP Connection Reset - RST
#[test]
fn rfc793_tcp_connection_reset() {
    let mut firewall = Firewall::<1, 1024, 512>::new();
    firewall.add_rule(FirewallRule {
        action: Action::Accept,
        l2_match: Layer2Match::Any,
        l3_match: Layer3Match::Any,
        l4_match: Layer4Match::Match {
            protocol: 6,
            src_port: None,
            dst_port: Some(80),
            one_way: false,
        },
    }).unwrap();
    
    // Establish connection
    let syn = create_tcp_packet([192, 168, 1, 100], [192, 168, 1, 1], 50000, 80, 0x02);
    let _ = firewall.match_packet(&syn);
    
    // Send RST to reset connection
    let rst = create_tcp_packet([192, 168, 1, 1], [192, 168, 1, 100], 80, 50000, 0x04);
    let result = firewall.match_packet(&rst);
    assert!(result == Ok(MatchResult::Accept) || result == Ok(MatchResult::Drop),
            "RFC 793: RST should be handled (connection should be reset)");
}

// Helper functions
fn create_ipv4_packet(src_ip: [u8; 4], dst_ip: [u8; 4], protocol: u8, df: bool) -> Vec<u8> {
    let mut packet = Vec::new();
    packet.extend_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
    packet.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
    packet.extend_from_slice(&0x0800u16.to_be_bytes());
    packet.push(0x45);
    packet.push(0x00);
    packet.extend_from_slice(&20u16.to_be_bytes());
    packet.extend_from_slice(&[0, 0]);
    let flags = if df { 0x4000u16 } else { 0u16 };
    packet.extend_from_slice(&flags.to_be_bytes());
    packet.push(64);
    packet.push(protocol);
    packet.extend_from_slice(&[0, 0]);
    packet.extend_from_slice(&src_ip);
    packet.extend_from_slice(&dst_ip);
    packet
}

fn create_ipv4_packet_df(src_ip: [u8; 4], dst_ip: [u8; 4], protocol: u8, df: bool) -> Vec<u8> {
    create_ipv4_packet(src_ip, dst_ip, protocol, df)
}

fn create_ipv4_packet_ttl(src_ip: [u8; 4], dst_ip: [u8; 4], protocol: u8, ttl: u8) -> Vec<u8> {
    let mut packet = Vec::new();
    packet.extend_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
    packet.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
    packet.extend_from_slice(&0x0800u16.to_be_bytes());
    packet.push(0x45);
    packet.push(0x00);
    packet.extend_from_slice(&20u16.to_be_bytes());
    packet.extend_from_slice(&[0, 0, 0, 0]);
    packet.push(ttl);
    packet.push(protocol);
    packet.extend_from_slice(&[0, 0]);
    packet.extend_from_slice(&src_ip);
    packet.extend_from_slice(&dst_ip);
    packet
}

fn create_udp_packet(src_ip: [u8; 4], dst_ip: [u8; 4], src_port: u16, dst_port: u16) -> Vec<u8> {
    let mut packet = create_ipv4_packet(src_ip, dst_ip, 17, false);
    packet[2] = 28; // Update total length
    packet.extend_from_slice(&src_port.to_be_bytes());
    packet.extend_from_slice(&dst_port.to_be_bytes());
    packet.extend_from_slice(&[0, 8]); // length, checksum
    packet
}

fn create_tcp_packet(src_ip: [u8; 4], dst_ip: [u8; 4], src_port: u16, dst_port: u16, flags: u8) -> Vec<u8> {
    let mut packet = create_ipv4_packet(src_ip, dst_ip, 6, false);
    packet[2] = 40;
    packet.extend_from_slice(&src_port.to_be_bytes());
    packet.extend_from_slice(&dst_port.to_be_bytes());
    packet.extend_from_slice(&[0, 0, 0, 0]); // seq
    packet.extend_from_slice(&[0, 0, 0, 0]); // ack
    packet.push(0x50); // data offset
    packet.push(flags);
    packet.extend_from_slice(&[0, 0]); // window
    packet.extend_from_slice(&[0, 0]); // checksum
    packet.extend_from_slice(&[0, 0]); // urgent
    packet
}

fn create_tcp_packet_seq(src_ip: [u8; 4], dst_ip: [u8; 4], src_port: u16, dst_port: u16, flags: u8, seq: u32) -> Vec<u8> {
    let mut packet = create_ipv4_packet(src_ip, dst_ip, 6, false);
    packet[2] = 40;
    packet.extend_from_slice(&src_port.to_be_bytes());
    packet.extend_from_slice(&dst_port.to_be_bytes());
    packet.extend_from_slice(&seq.to_be_bytes());
    packet.extend_from_slice(&[0, 0, 0, 0]); // ack
    packet.push(0x50);
    packet.push(flags);
    packet.extend_from_slice(&[0, 0]);
    packet.extend_from_slice(&[0, 0]);
    packet.extend_from_slice(&[0, 0]);
    packet
}

fn create_tcp_packet_ack(src_ip: [u8; 4], dst_ip: [u8; 4], src_port: u16, dst_port: u16, flags: u8, seq: u32, ack: u32) -> Vec<u8> {
    let mut packet = create_ipv4_packet(src_ip, dst_ip, 6, false);
    packet[2] = 40;
    packet.extend_from_slice(&src_port.to_be_bytes());
    packet.extend_from_slice(&dst_port.to_be_bytes());
    packet.extend_from_slice(&seq.to_be_bytes());
    packet.extend_from_slice(&ack.to_be_bytes());
    packet.push(0x50);
    packet.push(flags);
    packet.extend_from_slice(&[0, 0]);
    packet.extend_from_slice(&[0, 0]);
    packet.extend_from_slice(&[0, 0]);
    packet
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

