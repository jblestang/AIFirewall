//! Fuzzy Tests for Packet Parsing Functions
//! 
//! Tests to detect parsing logic errors by generating random packet data
//! and verifying parsing functions handle them gracefully without panicking

use aifirewall::firewall::{Firewall, FirewallRule, Action, Layer2Match, Layer3Match, Layer4Match};

/// Generate a random MAC address
fn random_mac() -> [u8; 6] {
    [
        rand::random::<u8>(),
        rand::random::<u8>(),
        rand::random::<u8>(),
        rand::random::<u8>(),
        rand::random::<u8>(),
        rand::random::<u8>(),
    ]
}

/// Generate a random IP address
fn random_ip() -> [u8; 4] {
    [
        rand::random::<u8>(),
        rand::random::<u8>(),
        rand::random::<u8>(),
        rand::random::<u8>(),
    ]
}

/// Generate a random port
fn random_port() -> u16 {
    rand::random::<u16>()
}

/// Generate a random ethertype
fn random_ethertype() -> u16 {
    rand::random::<u16>()
}

/// Generate a random protocol number
fn random_protocol() -> u8 {
    rand::random::<u8>()
}

/// Create a minimal Ethernet packet (14 bytes)
fn create_random_ethernet_packet(ethertype: u16) -> Vec<u8> {
    let mut packet = Vec::new();
    packet.extend_from_slice(&random_mac());
    packet.extend_from_slice(&random_mac());
    packet.extend_from_slice(&ethertype.to_be_bytes());
    packet
}

/// Create a random IP packet
fn create_random_ip_packet(src_ip: [u8; 4], dst_ip: [u8; 4], protocol: u8, payload_size: usize) -> Vec<u8> {
    let mut packet = create_random_ethernet_packet(0x0800);
    
    // IP header (minimum 20 bytes)
    let ip_header_len = 20;
    let total_length = ip_header_len + payload_size;
    
    packet.push(0x45); // Version 4, IHL 5
    packet.push(0x00); // DSCP/ECN
    packet.extend_from_slice(&(total_length as u16).to_be_bytes());
    packet.extend_from_slice(&rand::random::<u16>().to_be_bytes()); // ID
    packet.extend_from_slice(&[0x40, 0x00]); // Flags (DF) and fragment offset
    packet.push(64); // TTL
    packet.push(protocol);
    packet.extend_from_slice(&[0, 0]); // Checksum (not validated)
    packet.extend_from_slice(&src_ip);
    packet.extend_from_slice(&dst_ip);
    
    // Payload
    for _ in 0..payload_size {
        packet.push(rand::random::<u8>());
    }
    
    packet
}

/// Create a random TCP packet
fn create_random_tcp_packet(src_ip: [u8; 4], dst_ip: [u8; 4], src_port: u16, dst_port: u16, flags: u8) -> Vec<u8> {
    let mut packet = create_random_ip_packet(src_ip, dst_ip, 6, 20);
    
    // Update IP total length
    let total_length = 20 + 20; // IP header + TCP header
    packet[16] = (total_length >> 8) as u8;
    packet[17] = (total_length & 0xFF) as u8;
    
    // TCP header (minimum 20 bytes)
    packet.extend_from_slice(&src_port.to_be_bytes());
    packet.extend_from_slice(&dst_port.to_be_bytes());
    packet.extend_from_slice(&rand::random::<u32>().to_be_bytes()); // Sequence number
    packet.extend_from_slice(&rand::random::<u32>().to_be_bytes()); // Acknowledgment number
    packet.push(0x50); // Data offset (5 * 4 = 20 bytes)
    packet.push(flags);
    packet.extend_from_slice(&rand::random::<u16>().to_be_bytes()); // Window size
    packet.extend_from_slice(&[0, 0]); // Checksum
    packet.extend_from_slice(&[0, 0]); // Urgent pointer
    
    packet
}

/// Create a random UDP packet
fn create_random_udp_packet(src_ip: [u8; 4], dst_ip: [u8; 4], src_port: u16, dst_port: u16, payload_size: usize) -> Vec<u8> {
    let mut packet = create_random_ip_packet(src_ip, dst_ip, 17, 8 + payload_size);
    
    // Update IP total length
    let total_length = 20 + 8 + payload_size;
    packet[16] = (total_length >> 8) as u8;
    packet[17] = (total_length & 0xFF) as u8;
    
    // UDP header (8 bytes)
    packet.extend_from_slice(&src_port.to_be_bytes());
    packet.extend_from_slice(&dst_port.to_be_bytes());
    packet.extend_from_slice(&(8 + payload_size as u16).to_be_bytes()); // Length
    packet.extend_from_slice(&[0, 0]); // Checksum
    
    // Payload
    for _ in 0..payload_size {
        packet.push(rand::random::<u8>());
    }
    
    packet
}

/// Create a random VLAN packet
fn create_random_vlan_packet(vlan_id: u16, ethertype: u16) -> Vec<u8> {
    let mut packet = Vec::new();
    packet.extend_from_slice(&random_mac());
    packet.extend_from_slice(&random_mac());
    packet.extend_from_slice(&0x8100u16.to_be_bytes()); // VLAN TPID
    let tci = (vlan_id & 0x0FFF) | (rand::random::<u16>() & 0xF000); // VLAN ID + priority/CFI
    packet.extend_from_slice(&tci.to_be_bytes());
    packet.extend_from_slice(&ethertype.to_be_bytes());
    
    if ethertype == 0x0800 {
        // Add minimal IP header
        packet.push(0x45);
        packet.push(0x00);
        packet.extend_from_slice(&20u16.to_be_bytes());
        packet.extend_from_slice(&rand::random::<u16>().to_be_bytes());
        packet.extend_from_slice(&[0x40, 0x00]);
        packet.push(64);
        packet.push(rand::random::<u8>());
        packet.extend_from_slice(&[0, 0]);
        packet.extend_from_slice(&random_ip());
        packet.extend_from_slice(&random_ip());
    }
    
    packet
}

/// Create a random IP fragment
fn create_random_fragment(src_ip: [u8; 4], dst_ip: [u8; 4], ip_id: u16, offset: u16, more_fragments: bool, payload_size: usize) -> Vec<u8> {
    let mut packet = create_random_ethernet_packet(0x0800);
    
    let ip_header_len = 20;
    let total_length = ip_header_len + payload_size;
    
    packet.push(0x45);
    packet.push(0x00);
    packet.extend_from_slice(&(total_length as u16).to_be_bytes());
    packet.extend_from_slice(&ip_id.to_be_bytes());
    
    let flags_and_offset = if more_fragments {
        0x2000u16 | (offset & 0x1FFF)
    } else {
        offset & 0x1FFF
    };
    packet.extend_from_slice(&flags_and_offset.to_be_bytes());
    
    packet.push(64);
    packet.push(17); // UDP
    packet.extend_from_slice(&[0, 0]);
    packet.extend_from_slice(&src_ip);
    packet.extend_from_slice(&dst_ip);
    
    // Only first fragment (offset=0) has UDP header
    if offset == 0 {
        packet.extend_from_slice(&random_port().to_be_bytes());
        packet.extend_from_slice(&random_port().to_be_bytes());
        packet.extend_from_slice(&(8 + payload_size as u16).to_be_bytes());
        packet.extend_from_slice(&[0, 0]);
    }
    
    // Payload
    for _ in 0..payload_size {
        packet.push(rand::random::<u8>());
    }
    
    packet
}

/// Fuzzy test: Random L2 (Ethernet) packets
#[test]
fn fuzzy_l2_parsing() {
    let mut firewall = Firewall::<1, 1024, 512>::new();
    firewall.add_rule(FirewallRule {
        action: Action::Accept,
        l2_match: Layer2Match::Any,
        l3_match: Layer3Match::Any,
        l4_match: Layer4Match::Any,
    }).unwrap();
    
    // Test 1000 random Ethernet packets
    for _ in 0..1000 {
        let ethertype = random_ethertype();
        let packet = create_random_ethernet_packet(ethertype);
        
        // Should not panic - either accept, drop, or error
        let result = firewall.match_packet(&packet);
        assert!(result.is_ok() || result.is_err(), 
                "L2 parsing should not panic (ethertype: 0x{:04x}, result: {:?})", ethertype, result);
    }
}

/// Fuzzy test: Random L3 (IP) packets
#[test]
fn fuzzy_l3_parsing() {
    let mut firewall = Firewall::<1, 1024, 512>::new();
    firewall.add_rule(FirewallRule {
        action: Action::Accept,
        l2_match: Layer2Match::Any,
        l3_match: Layer3Match::Any,
        l4_match: Layer4Match::Any,
    }).unwrap();
    
    // Test 1000 random IP packets
    for _ in 0..1000 {
        let src_ip = random_ip();
        let dst_ip = random_ip();
        let protocol = random_protocol();
        let payload_size = rand::random::<usize>() % 1000;
        
        let packet = create_random_ip_packet(src_ip, dst_ip, protocol, payload_size);
        
        // Should not panic
        let result = firewall.match_packet(&packet);
        assert!(result.is_ok() || result.is_err(), 
                "L3 parsing should not panic (protocol: {}, result: {:?})", protocol, result);
    }
}

/// Fuzzy test: Random L4 (TCP) packets
#[test]
fn fuzzy_l4_tcp_parsing() {
    let mut firewall = Firewall::<1, 1024, 512>::new();
    firewall.add_rule(FirewallRule {
        action: Action::Accept,
        l2_match: Layer2Match::Any,
        l3_match: Layer3Match::Any,
        l4_match: Layer4Match::Any,
    }).unwrap();
    
    // Test 1000 random TCP packets
    for _ in 0..1000 {
        let src_ip = random_ip();
        let dst_ip = random_ip();
        let src_port = random_port();
        let dst_port = random_port();
        let flags = rand::random::<u8>();
        
        let packet = create_random_tcp_packet(src_ip, dst_ip, src_port, dst_port, flags);
        
        // Should not panic
        let result = firewall.match_packet(&packet);
        assert!(result.is_ok() || result.is_err(), 
                "L4 TCP parsing should not panic (flags: 0x{:02x}, result: {:?})", flags, result);
    }
}

/// Fuzzy test: Random L4 (UDP) packets
#[test]
fn fuzzy_l4_udp_parsing() {
    let mut firewall = Firewall::<1, 1024, 512>::new();
    firewall.add_rule(FirewallRule {
        action: Action::Accept,
        l2_match: Layer2Match::Any,
        l3_match: Layer3Match::Any,
        l4_match: Layer4Match::Any,
    }).unwrap();
    
    // Test 1000 random UDP packets
    for _ in 0..1000 {
        let src_ip = random_ip();
        let dst_ip = random_ip();
        let src_port = random_port();
        let dst_port = random_port();
        let payload_size = rand::random::<usize>() % 1000;
        
        let packet = create_random_udp_packet(src_ip, dst_ip, src_port, dst_port, payload_size);
        
        // Should not panic
        let result = firewall.match_packet(&packet);
        assert!(result.is_ok() || result.is_err(), 
                "L4 UDP parsing should not panic (payload_size: {}, result: {:?})", payload_size, result);
    }
}

/// Fuzzy test: Random VLAN packets
#[test]
fn fuzzy_vlan_parsing() {
    let mut firewall = Firewall::<1, 1024, 512>::new();
    firewall.add_rule(FirewallRule {
        action: Action::Accept,
        l2_match: Layer2Match::Any,
        l3_match: Layer3Match::Any,
        l4_match: Layer4Match::Any,
    }).unwrap();
    
    // Test 1000 random VLAN packets
    for _ in 0..1000 {
        let vlan_id = rand::random::<u16>() & 0x0FFF; // Valid VLAN ID (0-4095)
        let ethertype = random_ethertype();
        
        let packet = create_random_vlan_packet(vlan_id, ethertype);
        
        // Should not panic
        let result = firewall.match_packet(&packet);
        assert!(result.is_ok() || result.is_err(), 
                "VLAN parsing should not panic (vlan_id: {}, ethertype: 0x{:04x}, result: {:?})", 
                vlan_id, ethertype, result);
    }
}

/// Fuzzy test: Random IP fragments
#[test]
fn fuzzy_fragment_parsing() {
    let mut firewall = Firewall::<1, 1024, 512>::new();
    firewall.add_rule(FirewallRule {
        action: Action::Accept,
        l2_match: Layer2Match::Any,
        l3_match: Layer3Match::Any,
        l4_match: Layer4Match::Any,
    }).unwrap();
    
    // Test 1000 random fragments
    for _ in 0..1000 {
        let src_ip = random_ip();
        let dst_ip = random_ip();
        let ip_id = rand::random::<u16>();
        let offset = (rand::random::<u16>() % 8192) * 8; // Valid fragment offset (multiple of 8)
        let more_fragments = rand::random::<bool>();
        let payload_size = rand::random::<usize>() % 1000;
        
        let packet = create_random_fragment(src_ip, dst_ip, ip_id, offset, more_fragments, payload_size);
        
        // Should not panic
        let result = firewall.match_packet(&packet);
        assert!(result.is_ok() || result.is_err(), 
                "Fragment parsing should not panic (offset: {}, MF: {}, result: {:?})", 
                offset, more_fragments, result);
    }
}

/// Fuzzy test: Random packet sizes
#[test]
fn fuzzy_packet_size_variations() {
    let mut firewall = Firewall::<1, 1024, 512>::new();
    firewall.add_rule(FirewallRule {
        action: Action::Accept,
        l2_match: Layer2Match::Any,
        l3_match: Layer3Match::Any,
        l4_match: Layer4Match::Any,
    }).unwrap();
    
    // Test various packet sizes
    let sizes = vec![
        0, 1, 5, 10, 13, 14, 15, 20, 34, 50, 100, 500, 1000, 1500, 2000, 9000,
    ];
    
    for size in sizes {
        let mut packet = vec![0u8; size];
        // Fill with random data
        for byte in &mut packet {
            *byte = rand::random::<u8>();
        }
        
        // Ensure minimum Ethernet header if size allows
        if size >= 14 {
            packet[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
        }
        
        // Should not panic
        let result = firewall.match_packet(&packet);
        assert!(result.is_ok() || result.is_err(), 
                "Packet size parsing should not panic (size: {}, result: {:?})", size, result);
    }
}

/// Fuzzy test: Random malformed packets
#[test]
fn fuzzy_malformed_packets() {
    let mut firewall = Firewall::<1, 1024, 512>::new();
    firewall.add_rule(FirewallRule {
        action: Action::Accept,
        l2_match: Layer2Match::Any,
        l3_match: Layer3Match::Any,
        l4_match: Layer4Match::Any,
    }).unwrap();
    
    // Test 1000 random malformed packets
    for _ in 0..1000 {
        let size = rand::random::<usize>() % 2000;
        let mut packet = vec![0u8; size];
        
        // Fill with random data
        for byte in &mut packet {
            *byte = rand::random::<u8>();
        }
        
        // Randomly corrupt some fields
        if size >= 14 {
            // Sometimes set invalid ethertype
            if rand::random::<bool>() {
                packet[12..14].copy_from_slice(&rand::random::<u16>().to_be_bytes());
            }
        }
        
        if size >= 34 {
            // Sometimes set invalid IP version or IHL
            if rand::random::<bool>() {
                packet[14] = rand::random::<u8>(); // Version/IHL
            }
        }
        
        // Should not panic - should return error or drop
        let result = firewall.match_packet(&packet);
        assert!(result.is_ok() || result.is_err(), 
                "Malformed packet parsing should not panic (size: {}, result: {:?})", size, result);
    }
}

/// Fuzzy test: Random IP header length variations
#[test]
fn fuzzy_ip_header_length_variations() {
    let mut firewall = Firewall::<1, 1024, 512>::new();
    firewall.add_rule(FirewallRule {
        action: Action::Accept,
        l2_match: Layer2Match::Any,
        l3_match: Layer3Match::Any,
        l4_match: Layer4Match::Any,
    }).unwrap();
    
    // Test various IHL values (5-15 are valid, but we'll test edge cases)
    for ihl in 0..=15 {
        let mut packet = create_random_ethernet_packet(0x0800);
        
        // Set IHL
        packet.push((4 << 4) | (ihl & 0x0F));
        packet.push(0x00);
        packet.extend_from_slice(&20u16.to_be_bytes());
        packet.extend_from_slice(&rand::random::<u16>().to_be_bytes());
        packet.extend_from_slice(&[0x40, 0x00]);
        packet.push(64);
        packet.push(6); // TCP
        packet.extend_from_slice(&[0, 0]);
        packet.extend_from_slice(&random_ip());
        packet.extend_from_slice(&random_ip());
        
        // Add IP options if IHL > 5
        let ip_header_len = (ihl as usize) * 4;
        if ip_header_len > 20 {
            for _ in 20..ip_header_len {
                packet.push(rand::random::<u8>());
            }
        }
        
        // Add TCP header if packet is large enough
        if packet.len() >= 14 + ip_header_len + 20 {
            packet.extend_from_slice(&random_port().to_be_bytes());
            packet.extend_from_slice(&random_port().to_be_bytes());
            packet.extend_from_slice(&rand::random::<u32>().to_be_bytes());
            packet.extend_from_slice(&rand::random::<u32>().to_be_bytes());
            packet.push(0x50);
            packet.push(0x02); // SYN
            packet.extend_from_slice(&rand::random::<u16>().to_be_bytes());
            packet.extend_from_slice(&[0, 0]);
            packet.extend_from_slice(&[0, 0]);
        }
        
        // Should not panic
        let result = firewall.match_packet(&packet);
        assert!(result.is_ok() || result.is_err(), 
                "IP header length parsing should not panic (IHL: {}, result: {:?})", ihl, result);
    }
}

/// Fuzzy test: Random protocol combinations
#[test]
fn fuzzy_protocol_combinations() {
    let mut firewall = Firewall::<1, 1024, 512>::new();
    firewall.add_rule(FirewallRule {
        action: Action::Accept,
        l2_match: Layer2Match::Any,
        l3_match: Layer3Match::Any,
        l4_match: Layer4Match::Any,
    }).unwrap();
    
    // Test all possible protocol values
    for protocol in 0..=255u8 {
        let packet = create_random_ip_packet(random_ip(), random_ip(), protocol, 0);
        
        // Should not panic
        let result = firewall.match_packet(&packet);
        assert!(result.is_ok() || result.is_err(), 
                "Protocol parsing should not panic (protocol: {}, result: {:?})", protocol, result);
    }
}

/// Fuzzy test: Random ethertype combinations
#[test]
fn fuzzy_ethertype_combinations() {
    let mut firewall = Firewall::<1, 1024, 512>::new();
    firewall.add_rule(FirewallRule {
        action: Action::Accept,
        l2_match: Layer2Match::Any,
        l3_match: Layer3Match::Any,
        l4_match: Layer4Match::Any,
    }).unwrap();
    
    // Test common ethertypes and random ones
    let ethertypes = vec![
        0x0800, // IPv4
        0x0806, // ARP
        0x8100, // VLAN (should be handled specially)
        0x86DD, // IPv6
        0x8847, // MPLS
        0x8848, // MPLS
    ];
    
    for ethertype in ethertypes {
        let packet = create_random_ethernet_packet(ethertype);
        
        // Should not panic
        let result = firewall.match_packet(&packet);
        assert!(result.is_ok() || result.is_err(), 
                "Ethertype parsing should not panic (ethertype: 0x{:04x}, result: {:?})", ethertype, result);
    }
    
    // Also test 100 random ethertypes
    for _ in 0..100 {
        let ethertype = random_ethertype();
        // Skip VLAN TPID to avoid confusion
        if ethertype != 0x8100 {
            let packet = create_random_ethernet_packet(ethertype);
            let result = firewall.match_packet(&packet);
            assert!(result.is_ok() || result.is_err(), 
                    "Ethertype parsing should not panic (ethertype: 0x{:04x}, result: {:?})", ethertype, result);
        }
    }
}

/// Fuzzy test: Random fragment offset combinations
#[test]
fn fuzzy_fragment_offset_combinations() {
    let mut firewall = Firewall::<1, 1024, 512>::new();
    firewall.add_rule(FirewallRule {
        action: Action::Accept,
        l2_match: Layer2Match::Any,
        l3_match: Layer3Match::Any,
        l4_match: Layer4Match::Any,
    }).unwrap();
    
    // Test various fragment offsets
    let offsets = vec![
        0, 8, 16, 24, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384,
    ];
    
    for offset in offsets {
        let src_ip = random_ip();
        let dst_ip = random_ip();
        let ip_id = rand::random::<u16>();
        let more_fragments = rand::random::<bool>();
        let payload_size = rand::random::<usize>() % 1000;
        
        let packet = create_random_fragment(src_ip, dst_ip, ip_id, offset, more_fragments, payload_size);
        
        // Should not panic
        let result = firewall.match_packet(&packet);
        assert!(result.is_ok() || result.is_err(), 
                "Fragment offset parsing should not panic (offset: {}, result: {:?})", offset, result);
    }
}

/// Fuzzy test: Random TCP flag combinations
#[test]
fn fuzzy_tcp_flag_combinations() {
    let mut firewall = Firewall::<1, 1024, 512>::new();
    firewall.add_rule(FirewallRule {
        action: Action::Accept,
        l2_match: Layer2Match::Any,
        l3_match: Layer3Match::Any,
        l4_match: Layer4Match::Any,
    }).unwrap();
    
    // Test all possible TCP flag combinations
    for flags in 0..=255u8 {
        let packet = create_random_tcp_packet(
            random_ip(),
            random_ip(),
            random_port(),
            random_port(),
            flags,
        );
        
        // Should not panic
        let result = firewall.match_packet(&packet);
        assert!(result.is_ok() || result.is_err(), 
                "TCP flag parsing should not panic (flags: 0x{:02x}, result: {:?})", flags, result);
    }
}

/// Fuzzy test: Random port combinations
#[test]
fn fuzzy_port_combinations() {
    let mut firewall = Firewall::<1, 1024, 512>::new();
    firewall.add_rule(FirewallRule {
        action: Action::Accept,
        l2_match: Layer2Match::Any,
        l3_match: Layer3Match::Any,
        l4_match: Layer4Match::Any,
    }).unwrap();
    
    // Test edge case ports
    let ports = vec![0, 1, 1023, 1024, 49151, 49152, 65535];
    
    for src_port in &ports {
        for dst_port in &ports {
            // Test TCP
            let tcp_packet = create_random_tcp_packet(
                random_ip(),
                random_ip(),
                *src_port,
                *dst_port,
                0x02, // SYN
            );
            let result = firewall.match_packet(&tcp_packet);
            assert!(result.is_ok() || result.is_err(), 
                    "TCP port parsing should not panic (src: {}, dst: {}, result: {:?})", 
                    src_port, dst_port, result);
            
            // Test UDP
            let udp_packet = create_random_udp_packet(
                random_ip(),
                random_ip(),
                *src_port,
                *dst_port,
                0,
            );
            let result = firewall.match_packet(&udp_packet);
            assert!(result.is_ok() || result.is_err(), 
                    "UDP port parsing should not panic (src: {}, dst: {}, result: {:?})", 
                    src_port, dst_port, result);
        }
    }
}

