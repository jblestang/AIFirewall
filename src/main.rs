//! AIFirewall Test Binary
//!
//! Creates a VirtualStack with firewall rules connected to a network interface
//! and processes real packets through the firewall

use aifirewall::*;
use aifirewall::firewall::{Layer2Match, Layer3Match, Layer4Match, IpMatch};
use std::env;
use std::net::UdpSocket;
use std::time::Duration;

#[cfg(feature = "std")]
mod tap_stack;
#[cfg(feature = "std")]
use tap_stack::TapStack;

#[cfg(feature = "std")]
fn main() {
    println!("AIFirewall - Virtual IP Stack with Firewall");
    println!("===========================================\n");
    
    // Parse command line arguments
    let args: std::vec::Vec<String> = env::args().collect();
    let mode = args.get(1).map(|s| s.as_str()).unwrap_or("test");
    
    match mode {
        "tap" => {
            run_tap_mode(&args);
        }
        "network" => {
            run_network_mode(&args);
        }
        "test" | _ => {
            run_test_mode();
        }
    }
}

#[cfg(feature = "std")]
fn run_tap_mode(args: &[String]) {
    let tap_name = args.get(2).map(|s| s.as_str());
    
    println!("TAP Mode: Creating virtual network interface");
    println!("This will create a TAP interface that appears in your system\n");
    println!("Note: TAP interface creation requires root/administrator privileges\n");
    
    // Create firewall with rules
    let firewall = create_firewall();
    
    // Create TAP stack
    match TapStack::new(firewall, tap_name) {
        Ok(mut tap_stack) => {
            if let Err(e) = tap_stack.run() {
                eprintln!("Error running TAP stack: {}", e);
                eprintln!("\nFalling back to test mode...\n");
                run_test_mode();
            }
        }
        Err(e) => {
            eprintln!("Failed to create TAP stack: {}", e);
            eprintln!("\nNote: TAP interface creation requires root privileges");
            eprintln!("Try: sudo cargo run --features std --bin aifirewall tap");
            eprintln!("\nFalling back to test mode...\n");
            run_test_mode();
        }
    }
}

#[cfg(feature = "std")]
fn run_network_mode(args: &[String]) {
    let interface = args.get(2).map(|s| s.as_str()).unwrap_or("0.0.0.0:8888");
    
    println!("Network Mode: Binding to {}", interface);
    println!("This will process real UDP packets through the firewall\n");
    println!("Note: This uses UDP sockets for demonstration.");
    println!("      For real Ethernet packet capture, use raw sockets or TAP interface.\n");
    
    // Create firewall with rules
    let mut firewall = create_firewall();
    
    // Create a simple UDP-based network stack
    
    let socket = match UdpSocket::bind(interface) {
        Ok(s) => {
            println!("✓ Successfully bound to {}", interface);
            s
        }
        Err(e) => {
            eprintln!("✗ Failed to bind to {}: {}", interface, e);
            eprintln!("\nFalling back to test mode...\n");
            run_test_mode();
            return;
        }
    };
    
    socket.set_read_timeout(Some(Duration::from_millis(100))).unwrap();
    
    println!("\nFirewall rules active:");
    println!("  - Allow HTTP (TCP port 80) to 192.168.1.1");
    println!("  - Allow UDP from 10.0.0.0/8");
    println!("  - Block ICMP");
    println!("  - Allow IGMP (multicast)");
    println!("  - Allow MAC aa:bb:cc:dd:ee:ff");
    println!("\nWaiting for packets... (Ctrl+C to stop)\n");
    println!("You can test by sending UDP packets:");
    println!("  echo 'test' | nc -u localhost <port>");
    println!();
    
    let mut buf = [0u8; 1500];
    
    loop {
        match socket.recv_from(&mut buf) {
            Ok((size, addr)) => {
                println!("Received {} bytes from {}", size, addr);
                
                // Create a minimal Ethernet frame for firewall processing
                // In real implementation, this would be a proper Ethernet frame
                let mut packet = heapless::Vec::<u8, 1500>::new();
                
                // Add dummy Ethernet header (14 bytes)
                let dummy_mac = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
                packet.extend_from_slice(&dummy_mac).ok(); // dst_mac
                packet.extend_from_slice(&dummy_mac).ok(); // src_mac
                packet.extend_from_slice(&0x0800u16.to_be_bytes()).ok(); // IPv4 ethertype
                
                // Add the UDP payload as IP packet data
                if packet.extend_from_slice(&buf[..size]).is_ok() {
                    match firewall.match_packet(&packet) {
                        Ok(MatchResult::Accept) => {
                            println!("  ✓ Packet ACCEPTED by firewall");
                        }
                        Ok(MatchResult::Drop) => {
                            println!("  ✗ Packet DROPPED by firewall");
                        }
                        Ok(MatchResult::Reject) => {
                            println!("  ✗ Packet REJECTED by firewall");
                        }
                        Ok(MatchResult::NoMatch) => {
                            println!("  ? Packet NO MATCH (default: DROP)");
                        }
                        Err(e) => {
                            println!("  Error: {:?}", e);
                        }
                    }
                }
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                // No packet available, continue
            }
            Err(e) => {
                eprintln!("Error receiving packet: {}", e);
            }
        }
        
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[cfg(feature = "std")]
fn create_firewall() -> Firewall<32, 1024, 512> {

    let mut firewall = Firewall::<32, 1024, 512>::new();
    
    // Rule 1: Allow HTTP traffic to 192.168.1.1:80
    let _ = firewall.add_rule(FirewallRule {
        action: Action::Accept,
        l2_match: Layer2Match::Any,
        l3_match: Layer3Match::Match {
            dst_ip: Some(IpMatch { addr: [192, 168, 1, 1], cidr: None }),
            src_ip: None,
            protocol: None,
        },
        l4_match: Layer4Match::Match {
            protocol: 6, // TCP
            dst_port: Some(80),
            src_port: None,
            one_way: false,
        },
    });
    
    // Rule 2: Allow UDP from 10.0.0.0/8 (bidirectional)
    let _ = firewall.add_rule(FirewallRule {
        action: Action::Accept,
        l2_match: Layer2Match::Any,
        l3_match: Layer3Match::Match {
            src_ip: Some(IpMatch { addr: [10, 0, 0, 0], cidr: Some(8) }),
            dst_ip: None,
            protocol: None,
        },
        l4_match: Layer4Match::Match {
            protocol: 17, // UDP
            dst_port: None,
            src_port: None,
            one_way: false,
        },
    });
    
    // Rule 2.5: Example one-way UDP (outbound DNS queries, no replies)
    // This would be: ACCEPT ip src ip 192.168.1.0/24 udp dst port 53 oneway
    // (Not added to default rules, but available for use)
    
    // Rule 3: Block ICMP
    let _ = firewall.add_rule(FirewallRule {
        action: Action::Drop,
        l2_match: Layer2Match::Any,
        l3_match: Layer3Match::Match {
            src_ip: None,
            dst_ip: None,
            protocol: Some(1), // ICMP
        },
        l4_match: Layer4Match::Any,
    });
    
    // Rule 3.5: Allow IGMP (for multicast)
    let _ = firewall.add_rule(FirewallRule {
        action: Action::Accept,
        l2_match: Layer2Match::Any,
        l3_match: Layer3Match::Match {
            src_ip: None,
            dst_ip: None,
            protocol: Some(2), // IGMP
        },
        l4_match: Layer4Match::Any,
    });
    
    // Rule 4: Allow specific MAC
    let _ = firewall.add_rule(FirewallRule {
        action: Action::Accept,
        l2_match: Layer2Match::Match {
            vlan_id: None,
            src_mac: Some([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]),
            dst_mac: None,
            ethertype: None,
        },
        l3_match: Layer3Match::Any,
        l4_match: Layer4Match::Any,
    });
    
    firewall
}

#[cfg(feature = "std")]
fn run_test_mode() {
    println!("Test Mode: Running packet injection tests\n");
    
    // Create firewall with rules
    let firewall = create_firewall();
    println!("✓ Created firewall with 4 rules\n");

    let stack = VirtualStack::<32>::with_firewall(firewall);
    let mut injector = PacketInjector::<32>::new(stack);

    println!("Running test cases...\n");
    println!("{}", "=".repeat(50));

    // Test Case 1: TCP packet to port 80 (should ACCEPT)
    println!("\nTest 1: TCP packet to 192.168.1.1:80");
    println!("Expected: ACCEPT");
    let result = injector.inject_tcp(
        [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
        [0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
        [10, 0, 0, 1],
        [192, 168, 1, 1],
        12345,
        80,
        b"GET / HTTP/1.1\r\n",
    );
    match result {
        Ok(MatchResult::Accept) => println!("✓ Result: ACCEPT (PASS)"),
        Ok(MatchResult::Drop) => println!("✗ Result: DROP (FAIL)"),
        Ok(MatchResult::Reject) => println!("✗ Result: REJECT (FAIL)"),
        Ok(MatchResult::NoMatch) => println!("✗ Result: NO MATCH (FAIL)"),
        Err(e) => println!("✗ Error: {:?}", e),
    }

    // Test Case 2: UDP packet from 10.0.0.0/8 (should ACCEPT)
    println!("\nTest 2: UDP packet from 10.0.0.5");
    println!("Expected: ACCEPT");
    let result = injector.inject_udp(
        [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
        [0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
        [10, 0, 0, 5],
        [192, 168, 1, 1],
        53,
        53,
        b"DNS query",
    );
    match result {
        Ok(MatchResult::Accept) => println!("✓ Result: ACCEPT (PASS)"),
        Ok(MatchResult::Drop) => println!("✗ Result: DROP (FAIL)"),
        Ok(MatchResult::Reject) => println!("✗ Result: REJECT (FAIL)"),
        Ok(MatchResult::NoMatch) => println!("✗ Result: NO MATCH (FAIL)"),
        Err(e) => println!("✗ Error: {:?}", e),
    }

    // Test Case 3: ICMP packet (should DROP)
    println!("\nTest 3: ICMP packet");
    println!("Expected: DROP");
    let result = injector.inject_icmp(
        [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
        [0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
        [10, 0, 0, 1],
        [192, 168, 1, 1],
        8, // Echo request
        0,
        b"ping",
    );
    match result {
        Ok(MatchResult::Accept) => println!("✗ Result: ACCEPT (FAIL)"),
        Ok(MatchResult::Drop) => println!("✓ Result: DROP (PASS)"),
        Ok(MatchResult::Reject) => println!("✓ Result: REJECT (PASS)"),
        Ok(MatchResult::NoMatch) => println!("✗ Result: NO MATCH (FAIL)"),
        Err(e) => println!("✗ Error: {:?}", e),
    }

    // Test Case 4: TCP packet to port 443 (should DROP - no matching rule)
    // Use different MAC so it doesn't match Rule 4
    println!("\nTest 4: TCP packet to 192.168.1.1:443 (no matching rule)");
    println!("Expected: DROP (default policy)");
    let result = injector.inject_tcp(
        [0x11, 0x22, 0x33, 0x44, 0x55, 0x66], // Different MAC - won't match Rule 4
        [0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
        [10, 0, 0, 1],
        [192, 168, 1, 1],
        12345,
        443,
        b"HTTPS",
    );
    match result {
        Ok(MatchResult::Accept) => println!("✗ Result: ACCEPT (FAIL)"),
        Ok(MatchResult::Drop) => println!("✓ Result: DROP (PASS)"),
        Ok(MatchResult::Reject) => println!("✓ Result: REJECT (PASS)"),
        Ok(MatchResult::NoMatch) => println!("✗ Result: NO MATCH (FAIL)"),
        Err(e) => println!("✗ Error: {:?}", e),
    }

    // Test Case 5: Packet with matching MAC (should ACCEPT)
    println!("\nTest 5: Packet with matching source MAC");
    println!("Expected: ACCEPT");
    let result = injector.inject_tcp(
        [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF], // Matching MAC
        [0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
        [192, 168, 1, 100],
        [192, 168, 1, 200],
        12345,
        9999,
        b"test",
    );
    match result {
        Ok(MatchResult::Accept) => println!("✓ Result: ACCEPT (PASS)"),
        Ok(MatchResult::Drop) => println!("✗ Result: DROP (FAIL)"),
        Ok(MatchResult::Reject) => println!("✗ Result: REJECT (FAIL)"),
        Ok(MatchResult::NoMatch) => println!("✗ Result: NO MATCH (FAIL)"),
        Err(e) => println!("✗ Error: {:?}", e),
    }

    // Test Case 6: UDP from outside 10.0.0.0/8 (should DROP)
    // Use different MAC so it doesn't match Rule 4
    println!("\nTest 6: UDP packet from 192.168.1.5 (outside 10.0.0.0/8)");
    println!("Expected: DROP");
    let result = injector.inject_udp(
        [0x11, 0x22, 0x33, 0x44, 0x55, 0x66], // Different MAC - won't match Rule 4
        [0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
        [192, 168, 1, 5], // Not in 10.0.0.0/8
        [192, 168, 1, 1],
        53,
        53,
        b"DNS",
    );
    match result {
        Ok(MatchResult::Accept) => println!("✗ Result: ACCEPT (FAIL)"),
        Ok(MatchResult::Drop) => println!("✓ Result: DROP (PASS)"),
        Ok(MatchResult::Reject) => println!("✓ Result: REJECT (PASS)"),
        Ok(MatchResult::NoMatch) => println!("✗ Result: NO MATCH (FAIL)"),
        Err(e) => println!("✗ Error: {:?}", e),
    }

    println!("\n{}", "=".repeat(50));
    println!("\nAll tests completed!");
    println!("\nUsage:");
    println!("  cargo run --features std                    # Run test mode");
    println!("  cargo run --features std tap                # Create TAP interface (requires root)");
    println!("  cargo run --features std tap <name>         # Create TAP interface with custom name");
    println!("  cargo run --features std network             # Run network mode (UDP socket)");
    println!("  cargo run --features std network <addr>     # Run network mode (bind to specific address)");
    println!("\nFor TAP interface:");
    println!("  sudo cargo run --features std --bin aifirewall tap");
    println!("  # Then configure: sudo ip addr add 192.168.100.1/24 dev <tap_name>");
}


