//! Benchmark de performance pour le firewall
//!
//! Mesure le temps moyen d'exécution d'une règle de filtrage sur 1 000 000 de paquets.
//!
//! Pour exécuter les benchmarks:
//! ```bash
//! cargo bench --no-default-features
//! ```
//!
//! Les résultats affichent le temps total pour 1 000 000 de paquets.
//! Pour obtenir le temps moyen par paquet, divisez par 1 000 000.

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use aifirewall::firewall::{Firewall, FirewallRule, Action, Layer2Match, Layer3Match, Layer4Match, IpMatch};

/// Crée un paquet Ethernet/IP/TCP standard
fn create_test_packet() -> Vec<u8> {
    let mut packet = Vec::new();
    
    // En-tête Ethernet (14 bytes)
    packet.extend_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]); // dst_mac
    packet.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]); // src_mac
    packet.extend_from_slice(&0x0800u16.to_be_bytes()); // IPv4 ethertype
    
    // En-tête IP (20 bytes)
    packet.push(0x45); // Version 4, IHL 5
    packet.push(0x00); // TOS
    packet.extend_from_slice(&40u16.to_be_bytes()); // Total length
    packet.extend_from_slice(&[0, 0, 0, 0]); // ID, flags, offset
    packet.push(64); // TTL
    packet.push(6); // Protocol = TCP
    packet.extend_from_slice(&[0, 0]); // Checksum
    packet.extend_from_slice(&[192, 168, 1, 100]); // src_ip
    packet.extend_from_slice(&[192, 168, 1, 1]); // dst_ip
    
    // En-tête TCP (20 bytes)
    packet.extend_from_slice(&50000u16.to_be_bytes()); // src_port
    packet.extend_from_slice(&80u16.to_be_bytes()); // dst_port
    packet.extend_from_slice(&[0, 0, 0, 0]); // Seq
    packet.extend_from_slice(&[0, 0, 0, 0]); // Ack
    packet.push(0x50); // Data offset
    packet.push(0x00); // Flags
    packet.extend_from_slice(&[0, 0]); // Window
    packet.extend_from_slice(&[0, 0]); // Checksum
    packet.extend_from_slice(&[0, 0]); // Urgent
    
    packet
}

/// Crée un paquet avec tag VLAN
fn create_vlan_packet(vlan_id: u16) -> Vec<u8> {
    let mut packet = Vec::new();
    
    // En-tête Ethernet
    packet.extend_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]); // dst_mac
    packet.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]); // src_mac
    packet.extend_from_slice(&0x8100u16.to_be_bytes()); // VLAN TPID
    packet.extend_from_slice(&vlan_id.to_be_bytes()); // TCI avec VLAN ID
    packet.extend_from_slice(&0x0800u16.to_be_bytes()); // IPv4 ethertype
    
    // En-tête IP
    packet.push(0x45);
    packet.push(0x00);
    packet.extend_from_slice(&40u16.to_be_bytes());
    packet.extend_from_slice(&[0, 0, 0, 0]);
    packet.push(64);
    packet.push(6); // TCP
    packet.extend_from_slice(&[0, 0]);
    packet.extend_from_slice(&[192, 168, 1, 100]);
    packet.extend_from_slice(&[192, 168, 1, 1]);
    
    // En-tête TCP
    packet.extend_from_slice(&50000u16.to_be_bytes());
    packet.extend_from_slice(&80u16.to_be_bytes());
    packet.extend_from_slice(&[0, 0, 0, 0]);
    packet.extend_from_slice(&[0, 0, 0, 0]);
    packet.push(0x50);
    packet.push(0x00);
    packet.extend_from_slice(&[0, 0]);
    packet.extend_from_slice(&[0, 0]);
    packet.extend_from_slice(&[0, 0]);
    
    packet
}

/// Benchmark: Règle simple L2 (MAC)
fn benchmark_l2_simple(c: &mut Criterion) {
    let mut firewall = Firewall::<1>::new();
    firewall.add_rule(FirewallRule {
        action: Action::Accept,
        l2_match: Layer2Match::Match {
            src_mac: Some([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]),
            dst_mac: None,
            ethertype: Some(0x0800),
            vlan_id: None,
        },
        l3_match: Layer3Match::Any,
        l4_match: Layer4Match::Any,
    }).unwrap();
    
    let packet = create_test_packet();
    
    c.bench_function("L2 Simple (MAC matching)", |b| {
        b.iter(|| {
            for _ in 0..1_000_000 {
                black_box(firewall.match_packet(black_box(&packet))).ok();
            }
        });
    });
}

/// Benchmark: Règle L3 (IP + CIDR)
fn benchmark_l3_cidr(c: &mut Criterion) {
    let mut firewall = Firewall::<1>::new();
    firewall.add_rule(FirewallRule {
        action: Action::Accept,
        l2_match: Layer2Match::Any,
        l3_match: Layer3Match::Match {
            src_ip: Some(IpMatch { addr: [192, 168, 1, 0], cidr: Some(24) }),
            dst_ip: Some(IpMatch { addr: [192, 168, 1, 1], cidr: None }),
            protocol: Some(6), // TCP
        },
        l4_match: Layer4Match::Any,
    }).unwrap();
    
    let packet = create_test_packet();
    
    c.bench_function("L3 CIDR (IP subnet matching)", |b| {
        b.iter(|| {
            for _ in 0..1_000_000 {
                black_box(firewall.match_packet(black_box(&packet))).ok();
            }
        });
    });
}

/// Benchmark: Règle L4 (TCP port)
fn benchmark_l4_port(c: &mut Criterion) {
    let mut firewall = Firewall::<1>::new();
    firewall.add_rule(FirewallRule {
        action: Action::Accept,
        l2_match: Layer2Match::Any,
        l3_match: Layer3Match::Any,
        l4_match: Layer4Match::Match {
            protocol: 6, // TCP
            src_port: Some(50000),
            dst_port: Some(80),
            one_way: false,
        },
    }).unwrap();
    
    let packet = create_test_packet();
    
    c.bench_function("L4 Port (TCP port matching)", |b| {
        b.iter(|| {
            for _ in 0..1_000_000 {
                black_box(firewall.match_packet(black_box(&packet))).ok();
            }
        });
    });
}

/// Benchmark: Règle combinée L2+L3+L4
fn benchmark_combined(c: &mut Criterion) {
    let mut firewall = Firewall::<1>::new();
    firewall.add_rule(FirewallRule {
        action: Action::Accept,
        l2_match: Layer2Match::Match {
            src_mac: Some([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]),
            dst_mac: None,
            ethertype: Some(0x0800),
            vlan_id: None,
        },
        l3_match: Layer3Match::Match {
            src_ip: Some(IpMatch { addr: [192, 168, 1, 0], cidr: Some(24) }),
            dst_ip: Some(IpMatch { addr: [192, 168, 1, 1], cidr: None }),
            protocol: Some(6),
        },
        l4_match: Layer4Match::Match {
            protocol: 6,
            src_port: Some(50000),
            dst_port: Some(80),
            one_way: false,
        },
    }).unwrap();
    
    let packet = create_test_packet();
    
    c.bench_function("Combined L2+L3+L4 (all layers)", |b| {
        b.iter(|| {
            for _ in 0..1_000_000 {
                black_box(firewall.match_packet(black_box(&packet))).ok();
            }
        });
    });
}

/// Benchmark: Règle avec VLAN
fn benchmark_vlan(c: &mut Criterion) {
    let mut firewall = Firewall::<1>::new();
    firewall.add_rule(FirewallRule {
        action: Action::Accept,
        l2_match: Layer2Match::Match {
            src_mac: None,
            dst_mac: None,
            ethertype: Some(0x0800),
            vlan_id: Some(100),
        },
        l3_match: Layer3Match::Any,
        l4_match: Layer4Match::Any,
    }).unwrap();
    
    let packet = create_vlan_packet(100);
    
    c.bench_function("VLAN Tag (802.1Q matching)", |b| {
        b.iter(|| {
            for _ in 0..1_000_000 {
                black_box(firewall.match_packet(black_box(&packet))).ok();
            }
        });
    });
}

/// Benchmark: Règle UDP one-way
fn benchmark_oneway_udp(c: &mut Criterion) {
    let mut firewall = Firewall::<1>::new();
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
    
    // Créer un paquet UDP
    let mut packet = Vec::new();
    packet.extend_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
    packet.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
    packet.extend_from_slice(&0x0800u16.to_be_bytes());
    packet.push(0x45);
    packet.push(0x00);
    packet.extend_from_slice(&28u16.to_be_bytes());
    packet.extend_from_slice(&[0, 0, 0, 0]);
    packet.push(64);
    packet.push(17); // UDP
    packet.extend_from_slice(&[0, 0]);
    packet.extend_from_slice(&[192, 168, 1, 100]);
    packet.extend_from_slice(&[8, 8, 8, 8]);
    packet.extend_from_slice(&12345u16.to_be_bytes());
    packet.extend_from_slice(&53u16.to_be_bytes());
    packet.extend_from_slice(&[0, 8]);
    
    c.bench_function("UDP One-way (reverse detection)", |b| {
        b.iter(|| {
            for _ in 0..1_000_000 {
                black_box(firewall.match_packet(black_box(&packet))).ok();
            }
        });
    });
}

/// Benchmark: Plusieurs règles (first-match)
fn benchmark_multiple_rules(c: &mut Criterion) {
    let mut firewall = Firewall::<10>::new();
    
    // Ajouter 10 règles, la dernière correspond au paquet
    for i in 0..9 {
        firewall.add_rule(FirewallRule {
            action: Action::Drop,
            l2_match: Layer2Match::Match {
                src_mac: Some([0x11 + i, 0x22, 0x33, 0x44, 0x55, 0x66]),
                dst_mac: None,
                ethertype: None,
                vlan_id: None,
            },
            l3_match: Layer3Match::Any,
            l4_match: Layer4Match::Any,
        }).unwrap();
    }
    
    // Dernière règle qui correspond
    firewall.add_rule(FirewallRule {
        action: Action::Accept,
        l2_match: Layer2Match::Match {
            src_mac: Some([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]),
            dst_mac: None,
            ethertype: Some(0x0800),
            vlan_id: None,
        },
        l3_match: Layer3Match::Any,
        l4_match: Layer4Match::Any,
    }).unwrap();
    
    let packet = create_test_packet();
    
    c.bench_function("Multiple Rules (10 rules, last matches)", |b| {
        b.iter(|| {
            for _ in 0..1_000_000 {
                black_box(firewall.match_packet(black_box(&packet))).ok();
            }
        });
    });
}

/// Benchmark: Règle "Any" (match tout)
fn benchmark_any_rule(c: &mut Criterion) {
    let mut firewall = Firewall::<1>::new();
    firewall.add_rule(FirewallRule {
        action: Action::Accept,
        l2_match: Layer2Match::Any,
        l3_match: Layer3Match::Any,
        l4_match: Layer4Match::Any,
    }).unwrap();
    
    let packet = create_test_packet();
    
    c.bench_function("Any Rule (matches all)", |b| {
        b.iter(|| {
            for _ in 0..1_000_000 {
                black_box(firewall.match_packet(black_box(&packet))).ok();
            }
        });
    });
}

/// Benchmark: Pas de correspondance (no match)
fn benchmark_no_match(c: &mut Criterion) {
    let mut firewall = Firewall::<1>::new();
    firewall.add_rule(FirewallRule {
        action: Action::Accept,
        l2_match: Layer2Match::Match {
            src_mac: Some([0x99, 0x88, 0x77, 0x66, 0x55, 0x44]), // Différent MAC
            dst_mac: None,
            ethertype: None,
            vlan_id: None,
        },
        l3_match: Layer3Match::Any,
        l4_match: Layer4Match::Any,
    }).unwrap();
    
    let packet = create_test_packet();
    
    c.bench_function("No Match (rule doesn't match)", |b| {
        b.iter(|| {
            for _ in 0..1_000_000 {
                black_box(firewall.match_packet(black_box(&packet))).ok();
            }
        });
    });
}

criterion_group!(
    benches,
    benchmark_l2_simple,
    benchmark_l3_cidr,
    benchmark_l4_port,
    benchmark_combined,
    benchmark_vlan,
    benchmark_oneway_udp,
    benchmark_multiple_rules,
    benchmark_any_rule,
    benchmark_no_match
);
criterion_main!(benches);

