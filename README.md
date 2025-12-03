# AIFirewall

A Virtual IP Stack with integrated firewall using `smoltcp`, featuring a formally proven filtering language with L2, L3, and L4 filtering capabilities.

## Features

- **Virtual IP Stack**: Built on `smoltcp` for network stack functionality
- **Multi-Layer Filtering**: Support for L2 (Ethernet), L3 (IP), and L4 (TCP/UDP/ICMP) filtering
- **Formal Grammar**: Firewall rules defined using a Parsing Expression Grammar (PEG) with `pest`
- **Formally Proven**: Mathematical proofs of correctness, soundness, and completeness
- **no_std Compatible**: Suitable for embedded systems and constrained environments
- **Packet Injection**: Test interface for injecting packets and verifying firewall behavior

## Project Structure

```
AIFirewall/
├── src/
│   ├── firewall/      # Firewall rule matching engine
│   ├── parser/         # Formal grammar parser (PEG)
│   ├── stack/          # Virtual IP stack wrapper
│   ├── packet_injector/ # Packet injection for testing
│   └── proofs/         # Formal proofs and verification
├── tests/
│   └── property_tests.rs  # Property-based tests
├── PROOFS.md           # Formal proof documentation
└── README.md           # This file
```

## Building

### Prerequisites

- Rust toolchain (latest stable recommended)
- Cargo

### Build Commands

```bash
# Build the library (no_std mode)
cargo build --no-default-features

# Build with std features (if needed)
cargo build --features std

# Build in release mode
cargo build --release --no-default-features
```

## Testing

### Run All Tests

```bash
# Run all tests in no_std mode
cargo test --no-default-features

# Run with std features
cargo test --features std
```

### Run Specific Test Suites

```bash
# Run property-based verification tests
cargo test --no-default-features --test property_tests

# Run a specific test
cargo test --no-default-features --test property_tests property_exact_ip_reflexivity

# Run with output
cargo test --no-default-features --test property_tests -- --nocapture
```

### Test Coverage

The test suite includes:

1. **Property Tests** (`tests/property_tests.rs`):
   - Exact IP matching reflexivity
   - CIDR subnet matching correctness
   - Rule matching determinism
   - First-match-wins semantics
   - No-match behavior
   - Parser functionality

2. **Formal Proofs** (`src/proofs/mod.rs`):
   - Soundness proofs
   - Completeness proofs
   - Termination guarantees
   - CIDR matching correctness

## Running the Binary

The project includes a binary that can run in three modes:

### Test Mode (Default)

Runs packet injection tests:

```bash
cargo run --features std
# or
cargo run --features std --bin aifirewall test
```

### TAP Mode (Virtual Network Interface) - **Recommended**

Creates a virtual TAP network interface that appears in your system's network interfaces. This allows you to process real Ethernet packets at L2/L3/L4 layers.

**Prerequisites:**
- Root/administrator privileges (required to create network interfaces)
- On Linux: `tun` kernel module loaded (`sudo modprobe tun`)
- On macOS: No additional setup needed

**Platform Differences:**
- **Linux**: Full TAP mode support - processes Ethernet frames (L2)
- **macOS**: Uses utun (TUN mode) - processes IP packets (L3) only. Interface name is auto-generated (utun0, utun1, etc.)

**Usage:**

```bash
# Create TAP/TUN interface with default name (tap0 on Linux, auto on macOS)
sudo cargo run --features std --bin aifirewall tap

# Create TAP interface with custom name (Linux only, max 15 chars)
sudo cargo run --features std --bin aifirewall tap mytap0
```

**Note**: On macOS, if you specify a custom name and it fails, the system will auto-generate a name (utun0, utun1, etc.).

**After starting, configure the interface:**

**On Linux:**
```bash
# In another terminal (as root)
sudo ip addr add 192.168.100.1/24 dev aifw0
sudo ip link set aifw0 up
sudo ip route add 192.168.100.0/24 dev aifw0
```

**On macOS:**
```bash
# In another terminal (as root)
# First, find the actual interface name (it may be utun0, utun1, etc.)
ifconfig | grep utun

# Then configure it (replace utun0 with the actual name)
# TUN interfaces on macOS are point-to-point and require BOTH local and destination IPs
sudo ifconfig utun0 192.168.100.1 192.168.100.2 up
```

**Note**: On macOS, TUN interfaces are point-to-point, so you must specify both:
- Local IP: `192.168.100.1` (the interface's IP)
- Destination IP: `192.168.100.2` (the peer IP - can be any IP in the subnet)

**Testing the TAP interface:**

Once configured, you can send traffic to the interface:

```bash
# Ping the interface
ping 192.168.100.1

# Send TCP traffic
nc 192.168.100.1 80

# Send UDP traffic
echo "test" | nc -u 192.168.100.1 53
```

The firewall will display each packet received, including:
- Ethernet header information (MAC addresses, ethertype)
- Firewall decision (ACCEPT/DROP/REJECT)
- Packet size and timestamp

**Viewing the interface:**

You can verify the interface was created:

**On Linux:**
```bash
ip link show aifw0
# or
ifconfig aifw0
```

**On macOS:**
```bash
ifconfig aifw0
# or
networksetup -listallnetworkservices
```

**Removing TUN interfaces:**

To clean up TUN interfaces:

**On macOS:**
```bash
# List all utun interfaces
ifconfig | grep -E "^utun"

# Remove a specific interface (bring it down first)
sudo ifconfig utun0 down
sudo ifconfig utun0 destroy

# Or use the provided cleanup script
sudo ./cleanup_tun.sh
```

**On Linux:**
```bash
# List all tap interfaces
ip tuntap show

# Remove a specific interface
sudo ip tuntap del mode tap name tap0

# Or use the provided cleanup script
sudo ./cleanup_tun.sh
```

**Note**: On macOS, some utun interfaces may be managed by system processes (VPN, etc.) and cannot be removed. Only remove interfaces you created yourself.

### Network Mode (UDP Socket)

Binds to a UDP socket and processes packets (simpler, no root required):

```bash
# Bind to default address (0.0.0.0:8888)
cargo run --features std --bin aifirewall network

# Bind to specific address
cargo run --features std --bin aifirewall network 0.0.0.0:8888
```

Once running, you can send UDP packets to test the firewall:

```bash
# From another terminal
echo "test packet" | nc -u localhost 8888
```

The firewall will process each packet and display whether it was ACCEPTED, DROPPED, or REJECTED based on the configured rules.

**Note**: Network mode uses UDP sockets for demonstration. For full L2/L3/L4 packet processing, use TAP mode instead.
- libpcap for packet capture

## Usage

### Basic Example

```rust
use aifirewall::*;

// Parse firewall rules
let rules_str = r#"
    ACCEPT ip dst ip 192.168.1.1 tcp dst port 80
    DROP ip proto icmp *
"#;

let firewall_rules = parse_firewall_rules(rules_str)?;

// Create firewall and stack
let mut firewall = Firewall::new();
firewall.add_rules(firewall_rules)?;

let stack = VirtualStack::with_firewall(firewall);
let mut injector = PacketInjector::new(stack);

// Inject a TCP packet
let result = injector.inject_tcp(
    [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF], // src_mac
    [0x11, 0x22, 0x33, 0x44, 0x55, 0x66], // dst_mac
    [10, 0, 0, 1],                        // src_ip
    [192, 168, 1, 1],                     // dst_ip
    12345,                                 // src_port
    80,                                    // dst_port
    b"GET / HTTP/1.1\r\n",                // payload
)?;

match result {
    MatchResult::Accept => println!("Packet accepted"),
    MatchResult::Drop => println!("Packet dropped"),
    MatchResult::Reject => println!("Packet rejected"),
    MatchResult::NoMatch => println!("No matching rule"),
}
```

## Firewall Rule Language

### Grammar

The firewall uses a formal grammar defined in `src/parser/grammar.pest`. Rules follow this structure:

```
ACTION LAYER_MATCH [LAYER_MATCH ...]
```

### Actions

- `ACCEPT`: Allow the packet
- `DROP`: Silently drop the packet
- `REJECT`: Reject the packet (currently implemented as drop)

### Layer 2 (Ethernet) Matching

```rust
// Match specific source MAC
ACCEPT ether src mac aa:bb:cc:dd:ee:ff *

// Match specific destination MAC
ACCEPT ether dst mac 11:22:33:44:55:66 *

// Match ethertype
ACCEPT ether type 0x0800 *

// Match all L2 traffic
ACCEPT ether *
```

### Layer 3 (IP) Matching

```rust
// Match destination IP
ACCEPT ip dst ip 192.168.1.1 *

// Match source IP with CIDR
ACCEPT ip src ip 10.0.0.0/8 *

// Match protocol
ACCEPT ip proto tcp *
ACCEPT ip proto udp *
ACCEPT ip proto icmp *
ACCEPT ip proto igmp *  // IGMP for multicast
ACCEPT ip proto 6 *  // TCP by number
ACCEPT ip proto 2 *  // IGMP by number

// Match all IP traffic
ACCEPT ip *
```

### Layer 4 (TCP/UDP/ICMP) Matching

```rust
// Match TCP destination port
ACCEPT ip * tcp dst port 80

// Match UDP source port
ACCEPT ip * udp src port 53

// Match TCP with both ports
ACCEPT ip * tcp src port 12345 dst port 80

// Match all TCP traffic
ACCEPT ip * tcp *

// One-way UDP (allow outbound, block replies)
ACCEPT ip src ip 192.168.1.0/24 udp dst port 53 oneway
ACCEPT ip src ip 10.0.0.0/8 udp dst port 123 oneway  // NTP one-way
```

**One-way UDP**: The `oneway` or `one-way` keyword allows UDP traffic in the forward direction but blocks reverse/reply packets. This is useful for:
- Outbound DNS queries (block DNS responses)
- One-way data streaming
- Outbound NTP requests (block NTP responses)

### Combined Rules

```rust
// Combine L2, L3, and L4
ACCEPT ether src mac aa:bb:cc:dd:ee:ff ip dst ip 192.168.1.1 tcp dst port 80

// Combine L3 and L4
ACCEPT ip dst ip 192.168.1.1 tcp dst port 443
```

### Comments

Rules can include comments:

```rust
# Allow HTTP traffic
ACCEPT ip dst ip 192.168.1.1 tcp dst port 80

# Block ICMP
DROP ip proto icmp *
```

## Packet Injection Testing

### Injecting Different Packet Types

```rust
use aifirewall::*;

let mut injector = PacketInjector::new(VirtualStack::new());

// Inject TCP packet
let result = injector.inject_tcp(
    src_mac, dst_mac, src_ip, dst_ip,
    src_port, dst_port, payload
)?;

// Inject UDP packet
let result = injector.inject_udp(
    src_mac, dst_mac, src_ip, dst_ip,
    src_port, dst_port, payload
)?;

// Inject ICMP packet
let result = injector.inject_icmp(
    src_mac, dst_mac, src_ip, dst_ip,
    icmp_type, icmp_code, payload
)?;

// Inject raw Ethernet packet
let packet: heapless::Vec<u8, 1500> = /* ... */;
let result = injector.inject_raw(packet)?;
```

### Receiving Accepted Packets

```rust
// After injection, check if packet was accepted
if let Some(packet) = injector.receive() {
    println!("Received packet: {:?}", packet);
}
```

## Formal Proofs

The firewall implementation includes formal mathematical proofs of correctness. See `PROOFS.md` for detailed proofs of:

- **Soundness**: Rules only match packets that satisfy their conditions
- **Completeness**: Packets satisfying conditions are matched
- **Determinism**: Same inputs always produce same outputs
- **Termination**: Algorithm always completes
- **CIDR Correctness**: Subnet matching is mathematically correct

### Running Proof Verification

The proofs module can be enabled with the `proofs` feature:

```bash
cargo build --features proofs
```

Formal verification properties are documented in `src/proofs/mod.rs` and verified through property-based testing.

## Example Test Scenarios

### Test 1: Allow HTTP Traffic

```rust
let rules = "ACCEPT ip dst ip 192.168.1.1 tcp dst port 80\n";
let firewall_rules = parse_firewall_rules(rules)?;

let mut firewall = Firewall::new();
firewall.add_rules(firewall_rules)?;

let stack = VirtualStack::with_firewall(firewall);
let mut injector = PacketInjector::new(stack);

// This should be accepted
let result = injector.inject_tcp(
    [0; 6], [0; 6],
    [10, 0, 0, 1], [192, 168, 1, 1],
    12345, 80, b"GET /"
)?;
assert_eq!(result, MatchResult::Accept);

// This should be dropped (wrong port)
let result = injector.inject_tcp(
    [0; 6], [0; 6],
    [10, 0, 0, 1], [192, 168, 1, 1],
    12345, 443, b"HTTPS"
)?;
assert_eq!(result, MatchResult::Drop);
```

### Test 2: Block ICMP

```rust
let rules = "DROP ip proto icmp *\n";
let firewall_rules = parse_firewall_rules(rules)?;

let mut firewall = Firewall::new();
firewall.add_rules(firewall_rules)?;

let stack = VirtualStack::with_firewall(firewall);
let mut injector = PacketInjector::new(stack);

// This should be dropped
let result = injector.inject_icmp(
    [0; 6], [0; 6],
    [10, 0, 0, 1], [192, 168, 1, 1],
    8, 0, b"ping"
)?;
assert_eq!(result, MatchResult::Drop);
```

### Test 3: CIDR Subnet Matching

```rust
let rules = "ACCEPT ip src ip 10.0.0.0/8 *\n";
let firewall_rules = parse_firewall_rules(rules)?;

let mut firewall = Firewall::new();
firewall.add_rules(firewall_rules)?;

let stack = VirtualStack::with_firewall(firewall);
let mut injector = PacketInjector::new(stack);

// All 10.x.x.x addresses should match
for host in [1, 5, 100, 255].iter() {
    let result = injector.inject_udp(
        [0; 6], [0; 6],
        [10, 0, 0, *host], [192, 168, 1, 1],
        53, 53, b"DNS"
    )?;
    assert_eq!(result, MatchResult::Accept);
}
```

## Performance Benchmarks

Le projet inclut des benchmarks de performance pour mesurer le temps d'exécution moyen d'une règle de filtrage.

### Exécuter les Benchmarks

```bash
cargo bench --no-default-features
```

Les benchmarks testent 1 000 000 de paquets pour chaque type de règle et affichent:
- Le temps total pour 1 000 000 de paquets
- Le temps moyen par paquet (diviser par 1 000 000)

### Types de Benchmarks

1. **L2 Simple** - Matching MAC address
2. **L3 CIDR** - Matching IP avec CIDR subnet
3. **L4 Port** - Matching TCP/UDP ports
4. **Combined** - Matching L2+L3+L4 combinés
5. **VLAN Tag** - Matching VLAN tags (802.1Q)
6. **UDP One-way** - Matching UDP avec détection reverse
7. **Multiple Rules** - 10 règles, dernière correspond
8. **Any Rule** - Règle qui match tout
9. **No Match** - Aucune règle ne correspond

### Résultats Typiques

Sur une machine moderne, les benchmarks montrent généralement:
- **L2 Simple**: ~4.8 ms pour 1M paquets (~4.8 ns/paquet)
- **L3 CIDR**: ~4.8 ms pour 1M paquets (~4.8 ns/paquet)
- **L4 Port**: ~4.0 ms pour 1M paquets (~4.0 ns/paquet)
- **Combined**: ~7.2 ms pour 1M paquets (~7.2 ns/paquet)
- **VLAN**: ~7.4 ms pour 1M paquets (~7.4 ns/paquet)
- **UDP One-way**: ~7.4 ms pour 1M paquets (~7.4 ns/paquet)

Ces résultats permettent de traiter des millions de paquets par seconde sur un seul cœur CPU.

## Performance Considerations

- **Rule Capacity**: Firewall uses `heapless::Vec` with compile-time capacity (default: 32 rules)
- **Packet Buffer**: Stack uses `VecDeque` for packet buffering
- **Time Complexity**: O(N) where N is the number of rules (first-match semantics)
- **Memory**: All allocations are bounded and stack-allocated where possible

## Limitations

- Currently supports IPv4 only
- ICMP rejection sends no error message (silent drop)
- Parser may need refinement for complex rule combinations
- Packet size limited to 1500 bytes (Ethernet MTU)

## Contributing

When adding new features:

1. Update the formal grammar in `src/parser/grammar.pest`
2. Add corresponding proofs in `src/proofs/mod.rs`
3. Update `PROOFS.md` with new theorems
4. Add property-based tests in `tests/property_tests.rs`
5. Ensure all tests pass: `cargo test --no-default-features`

## License

[Specify your license here]

## References

- [smoltcp](https://github.com/smoltcp-rs/smoltcp) - Rust network stack
- [pest](https://github.com/pest-parser/pest) - PEG parser generator
- [PROOFS.md](PROOFS.md) - Formal proof documentation

