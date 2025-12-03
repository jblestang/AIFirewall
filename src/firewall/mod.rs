use core::fmt;
use hash32::{Hash, Hasher};

// Ethernet constants
const ETHERNET_HEADER_SIZE: usize = 14;
const MAC_ADDRESS_SIZE: usize = 6;
const ETHERNET_DST_MAC_OFFSET: usize = 0;
const ETHERNET_SRC_MAC_OFFSET: usize = 6;
const ETHERNET_ETHERTYPE_OFFSET: usize = 12;

// VLAN constants
const VLAN_TPID: u16 = 0x8100;
const VLAN_TAG_SIZE: usize = 4;
const VLAN_TCI_OFFSET: usize = 14;
const VLAN_ETHERTYPE_OFFSET: usize = 16;
const VLAN_ID_MASK: u16 = 0x0FFF;
const ETHERNET_HEADER_WITH_VLAN_SIZE: usize = ETHERNET_HEADER_SIZE + VLAN_TAG_SIZE;

// IP constants
const IPV4_ETHERTYPE: u16 = 0x0800;
const IP_HEADER_MIN_SIZE: usize = 20;
const IP_VERSION_OFFSET: usize = 0;
const IP_IHL_MASK: u8 = 0x0F;
const IP_TOTAL_LENGTH_OFFSET: usize = 2;
const IP_ID_OFFSET: usize = 4;
const IP_FLAGS_OFFSET: usize = 6;
const IP_TTL_OFFSET: usize = 8;
const IP_PROTOCOL_OFFSET: usize = 9;
const IP_CHECKSUM_OFFSET: usize = 10;
const IP_SRC_IP_OFFSET: usize = 12;
const IP_DST_IP_OFFSET: usize = 16;
const IP_ADDRESS_SIZE: usize = 4;

// IP Fragment flags
const IP_FLAG_MF: u16 = 0x2000; // More Fragments
const IP_FLAG_DF: u16 = 0x4000; // Don't Fragment
const IP_FRAGMENT_OFFSET_MASK: u16 = 0x1FFF; // 13 bits for fragment offset

// Protocol constants
const PROTOCOL_TCP: u8 = 6;
const PROTOCOL_UDP: u8 = 17;
const PROTOCOL_ICMP: u8 = 1;
const PROTOCOL_IGMP: u8 = 2;

// TCP/UDP constants
const PORT_SIZE: usize = 2;
const UDP_HEADER_SIZE: usize = 8;
const TCP_HEADER_MIN_SIZE: usize = 20;
const TCP_FLAGS_OFFSET: usize = 13;

// TCP flags
const TCP_FLAG_SYN: u8 = 0x02;
const TCP_FLAG_ACK: u8 = 0x10;
const TCP_FLAG_FIN: u8 = 0x01;
const TCP_FLAG_RST: u8 = 0x04;

// Connection tracking constants
const CONNECTION_CLEANUP_INTERVAL: u64 = 1000;
const CONNECTION_TIMEOUT: u64 = 300;

// Fragment tracking constants
const FRAGMENT_CLEANUP_INTERVAL: u64 = 1000;
const FRAGMENT_TIMEOUT: u64 = 60; // RFC 791: 60 seconds timeout for fragment reassembly

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    Accept,
    Drop,
    Reject,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Layer2Match {
    Any,
    Match {
        src_mac: Option<[u8; 6]>,
        dst_mac: Option<[u8; 6]>,
        ethertype: Option<u16>,
        vlan_id: Option<u16>, // VLAN ID (0-4095), None means no VLAN tag required
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Layer3Match {
    Any,
    Match {
        src_ip: Option<IpMatch>,
        dst_ip: Option<IpMatch>,
        protocol: Option<u8>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpMatch {
    pub addr: [u8; 4], // IPv4 address as bytes
    pub cidr: Option<u8>,
}

impl IpMatch {
    pub fn matches(&self, ip: [u8; 4]) -> bool {
        if let Some(cidr) = self.cidr {
            if cidr > 32 {
                return false;
            }
            // Handle special case: /0 matches all IPs
            if cidr == 0 {
                return true;
            }
            let mask = !((1u32 << (32 - cidr)) - 1);
            let self_net = u32::from_be_bytes(self.addr) & mask;
            let ip_net = u32::from_be_bytes(ip) & mask;
            self_net == ip_net
        } else {
            self.addr == ip
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Layer4Match {
    Any,
    Match {
        protocol: u8,
        src_port: Option<u16>,
        dst_port: Option<u16>,
        one_way: bool, // If true, only allow forward direction (block replies)
    },
}

#[derive(Debug, Clone)]
pub struct FirewallRule {
    pub action: Action,
    pub l2_match: Layer2Match,
    pub l3_match: Layer3Match,
    pub l4_match: Layer4Match,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MatchResult {
    Accept,
    Drop,
    Reject,
    NoMatch,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FirewallError {
    InvalidPacket,
}

impl fmt::Display for FirewallError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FirewallError::InvalidPacket => write!(f, "Invalid packet format"),
        }
    }
}

/// Connection identifier for tracking
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ConnectionId {
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    src_port: u16,
    dst_port: u16,
    protocol: u8,
}

impl Hash for ConnectionId {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.src_ip.hash(state);
        self.dst_ip.hash(state);
        self.src_port.hash(state);
        self.dst_port.hash(state);
        self.protocol.hash(state);
    }
}

impl ConnectionId {
    fn new(src_ip: [u8; 4], dst_ip: [u8; 4], src_port: u16, dst_port: u16, protocol: u8) -> Self {
        Self {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol,
        }
    }
    
    /// Create a normalized connection ID (smaller IP first for bidirectional matching)
    fn normalized(src_ip: [u8; 4], dst_ip: [u8; 4], src_port: u16, dst_port: u16, protocol: u8) -> Self {
        // For TCP/UDP, normalize by putting smaller IP first
        // This allows matching both directions of a connection
        if protocol == PROTOCOL_TCP || protocol == PROTOCOL_UDP {
            let src_ip_u32 = u32::from_be_bytes(src_ip);
            let dst_ip_u32 = u32::from_be_bytes(dst_ip);
            
            if src_ip_u32 < dst_ip_u32 || (src_ip_u32 == dst_ip_u32 && src_port < dst_port) {
                Self {
                    src_ip,
                    dst_ip,
                    src_port,
                    dst_port,
                    protocol,
                }
            } else {
                Self {
                    src_ip: dst_ip,
                    dst_ip: src_ip,
                    src_port: dst_port,
                    dst_port: src_port,
                    protocol,
                }
            }
        } else {
            Self {
                src_ip,
                dst_ip,
                src_port,
                dst_port,
                protocol,
            }
        }
    }
}

/// Connection state for tracking
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConnectionState {
    /// TCP: SYN sent, waiting for SYN-ACK
    SynSent,
    /// TCP: Connection established (SYN-ACK received or ACK after SYN)
    Established,
    /// TCP: FIN sent, connection closing
    FinWait,
    /// UDP: Connection tracked (bidirectional)
    Tracked,
}

/// Connection entry with timestamp
#[derive(Debug, Clone)]
struct ConnectionEntry {
    state: ConnectionState,
    last_seen: u64, // Timestamp in some unit (could be packet count or time)
}

/// Fragment identifier for tracking IP fragments
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FragmentId {
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    ip_id: u16,
    protocol: u8,
}

impl Hash for FragmentId {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.src_ip.hash(state);
        self.dst_ip.hash(state);
        self.ip_id.hash(state);
        self.protocol.hash(state);
    }
}

/// Fragment entry tracking first fragment acceptance
#[derive(Debug, Clone)]
struct FragmentEntry {
    first_fragment_seen: bool, // True if first fragment (offset=0) has been accepted
    last_seen: u64,
}

pub struct Firewall<const N: usize = 32, const C: usize = 1024, const F: usize = 512> {
    rules: heapless::Vec<FirewallRule, N>,
    connections: heapless::FnvIndexMap<ConnectionId, ConnectionEntry, C>,
    fragments: heapless::FnvIndexMap<FragmentId, FragmentEntry, F>,
    packet_counter: u64,
}

impl<const N: usize, const C: usize, const F: usize> Firewall<N, C, F> {
    pub fn new() -> Self {
        Self {
            rules: heapless::Vec::new(),
            connections: heapless::FnvIndexMap::new(),
            fragments: heapless::FnvIndexMap::new(),
            packet_counter: 0,
        }
    }
    
    pub fn add_rule(&mut self, rule: FirewallRule) -> Result<(), ()> {
        self.rules.push(rule).map_err(|_| ())
    }
    
    pub fn clear_rules(&mut self) {
        self.rules.clear();
    }
    
    /// Clean up expired connections (older than timeout)
    fn cleanup_connections(&mut self, timeout: u64) {
        let current = self.packet_counter;
        // Collect keys to remove (can't remove while iterating)
        let mut keys_to_remove = heapless::Vec::<ConnectionId, C>::new();
        for (id, entry) in self.connections.iter() {
            if current.saturating_sub(entry.last_seen) > timeout {
                let _ = keys_to_remove.push(*id);
            }
        }
        // Remove expired connections
        for id in keys_to_remove.iter() {
            let _ = self.connections.remove(id);
        }
    }
    
    /// Clean up expired fragments (older than timeout)
    fn cleanup_fragments(&mut self, timeout: u64) {
        let current = self.packet_counter;
        // Collect keys to remove (can't remove while iterating)
        let mut keys_to_remove = heapless::Vec::<FragmentId, F>::new();
        for (id, entry) in self.fragments.iter() {
            if current.saturating_sub(entry.last_seen) > timeout {
                let _ = keys_to_remove.push(*id);
            }
        }
        // Remove expired fragments
        for id in keys_to_remove.iter() {
            let _ = self.fragments.remove(id);
        }
    }
    
    /// Check if first fragment has been seen for this fragment ID
    /// 
    /// RFC 791 Compliance:
    /// According to RFC 791 (Internet Protocol), fragments can arrive out of order.
    /// However, for security reasons, a firewall should only accept fragments if the
    /// first fragment (offset=0) has been accepted. This prevents fragment-based attacks
    /// where malicious fragments are sent without the first fragment containing the
    /// L4 header (ports for TCP/UDP).
    /// 
    /// Fragment identification:
    /// - src_ip, dst_ip: Source and destination IP addresses
    /// - ip_id: IP Identification field (16 bits) - unique per fragmented packet
    /// - protocol: IP protocol number (TCP=6, UDP=17, etc.)
    /// 
    /// Returns:
    /// - Some(true): First fragment has been seen, fragment can be accepted
    /// - Some(false): First fragment has NOT been seen, fragment should be dropped
    /// - None: Cannot track (missing IP information)
    fn check_fragment_tracking(
        &mut self,
        src_ip: Option<[u8; 4]>,
        dst_ip: Option<[u8; 4]>,
        ip_id: Option<u16>,
        protocol: Option<u8>,
        fragment_offset: usize,
    ) -> Option<bool> {
        // Only track if we have all required information
        let (src_ip, dst_ip, ip_id, protocol) = match (src_ip, dst_ip, ip_id, protocol) {
            (Some(s), Some(d), Some(id), Some(p)) => (s, d, id, p),
            _ => return None,
        };
        
        let frag_id = FragmentId {
            src_ip,
            dst_ip,
            ip_id,
            protocol,
        };
        
        // Check if fragment entry exists (O(1) lookup with Map)
        if let Some(entry) = self.fragments.get_mut(&frag_id) {
            entry.last_seen = self.packet_counter;
            
            // If this is the first fragment (offset = 0), mark it as seen
            if fragment_offset == 0 {
                entry.first_fragment_seen = true;
            }
            
            return Some(entry.first_fragment_seen);
        }
        
        // No entry exists - create one if this is the first fragment
        if fragment_offset == 0 {
            // First fragment - create entry and mark as seen
            let _ = self.fragments.insert(frag_id, FragmentEntry {
                first_fragment_seen: true,
                last_seen: self.packet_counter,
            });
            Some(true)
        } else {
            // Not first fragment and no entry exists - first fragment not seen
            // RFC 791: Require first fragment before accepting subsequent fragments
            Some(false)
        }
    }
    
    /// Check if packet belongs to an established connection
    fn check_connection_tracking(
        &mut self,
        src_ip: Option<[u8; 4]>,
        dst_ip: Option<[u8; 4]>,
        protocol: Option<u8>,
        src_port: Option<u16>,
        dst_port: Option<u16>,
        packet: &[u8],
    ) -> Option<MatchResult> {
        // Only track TCP and UDP connections
        let protocol = protocol?;
        if protocol != PROTOCOL_TCP && protocol != PROTOCOL_UDP {
            return None;
        }
        
        let src_ip = src_ip?;
        let dst_ip = dst_ip?;
        let src_port = src_port?;
        let dst_port = dst_port?;
        
        // Normalize connection ID for bidirectional matching
        let conn_id = ConnectionId::normalized(src_ip, dst_ip, src_port, dst_port, protocol);
        
        // Check if connection exists (O(1) lookup with Map)
        if let Some(entry) = self.connections.get_mut(&conn_id) {
            // Connection exists - check state
            match entry.state {
                ConnectionState::Established | ConnectionState::Tracked => {
                    // Update last seen
                    entry.last_seen = self.packet_counter;
                    // Fast path: allow established connections
                    return Some(MatchResult::Accept);
                }
                ConnectionState::SynSent | ConnectionState::FinWait => {
                    // Update last seen
                    entry.last_seen = self.packet_counter;
                    // Still in progress, check rules
                    return None;
                }
            }
        }
        
        // For TCP, check if this is a SYN packet (new connection)
        if protocol == PROTOCOL_TCP && packet.len() >= IP_HEADER_MIN_SIZE {
            // TCP flags are at offset 13 of TCP header
            // Need to find TCP header offset
            let ip_offset = if packet.len() >= ETHERNET_HEADER_WITH_VLAN_SIZE && 
                u16::from_be_bytes([packet[ETHERNET_ETHERTYPE_OFFSET], packet[ETHERNET_ETHERTYPE_OFFSET + 1]]) == VLAN_TPID {
                ETHERNET_HEADER_WITH_VLAN_SIZE
            } else {
                ETHERNET_HEADER_SIZE
            };
            
            if packet.len() >= ip_offset + IP_HEADER_MIN_SIZE {
                let ip_header_len = (packet[ip_offset] & IP_IHL_MASK) as usize * 4;
                let tcp_offset = ip_offset + ip_header_len;
                
                if packet.len() > tcp_offset + TCP_FLAGS_OFFSET {
                    let tcp_flags = packet[tcp_offset + TCP_FLAGS_OFFSET];
                    let syn = (tcp_flags & TCP_FLAG_SYN) != 0;
                    let ack = (tcp_flags & TCP_FLAG_ACK) != 0;
                    let fin = (tcp_flags & TCP_FLAG_FIN) != 0;
                    let rst = (tcp_flags & TCP_FLAG_RST) != 0;
                    
                    if syn && !ack {
                        // New connection attempt - will be checked by rules
                        // Track it as SynSent
                        let _ = self.connections.insert(conn_id, ConnectionEntry {
                            state: ConnectionState::SynSent,
                            last_seen: self.packet_counter,
                        });
                    } else if syn && ack {
                        // SYN-ACK response - connection established
                        // Update existing or insert new
                        if let Some(entry) = self.connections.get_mut(&conn_id) {
                            entry.state = ConnectionState::Established;
                            entry.last_seen = self.packet_counter;
                        } else {
                            let _ = self.connections.insert(conn_id, ConnectionEntry {
                                state: ConnectionState::Established,
                                last_seen: self.packet_counter,
                            });
                        }
                        return Some(MatchResult::Accept);
                    } else if ack && !syn && !fin {
                        // ACK packet - check if we have SynSent state
                        if let Some(entry) = self.connections.get_mut(&conn_id) {
                            if entry.state == ConnectionState::SynSent {
                                // Connection established
                                entry.state = ConnectionState::Established;
                                entry.last_seen = self.packet_counter;
                                return Some(MatchResult::Accept);
                            }
                        }
                    } else if fin {
                        // FIN packet - mark as closing
                        if let Some(entry) = self.connections.get_mut(&conn_id) {
                            entry.state = ConnectionState::FinWait;
                            entry.last_seen = self.packet_counter;
                        } else {
                            let _ = self.connections.insert(conn_id, ConnectionEntry {
                                state: ConnectionState::FinWait,
                                last_seen: self.packet_counter,
                            });
                        }
                    } else if rst {
                        // RST packet - remove connection
                        let _ = self.connections.remove(&conn_id);
                    }
                }
            }
        }
        
        // For UDP, if we see a packet and it matches a rule, track it
        // (UDP tracking happens after rule matching)
        None
    }
    
    /// Track UDP connection after it's been accepted by a rule
    fn track_udp_connection(
        &mut self,
        src_ip: Option<[u8; 4]>,
        dst_ip: Option<[u8; 4]>,
        src_port: Option<u16>,
        dst_port: Option<u16>,
    ) {
        if let (Some(src_ip), Some(dst_ip), Some(src_port), Some(dst_port)) = (src_ip, dst_ip, src_port, dst_port) {
            let conn_id = ConnectionId::normalized(src_ip, dst_ip, src_port, dst_port, PROTOCOL_UDP);
            // Check if already exists (O(1) lookup with Map)
            if let Some(entry) = self.connections.get_mut(&conn_id) {
                entry.last_seen = self.packet_counter;
            } else {
                let _ = self.connections.insert(conn_id, ConnectionEntry {
                    state: ConnectionState::Tracked,
                    last_seen: self.packet_counter,
                });
            }
        }
    }
    
    pub fn match_packet(&mut self, packet: &[u8]) -> Result<MatchResult, FirewallError> {
        // Increment packet counter
        self.packet_counter = self.packet_counter.wrapping_add(1);
        
        // Cleanup old connections and fragments periodically
        if self.packet_counter % CONNECTION_CLEANUP_INTERVAL == 0 {
            self.cleanup_connections(CONNECTION_TIMEOUT);
            self.cleanup_fragments(FRAGMENT_TIMEOUT);
        }
        
        // Parse Ethernet header
        if packet.len() < ETHERNET_HEADER_SIZE {
            return Err(FirewallError::InvalidPacket);
        }
        
        let dst_mac = &packet[ETHERNET_DST_MAC_OFFSET..ETHERNET_DST_MAC_OFFSET + MAC_ADDRESS_SIZE];
        let src_mac = &packet[ETHERNET_SRC_MAC_OFFSET..ETHERNET_SRC_MAC_OFFSET + MAC_ADDRESS_SIZE];
        
        // Check for VLAN tag (802.1Q) - ethertype 0x8100 indicates VLAN tag
        let (ethertype, vlan_id, ip_offset) = if packet.len() >= ETHERNET_HEADER_WITH_VLAN_SIZE {
            let potential_ethertype = u16::from_be_bytes([packet[ETHERNET_ETHERTYPE_OFFSET], packet[ETHERNET_ETHERTYPE_OFFSET + 1]]);
            if potential_ethertype == VLAN_TPID {
                // VLAN tagged frame
                // TCI (Tag Control Information) is at bytes 14-15
                // VLAN ID is in lower 12 bits of TCI
                let tci = u16::from_be_bytes([packet[VLAN_TCI_OFFSET], packet[VLAN_TCI_OFFSET + 1]]);
                let vid = tci & VLAN_ID_MASK; // Extract VLAN ID (12 bits)
                // Real ethertype is at bytes 16-17
                let real_ethertype = u16::from_be_bytes([packet[VLAN_ETHERTYPE_OFFSET], packet[VLAN_ETHERTYPE_OFFSET + 1]]);
                (real_ethertype, Some(vid), ETHERNET_HEADER_WITH_VLAN_SIZE) // IP header starts at offset 18
            } else {
                // No VLAN tag
                (potential_ethertype, None, ETHERNET_HEADER_SIZE) // IP header starts at offset 14
            }
        } else {
            let ethertype = u16::from_be_bytes([packet[ETHERNET_ETHERTYPE_OFFSET], packet[ETHERNET_ETHERTYPE_OFFSET + 1]]);
            (ethertype, None, ETHERNET_HEADER_SIZE)
        };
        
        // Parse IP header if present (Ethertype 0x0800 for IPv4)
        let (src_ip, dst_ip, protocol, src_port, dst_port, is_fragment, fragment_offset, ip_id) = if ethertype == IPV4_ETHERTYPE && packet.len() >= ip_offset + IP_HEADER_MIN_SIZE {
            let ip_header_len = (packet[ip_offset] & IP_IHL_MASK) as usize * 4;
            if packet.len() < ip_offset + ip_header_len {
                return Err(FirewallError::InvalidPacket);
            }
            
            let src_ip_bytes = &packet[ip_offset + IP_SRC_IP_OFFSET..ip_offset + IP_SRC_IP_OFFSET + IP_ADDRESS_SIZE];
            let dst_ip_bytes = &packet[ip_offset + IP_DST_IP_OFFSET..ip_offset + IP_DST_IP_OFFSET + IP_ADDRESS_SIZE];
            let src_ip = [src_ip_bytes[0], src_ip_bytes[1], src_ip_bytes[2], src_ip_bytes[3]];
            let dst_ip = [dst_ip_bytes[0], dst_ip_bytes[1], dst_ip_bytes[2], dst_ip_bytes[3]];
            let protocol = packet[ip_offset + IP_PROTOCOL_OFFSET];
            
            // Extract IP ID
            let ip_id = u16::from_be_bytes([packet[ip_offset + IP_ID_OFFSET], packet[ip_offset + IP_ID_OFFSET + 1]]);
            
            // Check if this is a fragment (offset > 0 or MF flag set)
            let flags_and_offset = u16::from_be_bytes([packet[ip_offset + IP_FLAGS_OFFSET], packet[ip_offset + IP_FLAGS_OFFSET + 1]]);
            let fragment_offset = (flags_and_offset & IP_FRAGMENT_OFFSET_MASK) as usize * 8;
            let is_fragment = fragment_offset > 0 || (flags_and_offset & IP_FLAG_MF) != 0;
            
            // Parse L4 ports if TCP/UDP (only for non-fragmented packets)
            // For fragmented packets, ports are only in the first fragment
            let (src_port, dst_port) = if (protocol == PROTOCOL_TCP || protocol == PROTOCOL_UDP) && 
                packet.len() >= ip_offset + ip_header_len + PORT_SIZE * 2 && !is_fragment {
                let l4_offset = ip_offset + ip_header_len;
                let src_port = u16::from_be_bytes([packet[l4_offset], packet[l4_offset + 1]]);
                let dst_port = u16::from_be_bytes([packet[l4_offset + PORT_SIZE], packet[l4_offset + PORT_SIZE + 1]]);
                (Some(src_port), Some(dst_port))
            } else {
                (None, None)
            };
            
            (Some(src_ip), Some(dst_ip), Some(protocol), src_port, dst_port, is_fragment, fragment_offset, Some(ip_id))
        } else {
            (None, None, None, None, None, false, 0, None)
        };
        
        // RFC 791 Compliance: Check fragment tracking
        // According to RFC 791, fragments can arrive out of order, but for security,
        // a firewall should only accept fragments if the first fragment (offset=0) has been accepted.
        // This prevents fragment-based attacks where malicious fragments are sent without the first fragment.
        if is_fragment {
            if let Some(first_seen) = self.check_fragment_tracking(src_ip, dst_ip, ip_id, protocol, fragment_offset) {
                if !first_seen {
                    // Fragment received but first fragment (offset=0) not seen - drop it
                    // This is RFC 791 compliant: we require the first fragment to establish the fragment chain
                    return Ok(MatchResult::Drop);
                }
            }
        }
        
        // EARLY CONNECTION TRACKING: Check if packet belongs to established connection
        // This allows fast-path acceptance before checking rules
        // Skip connection tracking for UDP one-way rules (they need rule matching to detect reverse)
        let skip_connection_tracking = if protocol == Some(PROTOCOL_UDP) {
            // For UDP, check if any rule has one_way=true - if so, skip early tracking
            // to allow rule matching to detect reverse packets
            self.rules.iter().any(|rule| {
                if let Layer4Match::Match { protocol: rule_protocol, one_way, .. } = &rule.l4_match {
                    *rule_protocol == PROTOCOL_UDP && *one_way
                } else {
                    false
                }
            })
        } else {
            false
        };
        
        if !skip_connection_tracking {
            if let Some(result) = self.check_connection_tracking(src_ip, dst_ip, protocol, src_port, dst_port, packet) {
                return Ok(result);
            }
        }
        
        // Match against rules in order
        for rule in &self.rules {
            if self.matches_rule(rule, src_mac, dst_mac, ethertype, vlan_id, src_ip, dst_ip, protocol, src_port, dst_port, is_fragment) {
                let result = match rule.action {
                    Action::Accept => {
                        // Track UDP connections after acceptance (but not one-way)
                        if protocol == Some(PROTOCOL_UDP) {
                            if let Layer4Match::Match { one_way, .. } = &rule.l4_match {
                                if !one_way {
                                    // Only track non-one-way UDP connections
                                    self.track_udp_connection(src_ip, dst_ip, src_port, dst_port);
                                }
                            } else {
                                // Layer4Match::Any - track it
                                self.track_udp_connection(src_ip, dst_ip, src_port, dst_port);
                            }
                        }
                        MatchResult::Accept
                    }
                    Action::Drop => MatchResult::Drop,
                    Action::Reject => MatchResult::Reject,
                };
                return Ok(result);
            }
        }
        
        // DEFAULT DENY ALL: If no rule matches, deny the packet
        Ok(MatchResult::Drop)
    }
    
    fn matches_rule(
        &self,
        rule: &FirewallRule,
        src_mac: &[u8],
        dst_mac: &[u8],
        ethertype: u16,
        vlan_id: Option<u16>,
        src_ip: Option<[u8; 4]>,
        dst_ip: Option<[u8; 4]>,
        protocol: Option<u8>,
        src_port: Option<u16>,
        dst_port: Option<u16>,
        is_fragment: bool,
    ) -> bool {
        // Match L2
        match &rule.l2_match {
            Layer2Match::Any => {}
            Layer2Match::Match { src_mac: rule_src, dst_mac: rule_dst, ethertype: rule_ethertype, vlan_id: rule_vlan } => {
                if let Some(rule_src) = rule_src {
                    if src_mac != rule_src.as_slice() {
                        return false;
                    }
                }
                if let Some(rule_dst) = rule_dst {
                    if dst_mac != rule_dst.as_slice() {
                        return false;
                    }
                }
                if let Some(rule_ethertype) = rule_ethertype {
                    if ethertype != *rule_ethertype {
                        return false;
                    }
                }
                if let Some(rule_vlan) = rule_vlan {
                    // Rule requires a specific VLAN ID
                    match vlan_id {
                        Some(packet_vlan) => {
                            // Packet has VLAN tag - must match
                            if packet_vlan != *rule_vlan {
                                return false;
                            }
                        }
                        None => {
                            // Packet has no VLAN tag but rule requires one - no match
                            return false;
                        }
                    }
                } else {
                    // Rule doesn't specify VLAN - matches packets with or without VLAN tags
                    // (no additional check needed)
                }
            }
        }
        
        // Match L3
        match &rule.l3_match {
            Layer3Match::Any => {}
            Layer3Match::Match { src_ip: rule_src_ip, dst_ip: rule_dst_ip, protocol: rule_protocol } => {
                if let Some(rule_src_ip) = rule_src_ip {
                    if let Some(src_ip) = src_ip {
                        if !rule_src_ip.matches(src_ip) {
                            return false;
                        }
                    } else {
                        return false;
                    }
                }
                if let Some(rule_dst_ip) = rule_dst_ip {
                    if let Some(dst_ip) = dst_ip {
                        if !rule_dst_ip.matches(dst_ip) {
                            return false;
                        }
                    } else {
                        return false;
                    }
                }
                if let Some(rule_protocol) = rule_protocol {
                    if protocol != Some(*rule_protocol) {
                        return false;
                    }
                }
            }
        }
        
        // Match L4
        match &rule.l4_match {
            Layer4Match::Any => {}
            Layer4Match::Match { protocol: rule_protocol, src_port: rule_src_port, dst_port: rule_dst_port, one_way } => {
                if protocol != Some(*rule_protocol) {
                    return false;
                }
                // For IP fragments (offset > 0), skip port matching as ports are only in first fragment
                if !is_fragment {
                    if let Some(rule_src_port) = rule_src_port {
                        if src_port != Some(*rule_src_port) {
                            return false;
                        }
                    }
                    if let Some(rule_dst_port) = rule_dst_port {
                        if dst_port != Some(*rule_dst_port) {
                            return false;
                        }
                    }
                }
                
                // Check for one-way UDP: block reverse direction packets
                // Skip this check for fragments as they don't have ports
                if *one_way && *rule_protocol == PROTOCOL_UDP && !is_fragment {
                    // For one-way UDP, we need to detect reverse/reply packets
                    // A reverse packet has src/dst IPs and ports swapped compared to the rule
                    if let (Some(pkt_src_ip), Some(pkt_dst_ip), Some(pkt_src_port), Some(pkt_dst_port)) = (src_ip, dst_ip, src_port, dst_port) {
                        let is_reverse = match &rule.l3_match {
                            Layer3Match::Match { src_ip: rule_src_ip, dst_ip: rule_dst_ip, .. } => {
                                // Check if packet's src matches rule's dst and packet's dst matches rule's src
                                let src_matches_rule_dst = rule_dst_ip.as_ref()
                                    .map(|rule_dst| rule_dst.matches(pkt_src_ip))
                                    .unwrap_or(true); // If rule doesn't specify dst, any src is considered reverse
                                let dst_matches_rule_src = rule_src_ip.as_ref()
                                    .map(|rule_src| rule_src.matches(pkt_dst_ip))
                                    .unwrap_or(true); // If rule doesn't specify src, any dst is considered reverse
                                
                                // Check ports: packet src_port should match rule dst_port, packet dst_port should match rule src_port
                                let src_port_matches_rule_dst = rule_dst_port.map(|rule_dst| pkt_src_port == rule_dst).unwrap_or(true);
                                let dst_port_matches_rule_src = rule_src_port.map(|rule_src| pkt_dst_port == rule_src).unwrap_or(true);
                                
                                // If IPs and ports are swapped, this is a reverse packet
                                src_matches_rule_dst && dst_matches_rule_src && 
                                src_port_matches_rule_dst && dst_port_matches_rule_src
                            }
                            _ => false, // If no L3 match, can't determine reverse
                        };
                        
                        if is_reverse {
                            // Block reverse direction packet
                            return false;
                        }
                    }
                }
            }
        }
        
        true
    }
}

impl<const N: usize, const C: usize, const F: usize> Default for Firewall<N, C, F> {
    fn default() -> Self {
        Self::new()
    }
}
