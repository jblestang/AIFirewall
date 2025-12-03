use crate::stack::VirtualStack;
use crate::firewall::{MatchResult, FirewallError};
use heapless::Vec;

pub struct PacketInjector<const N: usize = 32, const C: usize = 1024, const F: usize = 512> {
    stack: VirtualStack<N, C, F>,
}

impl<const N: usize, const C: usize, const F: usize> PacketInjector<N, C, F> {
    pub fn new(stack: VirtualStack<N, C, F>) -> Self {
        Self { stack }
    }
    
    #[allow(dead_code)] // Public API method, may be used by external code
    pub fn get_stack(&mut self) -> &mut VirtualStack<N, C, F> {
        &mut self.stack
    }
    
    /// Inject a raw Ethernet packet
    pub fn inject_raw(&mut self, packet: Vec<u8, 1500>) -> Result<MatchResult, FirewallError> {
        self.stack.inject_packet(packet)
    }
    
    /// Create and inject an IPv4 TCP packet
    pub fn inject_tcp(
        &mut self,
        src_mac: [u8; 6],
        dst_mac: [u8; 6],
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        src_port: u16,
        dst_port: u16,
        payload: &[u8],
    ) -> Result<MatchResult, FirewallError> {
        let mut packet = Vec::<u8, 1500>::new();
        
        // Ethernet header
        packet.extend_from_slice(&dst_mac).map_err(|_| FirewallError::InvalidPacket)?;
        packet.extend_from_slice(&src_mac).map_err(|_| FirewallError::InvalidPacket)?;
        packet.extend_from_slice(&0x0800u16.to_be_bytes()).map_err(|_| FirewallError::InvalidPacket)?; // IPv4 ethertype
        
        // IP header (20 bytes, no options)
        let total_len = 20 + 20 + payload.len() as u16; // IP + TCP + payload
        packet.push(0x45).map_err(|_| FirewallError::InvalidPacket)?; // Version 4, IHL 5
        packet.push(0x00).map_err(|_| FirewallError::InvalidPacket)?; // TOS
        packet.extend_from_slice(&total_len.to_be_bytes()).map_err(|_| FirewallError::InvalidPacket)?;
        packet.extend_from_slice(&0u16.to_be_bytes()).map_err(|_| FirewallError::InvalidPacket)?; // ID
        packet.extend_from_slice(&0x4000u16.to_be_bytes()).map_err(|_| FirewallError::InvalidPacket)?; // Flags + Fragment offset
        packet.push(64).map_err(|_| FirewallError::InvalidPacket)?; // TTL
        packet.push(6).map_err(|_| FirewallError::InvalidPacket)?; // Protocol TCP
        packet.extend_from_slice(&0u16.to_be_bytes()).map_err(|_| FirewallError::InvalidPacket)?; // Checksum (placeholder)
        packet.extend_from_slice(&src_ip).map_err(|_| FirewallError::InvalidPacket)?;
        packet.extend_from_slice(&dst_ip).map_err(|_| FirewallError::InvalidPacket)?;
        
        // TCP header (20 bytes, no options)
        packet.extend_from_slice(&src_port.to_be_bytes()).map_err(|_| FirewallError::InvalidPacket)?;
        packet.extend_from_slice(&dst_port.to_be_bytes()).map_err(|_| FirewallError::InvalidPacket)?;
        packet.extend_from_slice(&0u32.to_be_bytes()).map_err(|_| FirewallError::InvalidPacket)?; // Seq
        packet.extend_from_slice(&0u32.to_be_bytes()).map_err(|_| FirewallError::InvalidPacket)?; // Ack
        packet.push(0x50).map_err(|_| FirewallError::InvalidPacket)?; // Data offset
        packet.push(0x00).map_err(|_| FirewallError::InvalidPacket)?; // Flags
        packet.extend_from_slice(&0x4000u16.to_be_bytes()).map_err(|_| FirewallError::InvalidPacket)?; // Window
        packet.extend_from_slice(&0u16.to_be_bytes()).map_err(|_| FirewallError::InvalidPacket)?; // Checksum (placeholder)
        packet.extend_from_slice(&0u16.to_be_bytes()).map_err(|_| FirewallError::InvalidPacket)?; // Urgent pointer
        
        // Payload
        packet.extend_from_slice(payload).map_err(|_| FirewallError::InvalidPacket)?;
        
        // Update IP total length and checksum
        let ip_total_len = packet.len() - 14;
        let ip_total_len_bytes = (ip_total_len as u16).to_be_bytes();
        packet[16] = ip_total_len_bytes[0];
        packet[17] = ip_total_len_bytes[1];
        
        // Simple IP checksum (for testing)
        if packet.len() >= 34 {
            let ip_checksum = calculate_ip_checksum(&packet[14..34]);
            let ip_checksum_bytes = ip_checksum.to_be_bytes();
            packet[24] = ip_checksum_bytes[0];
            packet[25] = ip_checksum_bytes[1];
        }
        
        self.stack.inject_packet(packet)
    }
    
    /// Create and inject an IPv4 UDP packet
    pub fn inject_udp(
        &mut self,
        src_mac: [u8; 6],
        dst_mac: [u8; 6],
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        src_port: u16,
        dst_port: u16,
        payload: &[u8],
    ) -> Result<MatchResult, FirewallError> {
        let mut packet = Vec::<u8, 1500>::new();
        
        // Ethernet header
        packet.extend_from_slice(&dst_mac).map_err(|_| FirewallError::InvalidPacket)?;
        packet.extend_from_slice(&src_mac).map_err(|_| FirewallError::InvalidPacket)?;
        packet.extend_from_slice(&0x0800u16.to_be_bytes()).map_err(|_| FirewallError::InvalidPacket)?; // IPv4 ethertype
        
        // IP header (20 bytes)
        let total_len = 20 + 8 + payload.len() as u16; // IP + UDP + payload
        packet.push(0x45).map_err(|_| FirewallError::InvalidPacket)?; // Version 4, IHL 5
        packet.push(0x00).map_err(|_| FirewallError::InvalidPacket)?; // TOS
        packet.extend_from_slice(&total_len.to_be_bytes()).map_err(|_| FirewallError::InvalidPacket)?;
        packet.extend_from_slice(&0u16.to_be_bytes()).map_err(|_| FirewallError::InvalidPacket)?; // ID
        packet.extend_from_slice(&0x4000u16.to_be_bytes()).map_err(|_| FirewallError::InvalidPacket)?; // Flags + Fragment offset
        packet.push(64).map_err(|_| FirewallError::InvalidPacket)?; // TTL
        packet.push(17).map_err(|_| FirewallError::InvalidPacket)?; // Protocol UDP
        packet.extend_from_slice(&0u16.to_be_bytes()).map_err(|_| FirewallError::InvalidPacket)?; // Checksum (placeholder)
        packet.extend_from_slice(&src_ip).map_err(|_| FirewallError::InvalidPacket)?;
        packet.extend_from_slice(&dst_ip).map_err(|_| FirewallError::InvalidPacket)?;
        
        // UDP header (8 bytes)
        packet.extend_from_slice(&src_port.to_be_bytes()).map_err(|_| FirewallError::InvalidPacket)?;
        packet.extend_from_slice(&dst_port.to_be_bytes()).map_err(|_| FirewallError::InvalidPacket)?;
        let udp_len = 8 + payload.len() as u16;
        packet.extend_from_slice(&udp_len.to_be_bytes()).map_err(|_| FirewallError::InvalidPacket)?;
        packet.extend_from_slice(&0u16.to_be_bytes()).map_err(|_| FirewallError::InvalidPacket)?; // Checksum (placeholder)
        
        // Payload
        packet.extend_from_slice(payload).map_err(|_| FirewallError::InvalidPacket)?;
        
        // Update IP total length
        let ip_total_len = packet.len() - 14;
        let ip_total_len_bytes = (ip_total_len as u16).to_be_bytes();
        packet[16] = ip_total_len_bytes[0];
        packet[17] = ip_total_len_bytes[1];
        
        // Simple IP checksum
        if packet.len() >= 34 {
            let ip_checksum = calculate_ip_checksum(&packet[14..34]);
            let ip_checksum_bytes = ip_checksum.to_be_bytes();
            packet[24] = ip_checksum_bytes[0];
            packet[25] = ip_checksum_bytes[1];
        }
        
        self.stack.inject_packet(packet)
    }
    
    /// Create and inject an IPv4 ICMP packet
    pub fn inject_icmp(
        &mut self,
        src_mac: [u8; 6],
        dst_mac: [u8; 6],
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        icmp_type: u8,
        icmp_code: u8,
        payload: &[u8],
    ) -> Result<MatchResult, FirewallError> {
        let mut packet = Vec::<u8, 1500>::new();
        
        // Ethernet header
        packet.extend_from_slice(&dst_mac).map_err(|_| FirewallError::InvalidPacket)?;
        packet.extend_from_slice(&src_mac).map_err(|_| FirewallError::InvalidPacket)?;
        packet.extend_from_slice(&0x0800u16.to_be_bytes()).map_err(|_| FirewallError::InvalidPacket)?; // IPv4 ethertype
        
        // IP header (20 bytes)
        let total_len = 20 + 8 + payload.len() as u16; // IP + ICMP header + payload
        packet.push(0x45).map_err(|_| FirewallError::InvalidPacket)?; // Version 4, IHL 5
        packet.push(0x00).map_err(|_| FirewallError::InvalidPacket)?; // TOS
        packet.extend_from_slice(&total_len.to_be_bytes()).map_err(|_| FirewallError::InvalidPacket)?;
        packet.extend_from_slice(&0u16.to_be_bytes()).map_err(|_| FirewallError::InvalidPacket)?; // ID
        packet.extend_from_slice(&0x4000u16.to_be_bytes()).map_err(|_| FirewallError::InvalidPacket)?; // Flags + Fragment offset
        packet.push(64).map_err(|_| FirewallError::InvalidPacket)?; // TTL
        packet.push(1).map_err(|_| FirewallError::InvalidPacket)?; // Protocol ICMP
        packet.extend_from_slice(&0u16.to_be_bytes()).map_err(|_| FirewallError::InvalidPacket)?; // Checksum (placeholder)
        packet.extend_from_slice(&src_ip).map_err(|_| FirewallError::InvalidPacket)?;
        packet.extend_from_slice(&dst_ip).map_err(|_| FirewallError::InvalidPacket)?;
        
        // ICMP header
        packet.push(icmp_type).map_err(|_| FirewallError::InvalidPacket)?;
        packet.push(icmp_code).map_err(|_| FirewallError::InvalidPacket)?;
        packet.extend_from_slice(&0u16.to_be_bytes()).map_err(|_| FirewallError::InvalidPacket)?; // Checksum (placeholder)
        packet.extend_from_slice(&0u32.to_be_bytes()).map_err(|_| FirewallError::InvalidPacket)?; // Rest of ICMP header
        
        // Payload
        packet.extend_from_slice(payload).map_err(|_| FirewallError::InvalidPacket)?;
        
        // Update IP total length
        let ip_total_len = packet.len() - 14;
        let ip_total_len_bytes = (ip_total_len as u16).to_be_bytes();
        packet[16] = ip_total_len_bytes[0];
        packet[17] = ip_total_len_bytes[1];
        
        // Simple IP checksum
        if packet.len() >= 34 {
            let ip_checksum = calculate_ip_checksum(&packet[14..34]);
            let ip_checksum_bytes = ip_checksum.to_be_bytes();
            packet[24] = ip_checksum_bytes[0];
            packet[25] = ip_checksum_bytes[1];
        }
        
        self.stack.inject_packet(packet)
    }
    
    /// Receive a packet that passed the firewall
    pub fn receive(&mut self) -> Option<heapless::Vec<u8, 1500>> {
        self.stack.receive_packet()
    }
}

fn calculate_ip_checksum(header: &[u8]) -> u16 {
    let mut sum = 0u32;
    for chunk in header.chunks(2) {
        if chunk.len() == 2 {
            let word = u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
            sum += word;
        }
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !sum as u16
}
