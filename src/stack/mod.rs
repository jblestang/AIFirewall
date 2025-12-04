use crate::firewall::{Firewall, MatchResult, FirewallError};
use alloc::collections::VecDeque;

pub struct VirtualStack<const N: usize = 32, const C: usize = 1024, const F: usize = 512> {
    firewall: Firewall<N, C, F>,
    rx_buffer: VecDeque<heapless::Vec<u8, 1500>>,
    tx_buffer: VecDeque<heapless::Vec<u8, 1500>>,
}

impl<const N: usize, const C: usize, const F: usize> VirtualStack<N, C, F> {
    pub fn new() -> Self {
        Self {
            firewall: Firewall::new(),
            rx_buffer: VecDeque::new(),
            tx_buffer: VecDeque::new(),
        }
    }
    
    pub fn with_firewall(firewall: Firewall<N, C, F>) -> Self {
        Self {
            firewall,
            rx_buffer: VecDeque::new(),
            tx_buffer: VecDeque::new(),
        }
    }
    
    pub fn set_firewall(&mut self, firewall: Firewall<N, C, F>) {
        self.firewall = firewall;
    }
    
    pub fn get_firewall(&mut self) -> &mut Firewall<N, C, F> {
        &mut self.firewall
    }
    
    pub fn inject_packet(&mut self, packet: heapless::Vec<u8, 1500>) -> Result<MatchResult, FirewallError> {
        // Check firewall rules
        let result = self.firewall.match_packet(&packet)?;
        
        match result {
            MatchResult::Accept => {
                // Packet accepted, add to receive buffer
                self.rx_buffer.push_back(packet);
                Ok(MatchResult::Accept)
            }
            MatchResult::Drop(rule_idx) => {
                // Packet dropped silently
                Ok(MatchResult::Drop(rule_idx))
            }
            MatchResult::Reject(rule_idx) => {
                // Packet rejected (could send ICMP error, but for now just drop)
                Ok(MatchResult::Reject(rule_idx))
            }
            MatchResult::NoMatch => {
                // Default policy: drop if no match
                Ok(MatchResult::Drop(None))
            }
        }
    }
    
    pub fn receive_packet(&mut self) -> Option<heapless::Vec<u8, 1500>> {
        self.rx_buffer.pop_front()
    }
    
    pub fn send_packet(&mut self, packet: heapless::Vec<u8, 1500>) -> Result<MatchResult, FirewallError> {
        // Check firewall rules for outgoing packets
        let result = self.firewall.match_packet(&packet)?;
        
        match result {
            MatchResult::Accept => {
                // Packet accepted, add to transmit buffer
                self.tx_buffer.push_back(packet);
                Ok(MatchResult::Accept)
            }
            MatchResult::Drop(rule_idx) => {
                Ok(MatchResult::Drop(rule_idx))
            }
            MatchResult::Reject(rule_idx) => {
                Ok(MatchResult::Reject(rule_idx))
            }
            MatchResult::NoMatch => {
                // Default policy: accept if no match (for outgoing)
                self.tx_buffer.push_back(packet);
                Ok(MatchResult::Accept)
            }
        }
    }
    
    pub fn get_tx_packet(&mut self) -> Option<heapless::Vec<u8, 1500>> {
        self.tx_buffer.pop_front()
    }
    
    pub fn has_packets(&self) -> bool {
        !self.rx_buffer.is_empty() || !self.tx_buffer.is_empty()
    }
}

impl<const N: usize, const C: usize, const F: usize> Default for VirtualStack<N, C, F> {
    fn default() -> Self {
        Self::new()
    }
}
