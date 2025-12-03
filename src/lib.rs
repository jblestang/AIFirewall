#![no_std]

#[cfg(feature = "std")]
extern crate std;

extern crate alloc;

pub mod firewall;
pub mod parser;
pub mod stack;
pub mod packet_injector;
#[cfg(any(test, feature = "proofs"))]
pub mod proofs;

pub use firewall::{Firewall, FirewallRule, Action, MatchResult, FirewallError};
pub use parser::parse_firewall_rules;
pub use stack::VirtualStack;
pub use packet_injector::PacketInjector;
