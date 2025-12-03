//! TAP interface implementation for VirtualStack
//! 
//! Creates a virtual network interface (TAP) that appears in the system's
//! network interfaces and processes real Ethernet packets.

#[cfg(feature = "std")]
use std::io;
#[cfg(feature = "std")]
use std::io::Read;
#[cfg(feature = "std")]
use std::time::Duration;
use crate::firewall::{Firewall, MatchResult};
use crate::stack::VirtualStack;
use heapless::Vec;

/// TAP-based VirtualStack that creates a virtual network interface
#[cfg(feature = "std")]
pub struct TapStack<const N: usize = 32, const C: usize = 1024, const F: usize = 512> {
    stack: VirtualStack<N, C, F>,
    #[allow(dead_code)] // Used in create_tap on Linux, stored for potential future use
    tap_name: String,
}

#[cfg(feature = "std")]
impl<const N: usize, const C: usize, const F: usize> TapStack<N, C, F> {
    /// Create a new TapStack with firewall
    pub fn new(firewall: Firewall<N, C, F>, tap_name: Option<&str>) -> io::Result<Self> {
        // Use shorter default name that works on both Linux and macOS
        // Linux TAP names are typically "tap0", "tap1", etc. (max 15 chars)
        // macOS can use longer names but shorter is safer
        let name = tap_name.unwrap_or("tap0");
        Ok(Self {
            stack: VirtualStack::with_firewall(firewall),
            tap_name: name.to_string(),
        })
    }
    
    /// Create and configure the TAP interface
    pub fn create_tap(&mut self) -> io::Result<(tun::platform::Device, String)> {
        // Create TAP interface configuration
        let mut config = tun::Configuration::default();
        
        // Validate and set name - TAP names have restrictions:
        // - Linux: max 15 characters, typically "tap0", "tap1", etc.
        // - macOS: utun interfaces are auto-named (utun0, utun1, etc.)
        // On macOS, utun interfaces are auto-named, so we don't set a name
        // On Linux, we can set a custom name
        #[cfg(target_os = "linux")]
        {
            let name = if self.tap_name.len() > 15 {
                // Truncate to 15 chars for Linux compatibility
                self.tap_name[..15].to_string()
            } else {
                self.tap_name.clone()
            };
            config.name(&name);
        }
        #[cfg(target_os = "macos")]
        {
            // macOS utun interfaces are auto-named - don't set a name
            // The system will create utun0, utun1, etc. automatically
        }
        
        // Set TAP mode (not TUN mode) - TAP works at L2 (Ethernet), TUN at L3 (IP)
        #[cfg(target_os = "linux")]
        {
            config.tap(true); // Explicitly set TAP mode on Linux
        }
        // macOS uses utun which is TUN mode by default, but we'll work with what we get
        
        config.up();
        
        // Create TAP interface - try with name first, then without if it fails
        let (tap, actual_name) = match tun::create(&config) {
            Ok(t) => {
                // Try to get the actual interface name from the device
                #[cfg(target_os = "macos")]
                {
                    // On macOS, the interface name is auto-generated
                    // We need to find which utun interface was just created
                    // Strategy: Get list before and after, or find the highest number
                    use std::process::Command;
                    use std::thread;
                    use std::time::Duration;
                    
                    // Give the system a moment to register the new interface
                    thread::sleep(Duration::from_millis(100));
                    
                    // Get list of all interfaces
                    let output = Command::new("ifconfig")
                        .args(&["-l"])
                        .output();
                    
                    if let Ok(o) = output {
                        if let Ok(output_str) = String::from_utf8(o.stdout) {
                            // Find the highest utun interface number
                            let mut max_utun = -1;
                            for word in output_str.split_whitespace() {
                                if word.starts_with("utun") {
                                    if let Ok(num) = word[4..].parse::<i32>() {
                                        if num > max_utun {
                                            max_utun = num;
                                        }
                                    }
                                }
                            }
                            if max_utun >= 0 {
                                (t, format!("utun{}", max_utun))
                            } else {
                                // Fallback: try to query the device directly or use utun0
                                (t, "utun0".to_string())
                            }
                        } else {
                            (t, "utun0".to_string()) // Fallback
                        }
                    } else {
                        (t, "utun0".to_string()) // Fallback
                    }
                }
                #[cfg(target_os = "linux")]
                {
                    // On Linux, we set the name, so use it
                    (t, name.clone())
                }
            }
            Err(e) => {
                // On Linux, try with a simpler name if the custom name failed
                #[cfg(target_os = "linux")]
                {
                    if name != "tap0" {
                        eprintln!("Warning: Failed to create TAP with name '{}': {}", name, e);
                        eprintln!("Trying with default name 'tap0'...");
                        let mut fallback_config = tun::Configuration::default();
                        fallback_config.name("tap0");
                        fallback_config.tap(true);
                        fallback_config.up();
                        let tap = tun::create(&fallback_config)
                            .map_err(|e2| io::Error::new(io::ErrorKind::Other, 
                                format!("Failed to create TAP (tried '{}' and 'tap0'): {}", name, e2)))?;
                        (tap, "tap0".to_string())
                    } else {
                        return Err(io::Error::new(io::ErrorKind::Other, 
                            format!("Failed to create TAP: {}", e)));
                    }
                }
                // On macOS, this shouldn't happen since we don't set a name
                #[cfg(target_os = "macos")]
                {
                    return Err(io::Error::new(io::ErrorKind::Other, 
                        format!("Failed to create TAP interface: {}", e)));
                }
            }
        };
        
        let ifname = actual_name;
        
        println!("✓ Created TAP interface: {}", ifname);
        
        #[cfg(target_os = "linux")]
        {
            // On Linux, configure the interface
            use std::process::Command;
            
            // Bring up the interface (requires root)
            println!("Bringing up interface {}...", ifname);
            let output = Command::new("ip")
                .args(&["link", "set", &ifname, "up"])
                .output();
            
            match output {
                Ok(o) if o.status.success() => {
                    println!("✓ Interface {} is now up", ifname);
                }
                _ => {
                    println!("⚠ Could not bring up interface (may need root)");
                    println!("  Try: sudo ip link set {} up", ifname);
                }
            }
            
            println!("\nConfigure the interface with:");
            println!("  sudo ip addr add 192.168.100.1/24 dev {}", ifname);
            println!("  sudo ip route add 192.168.100.0/24 dev {}", ifname);
        }
        
        #[cfg(target_os = "macos")]
        {
            use std::process::Command;
            
            println!("\nDetected interface: {}", ifname);
            
            // Check if interface already has an IP configured
            let check_output = Command::new("ifconfig")
                .arg(&ifname)
                .output();
            
            let needs_config = match check_output {
                Ok(o) => {
                    let output_str = String::from_utf8_lossy(&o.stdout);
                    !output_str.contains("inet 192.168.100.1")
                }
                Err(_) => true,
            };
            
            if needs_config {
                println!("Attempting to configure interface {}...", ifname);
                
                // Try to configure the interface automatically
                let configure_output = Command::new("ifconfig")
                    .args(&[&ifname, "192.168.100.1", "192.168.100.2", "up"])
                    .output();
                
                match configure_output {
                    Ok(o) if o.status.success() => {
                        println!("✓ Successfully configured interface {} with IP 192.168.100.1", ifname);
                    }
                    Ok(o) => {
                        let error_msg = String::from_utf8_lossy(&o.stderr);
                        if !error_msg.contains("already") && !error_msg.is_empty() {
                            println!("⚠ Could not auto-configure interface");
                            println!("  Error: {}", error_msg);
                            println!("\nManual configuration:");
                            println!("  sudo ifconfig {} 192.168.100.1 192.168.100.2 up", ifname);
                        } else {
                            println!("✓ Interface {} appears to be already configured", ifname);
                        }
                    }
                    Err(e) => {
                        println!("⚠ Could not auto-configure interface: {}", e);
                        println!("\nManual configuration:");
                        println!("  sudo ifconfig {} 192.168.100.1 192.168.100.2 up", ifname);
                    }
                }
            } else {
                println!("✓ Interface {} is already configured with IP 192.168.100.1", ifname);
            }
            
            println!("\nNote: macOS uses utun (TUN mode) which works at L3 (IP) level.");
            println!("      TUN interfaces are point-to-point and require both local and destination IPs.");
            println!("      For full L2 (Ethernet) support, use Linux with TAP mode.");
        }
        
        Ok((tap, ifname))
    }
    
    /// Run the TAP stack, processing packets continuously
    pub fn run(&mut self) -> io::Result<()> {
        let (tap, ifname) = self.create_tap()?;
        
        println!("\nTAP interface '{}' is ready!", ifname);
        println!("Firewall rules active:");
        println!("  - Allow HTTP (TCP port 80) to 192.168.1.1");
        println!("  - Allow UDP from 10.0.0.0/8");
        println!("  - Block ICMP");
        println!("  - Allow IGMP (multicast)");
        println!("  - Allow MAC aa:bb:cc:dd:ee:ff");
        println!("\nProcessing packets from TAP interface... (Ctrl+C to stop)\n");
        println!("You can test by:");
        println!("  1. Configure the interface: sudo ip addr add 192.168.100.1/24 dev {}", ifname);
        println!("  2. Ping or send traffic to the interface");
        println!();
        
        // Convert TUN device to file descriptor for reading
        #[cfg(unix)]
        use std::os::unix::io::{AsRawFd, FromRawFd};
        
        #[cfg(unix)]
        let fd = tap.as_raw_fd();
        #[cfg(unix)]
        let mut tap_reader = unsafe { std::fs::File::from_raw_fd(fd) };
        
        let mut buf = [0u8; 1522]; // Ethernet frame max size
        
        loop {
            #[cfg(unix)]
            match tap_reader.read(&mut buf) {
                Ok(0) => {
                    // EOF (shouldn't happen with TAP, but handle gracefully)
                }
                Ok(size) if size >= 14 => {
                    // Valid Ethernet frame
                    let timestamp = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs();
                    println!("\n[{}] Received {} bytes from TAP interface", timestamp, size);
                    
                    // Parse Ethernet header for display
                    let dst_mac = &buf[0..6];
                    let src_mac = &buf[6..12];
                    let ethertype = u16::from_be_bytes([buf[12], buf[13]]);
                    println!("  Ethernet: {} -> {} (type: 0x{:04x})",
                        format_mac(src_mac),
                        format_mac(dst_mac),
                        ethertype);
                    
                    // Convert to heapless::Vec for firewall processing
                    let mut packet = Vec::<u8, 1500>::new();
                    if packet.extend_from_slice(&buf[..size.min(1500)]).is_ok() {
                        match self.stack.inject_packet(packet) {
                            Ok(MatchResult::Accept) => {
                                println!("  ✓ Packet ACCEPTED by firewall");
                                // In a real implementation, we'd forward accepted packets
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
                Ok(_) => {
                    // Packet too short (< 14 bytes), ignore
                }
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    // No packet available
                }
                Err(e) => {
                    eprintln!("Error reading from TAP: {}", e);
                }
            }
            
            #[cfg(not(unix))]
            {
                eprintln!("TAP interface is only supported on Unix systems (Linux/macOS)");
                break;
            }
            
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    
    /// Get the underlying stack
    #[allow(dead_code)] // Public API method, may be used by external code
    pub fn get_stack(&mut self) -> &mut VirtualStack<N, C, F> {
        &mut self.stack
    }
}

#[cfg(feature = "std")]
fn format_mac(bytes: &[u8]) -> String {
    if bytes.len() >= 6 {
        format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5])
    } else {
        "??:??:??:??:??:??".to_string()
    }
}
