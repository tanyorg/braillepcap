// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Fuminori -Tany- Tanizaki

use std::{net::Ipv4Addr, str::FromStr};

/// Pre-computed CIDR matcher for high-performance bitwise IP filtering
#[derive(Debug, Clone, Copy)]
pub struct CidrMatcher {
    pub network: u32,
    pub mask: u32,
}

impl CidrMatcher {
    /// Creates a new CidrMatcher with pre-computed network address and mask
    pub fn new(network: u32, prefix: u32) -> Self {
        let mask = if prefix == 0 {
            0
        } else {
            !0u32 << (32 - prefix)
        };
        Self {
            network: network & mask,
            mask,
        }
    }

    /// Evaluates whether the given IPv4 address matches this CIDR prefix
    #[inline(always)]
    pub fn matches(&self, ip: u32) -> bool {
        (ip & self.mask) == self.network
    }
}

/// Expands tilde (~) in file paths to the user's home directory
pub fn expand_path(path: &str) -> String {
    if path.starts_with("~/") {
        if let Ok(home) = std::env::var("HOME") {
            return format!("{}{}", home, &path[1..]);
        }
    }
    path.to_string()
}

/// Parses a CIDR string (e.g., "192.168.1.0/24") into a pre-computed CidrMatcher
pub fn parse_cidr(cidr: &str) -> Option<CidrMatcher> {
    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 {
        return None;
    }
    let ip = Ipv4Addr::from_str(parts[0]).ok()?;
    let prefix: u32 = parts[1].parse().ok()?;
    if prefix > 32 {
        return None;
    }

    Some(CidrMatcher::new(u32::from(ip), prefix))
}

/// Fast-path check using short-circuit evaluation to filter excluded source IP networks
#[inline(always)]
fn should_exclude(src_ip: u32, omit_nets: &[CidrMatcher]) -> bool {
    if omit_nets.is_empty() {
        return false;
    }
    omit_nets.iter().any(|m| m.matches(src_ip))
}

/// Common IPv4 and L4 payload validation, filtering, and octet extraction logic
pub fn process_ip_payload(
    ip_data: &[u8],
    target_ports: &[u16],
    omit_nets: &[CidrMatcher],
) -> Option<(u8, u8)> {
    if ip_data.len() < 20 {
        return None;
    }

    // Verify IPv4 version
    if (ip_data[0] >> 4) != 4 {
        return None;
    }

    // Validate Internet Header Length (IHL) >= 20 bytes
    let ihl = ((ip_data[0] & 0x0F) * 4) as usize;
    if ihl < 20 || ip_data.len() < ihl {
        return None;
    }

    let src_ip_u32 = u32::from_be_bytes([ip_data[12], ip_data[13], ip_data[14], ip_data[15]]);

    // Fast-path CIDR exclusion check for source IP
    if should_exclude(src_ip_u32, omit_nets) {
        return None;
    }

    let src_oct1 = ip_data[12];
    let src_oct2 = ip_data[13];

    // Exclude Class D (Multicast: 224-239) and Class E (Reserved: 240-255)
    if src_oct1 >= 224 {
        return None;
    }

    // Filter by target port numbers
    if !target_ports.is_empty() {
        let proto = ip_data[9];
        if proto != 6 && proto != 17 {
            return None;
        }
        if ip_data.len() < ihl + 4 {
            return None;
        }
        let l4_data = &ip_data[ihl..];
        let src_port = u16::from_be_bytes([l4_data[0], l4_data[1]]);
        let dst_port = u16::from_be_bytes([l4_data[2], l4_data[3]]);

        if !target_ports.contains(&src_port) && !target_ports.contains(&dst_port) {
            return None;
        }
    }

    Some((src_oct1, src_oct2))
}
