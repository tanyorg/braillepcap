// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Fuminori -Tany- Tanizaki

use std::{
    net::Ipv4Addr,
    path::{Component, PathBuf},
    str::FromStr,
};

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

/// Expands tilde (~) in file paths to the user's home directory without allowing traversal.
pub fn expand_path(path: &str) -> Result<PathBuf, String> {
    if path == "-" {
        return Ok(PathBuf::from("-"));
    }

    let home = std::env::var("HOME").map_err(|_| "HOME is not set")?;
    let expanded = if let Some(rest) = path.strip_prefix("~/") {
        PathBuf::from(&home).join(rest)
    } else {
        PathBuf::from(path)
    };

    if expanded.components().any(|c| matches!(c, Component::ParentDir)) {
        return Err(format!("Path traversal is not allowed: {}", path));
    }

    if expanded.is_absolute() {
        let canonical = expanded.canonicalize().unwrap_or_else(|_| expanded.clone());
        let home_path = PathBuf::from(&home);
        if !canonical.starts_with(&home_path) {
            return Err(format!("Path escapes HOME: {}", path));
        }
        return Ok(canonical);
    }

    Ok(expanded)
}

/// Parses a CIDR string (e.g., "192.168.1.0/24") into a pre-computed CidrMatcher.
/// Invalid IPv4 values and reserved class D/E ranges are rejected with an error.
pub fn parse_cidr(cidr: &str) -> Result<CidrMatcher, String> {
    let (ip_str, prefix_str) = cidr.split_once('/').ok_or_else(|| format!("Invalid CIDR: {}", cidr))?;
    if ip_str.is_empty() || prefix_str.is_empty() {
        return Err(format!("Invalid CIDR: {}", cidr));
    }

    let ip = Ipv4Addr::from_str(ip_str)
        .map_err(|_| format!("Invalid IPv4 address in CIDR: {}", cidr))?;
    let prefix: u32 = prefix_str
        .parse()
        .map_err(|_| format!("Invalid prefix in CIDR: {}", cidr))?;
    if prefix > 32 {
        return Err(format!("CIDR prefix out of range: {}", cidr));
    }

    let first_octet = ip.octets()[0];
    if first_octet == 0 {
        return Err(format!("CIDR range {} is reserved: 0.0.0.0/8 is not allowed", cidr));
    }
    if matches!(first_octet, 224..=239) || matches!(first_octet, 240..=255) {
        return Err(format!("CIDR range {} is reserved: class D/E are not allowed", cidr));
    }

    Ok(CidrMatcher::new(u32::from(ip), prefix))
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
) -> Option<(u8, u8, u8)> {
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
    let src_oct3 = ip_data[14];

    // Exclude Class D (Multicast: 224-239) and Class E (Reserved: 240-255)
    if src_oct1 >= 224 {
        return None;
    }

    // Filter by target destination port numbers.
    // Counting either src_port or dst_port double-counts duplex traffic and makes the
    // "inbound-only" counter drift upward when responses are visible on the same interface.
    if !target_ports.is_empty() {
        let proto = ip_data[9];
        if proto != 6 && proto != 17 {
            return None;
        }
        if ip_data.len() < ihl + 4 {
            return None;
        }
        let l4_data = &ip_data[ihl..];
        let dst_port = u16::from_be_bytes([l4_data[2], l4_data[3]]);

        if !target_ports.contains(&dst_port) {
            return None;
        }
    }

    Some((src_oct1, src_oct2, src_oct3))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_ipv4_packet(src_ip: [u8; 4], dst_ip: [u8; 4], src_port: u16, dst_port: u16, proto: u8) -> Vec<u8> {
        let mut pkt = vec![0u8; 40];
        pkt[0] = 0x45; // Version 4, IHL 5
        pkt[8] = 0x00;
        pkt[9] = proto;
        pkt[12..16].copy_from_slice(&src_ip);
        pkt[16..20].copy_from_slice(&dst_ip);
        pkt[20..22].copy_from_slice(&src_port.to_be_bytes());
        pkt[22..24].copy_from_slice(&dst_port.to_be_bytes());
        pkt
    }

    #[test]
    fn inbound_port_filter_uses_destination_port_only() {
        let packet_to_target = make_ipv4_packet([192, 168, 1, 10], [10, 0, 0, 5], 54321, 443, 6);
        assert!(process_ip_payload(&packet_to_target, &[443], &[]).is_some());

        let response_from_target = make_ipv4_packet([10, 0, 0, 5], [192, 168, 1, 10], 443, 54321, 6);
        assert!(process_ip_payload(&response_from_target, &[443], &[]).is_none());
    }

    #[test]
    fn inbound_port_filter_rejects_non_tcp_udp_packets() {
        let icmp_packet = make_ipv4_packet([192, 168, 1, 10], [10, 0, 0, 5], 0, 0, 1);
        assert!(process_ip_payload(&icmp_packet, &[443], &[]).is_none());
    }

    #[test]
    fn inbound_port_filter_accepts_matching_destination_port_for_udp() {
        let udp_packet = make_ipv4_packet([192, 168, 1, 10], [10, 0, 0, 5], 55555, 53, 17);
        assert!(process_ip_payload(&udp_packet, &[53], &[]).is_some());
    }

    #[test]
    fn omit_filter_uses_source_ip_only() {
        let omitted_net = Ipv4Addr::new(192, 168, 111, 0);
        let packet = make_ipv4_packet([192, 168, 111, 10], [10, 0, 0, 5], 12345, 443, 6);
        assert!(process_ip_payload(&packet, &[443], &[CidrMatcher::new(u32::from(omitted_net), 24)]).is_none());

        let allowed_packet = make_ipv4_packet([192, 168, 110, 10], [10, 0, 0, 5], 12345, 443, 6);
        assert!(process_ip_payload(&allowed_packet, &[443], &[CidrMatcher::new(u32::from(omitted_net), 24)]).is_some());
    }

    #[test]
    fn rejects_invalid_cidr_prefixes() {
        assert!(parse_cidr("192.168.1.1").is_err());
        assert!(parse_cidr("192.168.1.1/").is_err());
        assert!(parse_cidr("192.168.1.1/33").is_err());
        assert!(parse_cidr("192.168.299.0/24").is_err());
    }

    #[test]
    fn rejects_reserved_class_ranges() {
        assert!(parse_cidr("0.0.0.0/8").is_err());
        assert!(parse_cidr("224.0.0.0/24").is_err());
        assert!(parse_cidr("239.255.255.0/24").is_err());
        assert!(parse_cidr("240.0.0.0/24").is_err());
        assert!(parse_cidr("255.255.255.255/32").is_err());
    }

    #[test]
    fn allows_loopback_and_link_local_ranges() {
        assert!(parse_cidr("127.0.0.0/8").is_ok());
        assert!(parse_cidr("169.254.0.0/16").is_ok());
    }

    #[test]
    fn rejects_path_traversal() {
        let result = expand_path("~/../../etc/passwd");
        assert!(result.is_err());
    }
}
