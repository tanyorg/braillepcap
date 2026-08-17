use std::{net::Ipv4Addr, str::FromStr};

// Expand tilde in path to full home directory path
pub fn expand_path(path: &str) -> String {
    if path.starts_with("~/") {
        if let Ok(home) = std::env::var("HOME") {
            return format!("{}{}", home, &path[1..]);
        }
    }
    path.to_string()
}

// Parse CIDR string into (network_address_u32, subnet_mask_u32)
pub fn parse_cidr(cidr: &str) -> Option<(u32, u32)> {
    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 {
        return None;
    }
    let ip = Ipv4Addr::from_str(parts[0]).ok()?;
    let prefix: u32 = parts[1].parse().ok()?;
    if prefix > 32 {
        return None;
    }

    let mask = if prefix == 0 {
        0
    } else {
        !0u32 << (32 - prefix)
    };
    let net = u32::from(ip) & mask;
    Some((net, mask))
}

// Common IPv4 and L4 payload validation and filtering logic
pub fn process_ip_payload(
    ip_data: &[u8],
    target_ports: &[u16],
    omit_nets: &[(u32, u32)],
) -> Option<(u8, u8)> {
    // Verify IPv4 version
    if (ip_data[0] >> 4) != 4 {
        return None;
    }

    // Validate Internet Header Length (IHL) >= 20 bytes
    let ihl = ((ip_data[0] & 0x0F) * 4) as usize;
    if ihl < 20 || ip_data.len() < ihl {
        return None;
    }

    let proto = ip_data[9];
    let src_oct1 = ip_data[12];
    let src_oct2 = ip_data[13];

    // Exclude Multicast and Class E
    if src_oct1 >= 224 {
        return None;
    }

    // Filter omitted IPv4 subnets
    if !omit_nets.is_empty() {
        let src_ip_u32 = u32::from_be_bytes([ip_data[12], ip_data[13], ip_data[14], ip_data[15]]);
        for &(net, mask) in omit_nets {
            if (src_ip_u32 & mask) == net {
                return None;
            }
        }
    }

    // Filter by target port numbers
    if !target_ports.is_empty() {
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
