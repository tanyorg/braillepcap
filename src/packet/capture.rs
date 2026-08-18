// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Fuminori -Tany- Tanizaki

use pcap::{Capture, Linktype};
use super::os::calculate_l2_offset;
use super::parser::{process_ip_payload, CidrMatcher};

pub enum CapEngine {
    File(Capture<pcap::Offline>),
    Live(Capture<pcap::Active>),
}

/// Strip L2 header and pass remaining payload to the packet parser
pub fn parse_packet(
    data: &[u8],
    linktype: Linktype,
    target_ports: &[u16],
    omit_nets: &[CidrMatcher],
) -> Option<(u8, u8)> {
    let l2_offset = calculate_l2_offset(linktype, data)?;

    if data.len() < l2_offset + 20 {
        return None;
    }

    let ip_data = &data[l2_offset..];
    process_ip_payload(ip_data, target_ports, omit_nets)
}
