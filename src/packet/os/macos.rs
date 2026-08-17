use pcap::Linktype;

// Resolve macOS-specific data link layer offsets (PKTAP, BSD Loopback, etc.)
pub fn get_l2_offset_macos(linktype: Linktype, data: &[u8]) -> Option<usize> {
    match linktype.0 {
        0 => Some(4), // DLT_NULL / BSD Loopback (macOS lo0)
        149 => {
            // DLT_APPLE_PKTAP (macOS header)
            if data.len() < 8 {
                return None;
            }
            let pktap_len = u32::from_le_bytes([data[4], data[5], data[6], data[7]]) as usize;
            Some(pktap_len + 14)
        }
        _ => None,
    }
}
