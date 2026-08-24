#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "macos")]
pub mod macos;

use pcap::Linktype;

// Resolve supported link-layer offsets and reject formats that cannot be decoded safely.
pub fn calculate_l2_offset(linktype: Linktype, data: &[u8]) -> Option<usize> {
    #[cfg(target_os = "macos")]
    if let Some(offset) = macos::get_l2_offset_macos(linktype, data) {
        return Some(offset);
    }

    #[cfg(target_os = "linux")]
    if let Some(offset) = linux::get_l2_offset_linux(linktype, data) {
        return Some(offset);
    }

    let offset = match linktype.0 {
        1 => {
            if data.len() < 14 {
                return None;
            }
            let ether_type = u16::from_be_bytes([data[12], data[13]]);
            if ether_type == 0x0800 {
                14
            } else if ether_type == 0x8100 && data.len() >= 18 {
                if u16::from_be_bytes([data[16], data[17]]) != 0x0800 {
                    return None;
                }
                18
            } else {
                return None;
            }
        } // DLT_EN10MB / Standard Ethernet
        12 => 0, // DLT_RAW
        _ => return None,
    };

    Some(offset)
}
