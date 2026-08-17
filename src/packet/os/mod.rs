#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "macos")]
pub mod macos;

use pcap::Linktype;

// Resolve OS-specific offset with fallbacks to cross-platform standard link types
pub fn calculate_l2_offset(linktype: Linktype, data: &[u8]) -> Option<usize> {
    #[cfg(target_os = "macos")]
    if let Some(offset) = macos::get_l2_offset_macos(linktype, data) {
        return Some(offset);
    }

    #[cfg(target_os = "linux")]
    if let Some(offset) = linux::get_l2_offset_linux(linktype) {
        return Some(offset);
    }

    // Fallback to cross-platform standards
    let mut offset = match linktype.0 {
        1 => 14,  // DLT_EN10MB / Standard Ethernet
        12 => 0,  // DLT_RAW
        _ => 14,
    };

    // Handle 802.1Q VLAN Tagging (0x8100) on Ethernet
    if linktype.0 == 1 && data.len() >= 18 {
        if data[12] == 0x81 && data[13] == 0x00 {
            offset = 18; // 14 + 4 bytes VLAN header
        }
    }

    Some(offset)
}
