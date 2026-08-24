use pcap::Linktype;

// Resolve Linux-specific data link layer offsets (SLL / SLL2 Cooked Capture)
pub fn get_l2_offset_linux(linktype: Linktype, data: &[u8]) -> Option<usize> {
    match linktype.0 {
        113 if data.len() >= 16 && data[14..16] == [0x08, 0x00] => Some(16),
        276 if data.len() >= 20 && data[0..2] == [0x08, 0x00] => Some(20),
        _ => None,
    }
}
