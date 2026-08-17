use pcap::Linktype;

// Resolve Linux-specific data link layer offsets (SLL / SLL2 Cooked Capture)
pub fn get_l2_offset_linux(linktype: Linktype) -> Option<usize> {
    match linktype.0 {
        113 => Some(16), // DLT_LINUX_SLL
        276 => Some(20), // DLT_LINUX_SLL2
        _ => None,
    }
}
