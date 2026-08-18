pub mod capture;
pub mod os;
pub mod parser;

pub use capture::{parse_packet, CapEngine};
pub use parser::{expand_path, parse_cidr};

pub struct BatchUpdate {
    pub dots: Vec<(u8, u8)>,
    pub count: usize,
    pub pps_stat: Option<usize>,
    pub last_pcap_sec: Option<i64>,
}
