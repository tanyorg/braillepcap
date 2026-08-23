// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Fuminori -Tany- Tanizaki

pub mod capture;
pub mod os;
pub mod parser;

pub use capture::{spawn_capture_thread, CapEngine};
pub use parser::{expand_path, parse_cidr, CidrMatcher};

pub struct BatchUpdate {
    pub dots: Vec<(u8, u8, u8)>,
    pub count: usize,
    pub pps_stat: Option<usize>,
    pub last_pcap_sec: Option<i64>,
}
