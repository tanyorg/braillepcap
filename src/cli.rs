// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Fuminori -Tany- Tanizaki

use clap::Parser;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    /// Network interface for live capture
    #[arg(short, long)]
    pub interface: Option<String>,

    /// Read PCAP file or '-' for stdin
    #[arg(short, long)]
    pub read_file: Option<String>,

    /// Replay speed for PCAP file (0 = max speed)
    #[arg(short, long, default_value_t = 1.0)]
    pub speed: f64,

    /// Dot persistence duration in seconds
    #[arg(short = 't', long, default_value_t = 0.5)]
    pub hold_time: f64,

    /// Filter by port numbers
    #[arg(short, long, value_delimiter = ' ')]
    pub port: Vec<u16>,

    /// Exclude IP networks in CIDR notation
    #[arg(short, long, value_delimiter = ' ')]
    pub omit: Vec<String>,

    /// Capture buffer size in MB for live capture
    #[arg(short = 'b', long = "buffer-size", default_value_t = 8)]
    pub buffer_size: i32,
}