use clap::Parser;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    /// Network interface for live capture (default: "en0")
    #[arg(short, long, conflicts_with = "read_file")]
    pub interface: Option<String>,

    /// Read PCAP file or '-' for stdin
    #[arg(short, long, conflicts_with = "interface")]
    pub read_file: Option<String>,

    /// Replay speed for PCAP file (0 = max speed / burst mode)
    #[arg(short, long, default_value_t = 1.0)]
    pub speed: f64,

    /// Dot persistence duration in seconds
    #[arg(short = 't', long, default_value_t = 0.5)]
    pub hold_time: f64,

    /// Filter by port numbers (e.g., -p 80 443)
    #[arg(short, long, value_delimiter = ' ')]
    pub port: Vec<u16>,

    /// Exclude IP networks in CIDR notation (e.g., -o 10.0.0.0/8 192.168.0.0/16)
    #[arg(short, long, value_delimiter = ' ')]
    pub omit: Vec<String>,
}
