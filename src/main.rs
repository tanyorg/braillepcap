use clap::Parser;
use crossterm::{
    event::{self, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use pcap::{Capture, Linktype};
use ratatui::{
    backend::CrosstermBackend,
    style::{Color, Modifier, Style},
    text::Span,
    Terminal,
};
use std::{
    collections::HashMap,
    io,
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

const REQ_COLS: u16 = 134;
const REQ_ROWS: u16 = 62;
const GRID_COLS: [usize; 7] = [16, 32, 48, 64, 80, 96, 112];

const BRAILLE_BIT_MAP: [[u16; 2]; 4] = [
    [0x01, 0x08],
    [0x02, 0x10],
    [0x04, 0x20],
    [0x40, 0x80],
];

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    /// Network interface for live capture
    #[arg(short, long, default_value = "en0")]
    pub interface: String,

    /// Read PCAP file or '-' for stdin
    #[arg(short, long)]
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

    /// Exclude IP networks in CIDR (e.g., -o 10.0.0.0/8)
    #[arg(short, long, value_delimiter = ' ')]
    pub omit: Vec<String>,
}

/// Batch update sent from capture thread to UI thread
pub struct BatchUpdate {
    pub dots: Vec<(u8, u8)>,
    pub count: usize,
}

fn get_l2_offset(linktype: Linktype) -> usize {
    match linktype {
        Linktype::ETHERNET => 14,
        Linktype::NULL => 4,
        Linktype::RAW => 0,
        Linktype::LINUX_SLL => 16,
        _ => 14,
    }
}

fn parse_packet(data: &[u8], l2_offset: usize, target_ports: &[u16]) -> Option<(u8, u8)> {
    if data.len() < l2_offset + 20 {
        return None;
    }

    let ip_data = &data[l2_offset..];
    if (ip_data[0] >> 4) != 4 {
        return None;
    }

    let ihl = ((ip_data[0] & 0x0F) * 4) as usize;
    if ip_data.len() < ihl {
        return None;
    }

    let proto = ip_data[9];
    let src_oct1 = ip_data[12];
    let src_oct2 = ip_data[13];

    if src_oct1 >= 224 {
        return None;
    }

    if !target_ports.is_empty() {
        if proto != 6 && proto != 17 {
            return None;
        }
        if ip_data.len() < ihl + 4 {
            return None;
        }
        let l4_data = &ip_data[ihl..];
        let src_port = u16::from_be_bytes([l4_data[0], l4_data[1]]);
        let dst_port = u16::from_be_bytes([l4_data[2], l4_data[3]]);

        if !target_ports.contains(&src_port) && !target_ports.contains(&dst_port) {
            return None;
        }
    }

    Some((src_oct1, src_oct2))
}

pub fn get_iana_rir(octet1: u8) -> &'static str {
    match octet1 {
        0 => "Local",
        10 => "Private",
        127 => "Loopback",
        224..=239 => "Multicast",
        240..=255 => "Reserved",
        1 | 14 | 27 | 36 | 39 | 42 | 43 | 49 | 58..=61 
        | 101 | 103 | 106 | 110..=126 | 133 | 150 | 153 | 163 
        | 171 | 175 | 180 | 182 | 183 | 202 | 203 | 210 | 211 
        | 218..=223 => "APNIC",
        2 | 5 | 25 | 31 | 37 | 46 | 51 | 53 | 57 | 62 
        | 77..=95 | 109 | 141 | 145 | 151 | 176 | 178 | 185 
        | 188 | 193..=195 | 212 | 213 | 217 => "RIPE NCC",
        41 | 102 | 105 | 154 | 196 | 197 => "AFRINIC",
        177 | 179 | 181 | 186 | 187 | 189..=191 | 200 | 201 => "LACNIC",
        _ => "ARIN",
    }
}

fn get_color_and_style(pkt_count: usize) -> Style {
    match pkt_count {
        0..=5 => Style::default().fg(Color::Cyan),
        6..=20 => Style::default().fg(Color::Green),
        21..=100 => Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
        _ => Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let (tx, rx) = mpsc::channel::<BatchUpdate>();

    let iface = args.interface.clone();
    let read_file = args.read_file.clone();
    let ports = args.port.clone();
    let speed = args.speed;

    // High-performance Packet Capture Thread with Batching
    thread::spawn(move || {
        let mut batch = Vec::with_capacity(10000);
        let mut last_flush = Instant::now();
        let flush_interval = Duration::from_millis(16); // Flush ~60 times per sec

        if let Some(file_path) = read_file {
            if let Ok(mut cap) = Capture::from_file(&file_path) {
                let l2_offset = get_l2_offset(cap.get_datalink());
                let mut start_pcap_ts: Option<Duration> = None;
                let start_real_ts = Instant::now();

                while let Ok(packet) = cap.next_packet() {
                    let pkt_ts = Duration::new(
                        packet.header.ts.tv_sec as u64,
                        (packet.header.ts.tv_usec * 1000) as u32,
                    );

                    if speed > 0.0 {
                        if start_pcap_ts.is_none() {
                            start_pcap_ts = Some(pkt_ts);
                        }
                        let pcap_elapsed = (pkt_ts - start_pcap_ts.unwrap()).div_f64(speed);
                        let real_elapsed = start_real_ts.elapsed();

                        if pcap_elapsed > real_elapsed {
                            thread::sleep(pcap_elapsed - real_elapsed);
                        }
                    }

                    if let Some((oct1, oct2)) = parse_packet(packet.data, l2_offset, &ports) {
                        batch.push((oct1, oct2));
                    }

                    if last_flush.elapsed() >= flush_interval {
                        let count = batch.len();
                        if tx.send(BatchUpdate { dots: std::mem::take(&mut batch), count }).is_err() {
                            break;
                        }
                        last_flush = Instant::now();
                    }
                }
                if !batch.is_empty() {
                    let count = batch.len();
                    let _ = tx.send(BatchUpdate { dots: batch, count });
                }
            }
        } else if let Ok(mut cap) = Capture::from_device(iface.as_str())
            .and_then(|c| c.promisc(true).snaplen(65535).timeout(10).open())
        {
            let l2_offset = get_l2_offset(cap.get_datalink());
            while let Ok(packet) = cap.next_packet() {
                if let Some((oct1, oct2)) = parse_packet(packet.data, l2_offset, &ports) {
                    batch.push((oct1, oct2));
                }

                if last_flush.elapsed() >= flush_interval {
                    let count = batch.len();
                    if tx.send(BatchUpdate { dots: std::mem::take(&mut batch), count }).is_err() {
                        break;
                    }
                    last_flush = Instant::now();
                }
            }
        }
    });

    // Terminal Initialization
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let hold_duration = Duration::from_secs_f64(args.hold_time);
    let mut active_dots: HashMap<(u8, u8), Instant> = HashMap::new();
    let mut cell_history: HashMap<(usize, usize), Vec<Instant>> = HashMap::new();
    let mut rir_counter: HashMap<&'static str, usize> = HashMap::new();

    let mut packet_count = 0;
    let mut pps = 0;
    let mut last_stats_calc = Instant::now();

    let mode_label = if let Some(ref f) = args.read_file {
        format!("PCAP: {}", f)
    } else {
        format!("Live: {}", args.interface)
    };

    loop {
        let now = Instant::now();

        if event::poll(Duration::from_millis(1))? {
            if let Event::Key(key) = event::read()? {
                if key.code == KeyCode::Char('q') {
                    break;
                }
            }
        }

        // Receive Batches
        while let Ok(update) = rx.try_recv() {
            packet_count += update.count;

            for (oct1, oct2) in update.dots {
                active_dots.insert((oct1, oct2), now);

                let rir = get_iana_rir(oct1);
                *rir_counter.entry(rir).or_insert(0) += 1;

                let char_y = (oct1 / 4) as usize;
                let char_x = (oct2 / 2) as usize;
                cell_history.entry((char_x, char_y)).or_default().push(now);
            }
        }

        if now.duration_since(last_stats_calc) >= Duration::from_secs(1) {
            pps = packet_count;
            packet_count = 0;
            last_stats_calc = now;
        }

        active_dots.retain(|_, time| now.duration_since(*time) < hold_duration);
        cell_history.retain(|_, timestamps| {
            timestamps.retain(|t| now.duration_since(*t) < hold_duration);
            !timestamps.is_empty()
        });

        terminal.draw(|f| {
            let size = f.size();
            if size.width < REQ_COLS || size.height < REQ_ROWS {
                let msg = Span::raw(format!(
                    "Screen too small: {}x{} (Required: {}x{})",
                    size.width, size.height, REQ_COLS, REQ_ROWS
                ));
                f.render_widget(ratatui::widgets::Paragraph::new(msg), size);
                return;
            }

            let buf = f.buffer_mut();

            let port_ind = if args.port.is_empty() {
                " [Ports: ALL]".to_string()
            } else {
                format!(" [Ports: {:?}]", args.port)
            };
            let title = format!(" IPv4 Traffic Map [{}]{} ", mode_label, port_ind);
            buf.set_string(0, 0, &title, Style::default().add_modifier(Modifier::REVERSED | Modifier::BOLD));

            let header = "     0              32              64              96             128             160             192             224          255";
            buf.set_string(0, 1, header, Style::default().add_modifier(Modifier::DIM));

            let mut top_border = "    +".to_string() + &"-".repeat(128) + "+";
            let mut top_chars: Vec<char> = top_border.chars().collect();
            for pos in [21, 37, 53, 69, 85, 101, 117] {
                top_chars[pos] = '+';
            }
            top_border = top_chars.into_iter().collect();
            buf.set_string(0, 2, &top_border, Style::default());
            buf.set_string(0, 59, &top_border, Style::default());

            for y in 0..56 {
                let scr_y = (y + 3) as u16;
                buf.set_string(0, scr_y, format!("{:>3}|", y * 4), Style::default());
                buf.set_string(133, scr_y, "|", Style::default());

                for cx in GRID_COLS {
                    buf.set_string((cx + 5) as u16, scr_y, "│", Style::default().add_modifier(Modifier::DIM));
                }
            }

            let mut cell_masks: HashMap<(usize, usize), u16> = HashMap::new();
            for &(oct1, oct2) in active_dots.keys() {
                let cy = (oct1 / 4) as usize;
                let cx = (oct2 / 2) as usize;
                let sub_y = (oct1 % 4) as usize;
                let sub_x = (oct2 % 2) as usize;

                let bit_val = BRAILLE_BIT_MAP[sub_y][sub_x];
                *cell_masks.entry((cx, cy)).or_insert(0) |= bit_val;
            }

            for ((cx, cy), mask) in cell_masks {
                let scr_x = (cx + 5) as u16;
                let scr_y = (cy + 3) as u16;

                let braille_char = std::char::from_u32(0x2800 + mask as u32).unwrap_or(' ');
                let pkt_freq = cell_history.get(&(cx, cy)).map_or(0, |v| v.len());
                let style = get_color_and_style(pkt_freq);

                buf.set_string(scr_x, scr_y, braille_char.to_string(), style);
            }

            let total_rir_pkts: usize = rir_counter.values().sum();
            let rir_text = if total_rir_pkts > 0 {
                let mut sorted_rirs: Vec<(&&str, &usize)> = rir_counter.iter().collect();
                sorted_rirs.sort_by(|a, b| b.1.cmp(a.1));
                let breakdown: Vec<String> = sorted_rirs
                    .iter()
                    .take(5)
                    .map(|(name, count)| format!("{}: {:.1}%", name, (**count as f64 / total_rir_pkts as f64) * 100.0))
                    .collect();
                format!("RIR: {}", breakdown.join(" | "))
            } else {
                "RIR: Waiting for packets...".to_string()
            };

            let status_text = format!(" PPS: {:<7} | {} ", pps, rir_text);
            buf.set_string(0, 60, status_text, Style::default());
        })?;

        thread::sleep(Duration::from_millis(16));
    }

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    Ok(())
}
