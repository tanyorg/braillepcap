// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Fuminori -Tany- Tanizaki

mod cli;
mod packet;
mod rir;
mod ui;

use chrono::{DateTime, Local, TimeZone};
use clap::Parser;
use crossterm::{
    event::{self, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use pcap::Capture;
use ratatui::{
    backend::CrosstermBackend,
    layout::Rect,
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, Paragraph},
    Terminal,
};
use std::{
    collections::HashMap,
    io,
    net::Ipv4Addr,
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

use cli::Args;
use packet::{expand_path, parse_cidr, parse_packet, BatchUpdate, CapEngine, CidrMatcher};
use rir::get_iana_rir;
use ui::{get_color_and_style, BRAILLE_BIT_MAP, GRID_COLS, REQ_COLS, REQ_ROWS};

fn has_root_privileges() -> bool {
    #[cfg(target_family = "unix")]
    {
        std::process::Command::new("id")
            .arg("-u")
            .output()
            .map(|output| {
                output.status.success() && String::from_utf8_lossy(&output.stdout).trim() == "0"
            })
            .unwrap_or(false)
    }

    #[cfg(not(target_family = "unix"))]
    {
        true
    }
}

fn validate_interface_name(iface: &str) -> Result<(), String> {
    if iface.trim().is_empty() {
        return Err("Interface name cannot be empty".to_string());
    }

    if iface
        .chars()
        .any(|c| c.is_whitespace() || c == '/' || c == '\\')
    {
        return Err(format!("Invalid interface name: '{}'", iface));
    }

    #[cfg(target_os = "linux")]
    {
        let net_dir = std::path::Path::new("/sys/class/net");
        let entries = std::fs::read_dir(net_dir).map_err(|_| {
            format!(
                "Unable to inspect system interfaces for '{}': /sys/class/net is not accessible",
                iface
            )
        })?;

        let valid = entries
            .filter_map(|entry| entry.ok())
            .any(|entry| entry.file_name() == iface);

        if !valid {
            return Err(format!(
                "Interface '{}' does not exist on this system. Check /sys/class/net or pass a valid interface name.",
                iface
            ));
        }
    }

    Ok(())
}

#[derive(Clone, Debug)]
enum AppMode {
    Main,
    ZoomInput {
        value: String,
        error: Option<String>,
    },
    Detail {
        focus: (u8, u8),
    },
}

fn parse_zoom_target(value: &str) -> Result<(u8, u8), String> {
    let trimmed = value.trim();
    let host = if let Some((left, prefix)) = trimmed.split_once('/') {
        if prefix.trim() != "16" {
            return Err("Only /16 ranges are supported in the detail zoom view.".to_string());
        }
        left
    } else {
        trimmed
    };

    let parts: Vec<&str> = host.split('.').collect();
    match parts.len() {
        2 => {
            let first = parts[0]
                .parse::<u8>()
                .map_err(|_| "Invalid IPv4 address. Use a.b /16".to_string())?;
            let second = parts[1]
                .parse::<u8>()
                .map_err(|_| "Invalid IPv4 address. Use a.b /16".to_string())?;
            Ok((first, second))
        }
        4 => {
            let ip = host
                .parse::<Ipv4Addr>()
                .map_err(|_| "Invalid IPv4 address. Use a.b /16 or a.b.c.d/16".to_string())?;
            let octets = ip.octets();
            Ok((octets[0], octets[1]))
        }
        _ => Err("Invalid IPv4 address. Use a.b /16 or a.b.c.d/16".to_string()),
    }
}

fn detail_activity_cells(
    focus: (u8, u8),
    activity_by_network: &HashMap<(u8, u8), usize>,
) -> Vec<((u8, u8), usize)> {
    let mut cells = Vec::with_capacity(16);

    let base_oct1 = focus.0;
    let base_oct2 = focus.1;
    for row in 0..4 {
        for col in 0..4 {
            let oct1 = base_oct1 + row as u8;
            let oct2 = base_oct2 + col as u8;
            let count = activity_by_network.get(&(oct1, oct2)).copied().unwrap_or(0);
            cells.push(((oct1, oct2), count));
        }
    }

    cells
}

const ACTIVITY_BUCKET_WIDTH: Duration = Duration::from_millis(100);

struct ActivityBucket {
    dots: HashMap<(u8, u8), usize>,
    cells: HashMap<(usize, usize), usize>,
    networks: HashMap<(u8, u8), usize>,
}

impl ActivityBucket {
    fn new() -> Self {
        Self {
            dots: HashMap::new(),
            cells: HashMap::new(),
            networks: HashMap::new(),
        }
    }

    fn clear(&mut self) {
        self.dots.clear();
        self.cells.clear();
        self.networks.clear();
    }
}

struct ActivityBuckets {
    buckets: Vec<ActivityBucket>,
    current_index: usize,
    current_start: Instant,
    dots: HashMap<(u8, u8), usize>,
    cells: HashMap<(usize, usize), usize>,
    networks: HashMap<(u8, u8), usize>,
}

impl ActivityBuckets {
    fn new(now: Instant, hold_duration: Duration) -> Self {
        let bucket_count = (hold_duration.as_millis() + ACTIVITY_BUCKET_WIDTH.as_millis() - 1)
            .checked_div(ACTIVITY_BUCKET_WIDTH.as_millis())
            .unwrap_or(1)
            .max(1) as usize;

        Self {
            buckets: (0..bucket_count).map(|_| ActivityBucket::new()).collect(),
            current_index: 0,
            current_start: now,
            dots: HashMap::new(),
            cells: HashMap::new(),
            networks: HashMap::new(),
        }
    }

    fn advance(&mut self, now: Instant) {
        let elapsed = now.saturating_duration_since(self.current_start);
        let steps = elapsed.as_millis() / ACTIVITY_BUCKET_WIDTH.as_millis();
        if steps == 0 {
            return;
        }

        if steps >= self.buckets.len() as u128 {
            for bucket in &mut self.buckets {
                bucket.clear();
            }
            self.dots.clear();
            self.cells.clear();
            self.networks.clear();
            self.current_index = 0;
            self.current_start = now;
            return;
        }

        for _ in 0..steps {
            self.current_index = (self.current_index + 1) % self.buckets.len();
            let expired = &mut self.buckets[self.current_index];
            for (key, count) in expired.dots.drain() {
                Self::subtract(&mut self.dots, key, count);
            }
            for (key, count) in expired.cells.drain() {
                Self::subtract(&mut self.cells, key, count);
            }
            for (key, count) in expired.networks.drain() {
                Self::subtract(&mut self.networks, key, count);
            }
            self.current_start += ACTIVITY_BUCKET_WIDTH;
        }
    }

    fn record(&mut self, oct1: u8, oct2: u8, now: Instant) {
        self.advance(now);
        let dot_key = (oct1, oct2);
        let cell_key = ((oct2 / 2) as usize, (oct1 / 4) as usize);
        let bucket = &mut self.buckets[self.current_index];
        *bucket.dots.entry(dot_key).or_insert(0) += 1;
        *bucket.cells.entry(cell_key).or_insert(0) += 1;
        *bucket.networks.entry(dot_key).or_insert(0) += 1;
        *self.dots.entry(dot_key).or_insert(0) += 1;
        *self.cells.entry(cell_key).or_insert(0) += 1;
        *self.networks.entry(dot_key).or_insert(0) += 1;
    }

    fn subtract<K: Eq + std::hash::Hash>(totals: &mut HashMap<K, usize>, key: K, count: usize) {
        if let Some(total) = totals.get_mut(&key) {
            *total = total.saturating_sub(count);
            if *total == 0 {
                totals.remove(&key);
            }
        }
    }

    fn reset(&mut self, now: Instant, hold_duration: Duration) {
        *self = Self::new(now, hold_duration);
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::HashMap,
        time::{Duration, Instant},
    };

    use super::{detail_activity_cells, parse_zoom_target, ActivityBuckets};

    #[test]
    fn parse_zoom_target_accepts_first_two_octets_in_16_form() {
        assert_eq!(parse_zoom_target("13.112").unwrap(), (13, 112));
        assert_eq!(parse_zoom_target("13.112/16").unwrap(), (13, 112));
        assert_eq!(parse_zoom_target("192.168").unwrap(), (192, 168));
        assert_eq!(parse_zoom_target("192.168/16").unwrap(), (192, 168));
        assert!(parse_zoom_target("192.168.0.0/16").is_ok());
        assert!(parse_zoom_target("192").is_err());
        assert!(parse_zoom_target("256.168").is_err());
    }

    #[test]
    fn detail_activity_cells_use_the_selected_braille_window() {
        let activity = HashMap::from([
            ((192, 168), 24),
            ((192, 169), 14),
            ((192, 170), 8),
            ((192, 171), 2),
            ((193, 168), 0),
            ((193, 169), 0),
            ((193, 170), 18),
            ((193, 171), 4),
            ((194, 168), 6),
            ((194, 169), 10),
            ((194, 170), 16),
            ((194, 171), 12),
            ((195, 168), 22),
            ((195, 169), 20),
            ((195, 170), 26),
            ((195, 171), 28),
        ]);

        let cells = detail_activity_cells((192, 168), &activity);
        assert_eq!(cells.len(), 16);
        assert_eq!(cells[0].1, 24);
        assert_eq!(cells[1].1, 14);
        assert_eq!(cells[2].1, 8);
        assert_eq!(cells[3].1, 2);
        assert_eq!(cells[4].1, 0);
        assert_eq!(cells[5].1, 0);
        assert_eq!(cells[6].1, 18);
        assert_eq!(cells[7].1, 4);
        assert_eq!(cells[8].1, 6);
        assert_eq!(cells[9].1, 10);
        assert_eq!(cells[10].1, 16);
        assert_eq!(cells[11].1, 12);
        assert_eq!(cells[12].1, 22);
        assert_eq!(cells[13].1, 20);
        assert_eq!(cells[14].1, 26);
        assert_eq!(cells[15].1, 28);
    }

    #[test]
    fn activity_buckets_expire_data_by_bucket_width() {
        let start = Instant::now();
        let mut activity = ActivityBuckets::new(start, Duration::from_millis(300));
        activity.record(10, 123, start);
        assert_eq!(activity.networks.get(&(10, 123)), Some(&1));

        activity.advance(start + Duration::from_millis(299));
        assert_eq!(activity.networks.get(&(10, 123)), Some(&1));

        activity.advance(start + Duration::from_millis(300));
        assert!(!activity.networks.contains_key(&(10, 123)));
    }
}

fn reset_screen_state(
    activity: &mut ActivityBuckets,
    hold_duration: Duration,
    rir_counter: &mut HashMap<&'static str, usize>,
    rir_delta: &mut HashMap<&'static str, usize>,
    packet_count: &mut usize,
    pps: &mut usize,
    pps_window_start: &mut Instant,
    last_stats_calc: &mut Instant,
) {
    activity.reset(Instant::now(), hold_duration);
    rir_counter.clear();
    rir_delta.clear();
    *packet_count = 0;
    *pps = 0;
    *pps_window_start = Instant::now();
    *last_stats_calc = Instant::now();
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let iface = args.interface.clone().unwrap_or_else(|| "en0".to_string());

    if args.read_file.is_none() && !has_root_privileges() {
        return Err("Live capture requires root privileges. Run with sudo or as root.".into());
    }

    validate_interface_name(&iface)?;

    let omit_nets: Vec<CidrMatcher> = args
        .omit
        .iter()
        .map(|cidr_str| {
            parse_cidr(cidr_str).map_err(|err| format!("Invalid omit CIDR '{}': {}", cidr_str, err))
        })
        .collect::<Result<Vec<_>, _>>()?;

    let safe_buffer_size = args.buffer_size.clamp(1, 1024);
    let buffer_size_mb = safe_buffer_size as usize;
    let buf_bytes = buffer_size_mb
        .checked_mul(1024 * 1024)
        .and_then(|value| i32::try_from(value).ok())
        .ok_or_else(|| format!("buffer size is too large: {}", buffer_size_mb))?;

    // Initialize capture engine before launching TUI mode to fail fast on errors
    let engine = if let Some(ref file) = args.read_file {
        let path = expand_path(file.to_string_lossy().as_ref())?;
        let cap = Capture::from_file(path)?;
        CapEngine::File(cap)
    } else {
        let cap = Capture::from_device(iface.as_str())
            .map_err(|e| format!("Device error '{}': {}", iface, e))?
            .promisc(false)
            .snaplen(65535)
            .buffer_size(buf_bytes)
            .timeout(10)
            .immediate_mode(true)
            .open()?
            .setnonblock()?;

        CapEngine::Live(cap)
    };

    let (tx, rx) = mpsc::channel::<BatchUpdate>();
    let ports = args.port.clone();
    let replay_speed = args.speed;

    // Background capture thread with batching and clock synchronization
    thread::spawn(move || {
        let mut batch = Vec::with_capacity(10000);
        let mut last_flush = Instant::now();
        let flush_interval = Duration::from_millis(16);

        match engine {
            CapEngine::File(mut cap) => {
                let datalink = cap.get_datalink();
                let mut start_pcap_ts: Option<Duration> = None;
                let start_real_ts = Instant::now();
                let mut current_pcap_sec = 0u64;
                let mut pcap_sec_count = 0usize;

                while let Ok(packet) = cap.next_packet() {
                    let pkt_sec = packet.header.ts.tv_sec as u64;
                    if current_pcap_sec == 0 {
                        current_pcap_sec = pkt_sec;
                    }

                    let mut pps_to_send = None;
                    if pkt_sec > current_pcap_sec {
                        pps_to_send = Some(pcap_sec_count);
                        pcap_sec_count = 0;
                        current_pcap_sec = pkt_sec;
                    }

                    if replay_speed > 0.0 {
                        let pkt_ts =
                            Duration::new(pkt_sec, (packet.header.ts.tv_usec * 1000) as u32);
                        if start_pcap_ts.is_none() {
                            start_pcap_ts = Some(pkt_ts);
                        }
                        let pcap_elapsed = (pkt_ts - start_pcap_ts.unwrap()).div_f64(replay_speed);
                        let real_elapsed = start_real_ts.elapsed();

                        if pcap_elapsed > real_elapsed {
                            thread::sleep(pcap_elapsed - real_elapsed);
                        }
                    }

                    pcap_sec_count += 1;

                    if let Some((oct1, oct2, oct3)) =
                        parse_packet(packet.data, datalink, &ports, &omit_nets)
                    {
                        batch.push((oct1, oct2, oct3));
                    }

                    if batch.len() >= 10000
                        || last_flush.elapsed() >= flush_interval
                        || pps_to_send.is_some()
                    {
                        let count = batch.len();
                        if tx
                            .send(BatchUpdate {
                                dots: std::mem::take(&mut batch),
                                count,
                                pps_stat: pps_to_send,
                                last_pcap_sec: Some(current_pcap_sec as i64),
                            })
                            .is_err()
                        {
                            break;
                        }
                        last_flush = Instant::now();
                    }
                }
                if !batch.is_empty() || pcap_sec_count > 0 {
                    let count = batch.len();
                    let _ = tx.send(BatchUpdate {
                        dots: batch,
                        count,
                        pps_stat: Some(pcap_sec_count),
                        last_pcap_sec: Some(current_pcap_sec as i64),
                    });
                }
            }
            CapEngine::Live(mut cap) => {
                let datalink = cap.get_datalink();
                loop {
                    match cap.next_packet() {
                        Ok(packet) => {
                            if let Some((oct1, oct2, oct3)) =
                                parse_packet(packet.data, datalink, &ports, &omit_nets)
                            {
                                batch.push((oct1, oct2, oct3));
                            }
                        }
                        Err(pcap::Error::TimeoutExpired) => {}
                        Err(_) => break,
                    }

                    if batch.len() >= 10000 || last_flush.elapsed() >= flush_interval {
                        let count = batch.len();
                        if tx
                            .send(BatchUpdate {
                                dots: std::mem::take(&mut batch),
                                count,
                                pps_stat: None,
                                last_pcap_sec: None,
                            })
                            .is_err()
                        {
                            break;
                        }
                        last_flush = Instant::now();
                    }
                }
            }
        }
    });

    // Terminal display setup
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let hold_seconds = if args.hold_time.is_finite() {
        args.hold_time.clamp(0.01, 60.0)
    } else {
        0.5
    };
    let hold_duration = Duration::from_secs_f64(hold_seconds);

    let _speed = if args.speed.is_finite() {
        args.speed.clamp(0.0, 1000.0)
    } else {
        1.0
    };
    let mut activity = ActivityBuckets::new(Instant::now(), hold_duration);
    let mut rir_counter: HashMap<&'static str, usize> = HashMap::new();
    let mut rir_delta: HashMap<&'static str, usize> = HashMap::new();

    let mut packet_count = 0;
    let mut pps = 0;
    let mut pps_window_start = Instant::now();
    let mut pps_accumulator = 0usize;
    let mut last_stats_calc = Instant::now();
    let mut last_rir_flush = Instant::now();
    let mut is_paused = false;
    let mut current_time_str = String::from("-------------------");
    let mut app_mode = AppMode::Main;

    let mode_label = if let Some(ref f) = args.read_file {
        format!("PCAP: {}", f.display())
    } else {
        format!("Live: {}", iface)
    };

    // Main rendering loop
    loop {
        let now = Instant::now();

        if event::poll(Duration::from_millis(1))? {
            if let Event::Key(key) = event::read()? {
                match &mut app_mode {
                    AppMode::Main => match key.code {
                        KeyCode::Char('q') => break,
                        KeyCode::Char(' ') => is_paused = !is_paused,
                        KeyCode::Char('z') | KeyCode::Char('Z') => {
                            app_mode = AppMode::ZoomInput {
                                value: String::new(),
                                error: None,
                            };
                        }
                        KeyCode::Char('r') | KeyCode::Char('R') => {
                            reset_screen_state(
                                &mut activity,
                                hold_duration,
                                &mut rir_counter,
                                &mut rir_delta,
                                &mut packet_count,
                                &mut pps,
                                &mut pps_window_start,
                                &mut last_stats_calc,
                            );
                            terminal.clear()?;
                        }
                        _ => {}
                    },
                    AppMode::ZoomInput { value, error } => match key.code {
                        KeyCode::Esc => {
                            app_mode = AppMode::Main;
                            reset_screen_state(
                                &mut activity,
                                hold_duration,
                                &mut rir_counter,
                                &mut rir_delta,
                                &mut packet_count,
                                &mut pps,
                                &mut pps_window_start,
                                &mut last_stats_calc,
                            );
                            terminal.clear()?;
                        }
                        KeyCode::Enter => match parse_zoom_target(value) {
                            Ok((oct1, oct2)) => {
                                app_mode = AppMode::Detail {
                                    focus: (oct1, oct2),
                                };
                            }
                            Err(msg) => {
                                *error = Some(msg);
                            }
                        },
                        KeyCode::Backspace | KeyCode::Delete => {
                            value.pop();
                            *error = None;
                        }
                        KeyCode::Char(c) if c == '\u{7}' || c == '\u{8}' || c == '\u{127}' => {
                            value.pop();
                            *error = None;
                        }
                        KeyCode::Char(c) if c.is_ascii_graphic() || c == ' ' => {
                            value.push(c);
                            *error = None;
                        }
                        KeyCode::Char('q') => break,
                        _ => {}
                    },
                    AppMode::Detail { .. } => match key.code {
                        KeyCode::Esc => {
                            app_mode = AppMode::Main;
                            reset_screen_state(
                                &mut activity,
                                hold_duration,
                                &mut rir_counter,
                                &mut rir_delta,
                                &mut packet_count,
                                &mut pps,
                                &mut pps_window_start,
                                &mut last_stats_calc,
                            );
                            terminal.clear()?;
                            terminal.flush()?;
                        }
                        KeyCode::Char('q') => break,
                        _ => {}
                    },
                }
            }
        }

        match app_mode {
            AppMode::Main => {
                activity.advance(now);
                if is_paused {
                    while rx.try_recv().is_ok() {}
                } else {
                    while let Ok(update) = rx.try_recv() {
                        packet_count += update.count;

                        if let Some(exact_pps) = update.pps_stat {
                            pps = exact_pps;
                            pps_accumulator = 0;
                            pps_window_start = now;
                        } else {
                            pps_accumulator += update.count;
                            if now.duration_since(pps_window_start) >= Duration::from_secs(1) {
                                pps = pps_accumulator;
                                pps_accumulator = 0;
                                pps_window_start = now;
                            }
                        }

                        if let Some(pcap_sec) = update.last_pcap_sec {
                            if let Some(dt) = DateTime::from_timestamp(pcap_sec, 0) {
                                let local_dt = Local.from_utc_datetime(&dt.naive_utc());
                                current_time_str = local_dt.format("%Y-%m-%d %H:%M:%S").to_string();
                            }
                        }

                        for (oct1, oct2, _oct3) in update.dots {
                            activity.record(oct1, oct2, now);

                            let rir = get_iana_rir(oct1);
                            *rir_delta.entry(rir).or_insert(0) += 1;
                        }
                    }

                    if now.duration_since(last_rir_flush) >= Duration::from_secs(1) {
                        for (rir, count) in rir_delta.drain() {
                            *rir_counter.entry(rir).or_insert(0) += count;
                        }
                        last_rir_flush = now;
                    }

                    if args.read_file.is_none() {
                        current_time_str = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();

                        if now.duration_since(last_stats_calc) >= Duration::from_secs(1) {
                            packet_count = 0;
                            last_stats_calc = now;
                        }
                    }
                }
            }
            AppMode::ZoomInput { .. } | AppMode::Detail { .. } => {
                activity.advance(now);
                while let Ok(update) = rx.try_recv() {
                    for (oct1, oct2, _oct3) in update.dots {
                        activity.record(oct1, oct2, now);
                    }
                }
            }
        }

        terminal.draw(|f| {
            let size = f.area();
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
            let pause_ind = if is_paused { " [PAUSED]" } else { "" };
            let title_left = format!(" BraillePcap [{}{}]{} ", mode_label, pause_ind, port_ind);
            let total_width = size.width as usize;
            let time_len = current_time_str.len();

            let pad_len = if total_width > title_left.len() + time_len {
                total_width - title_left.len() - time_len
            } else {
                1
            };
            let full_title = format!("{}{}{}", title_left, " ".repeat(pad_len), current_time_str);

            buf.set_string(0, 0, &full_title, Style::default().add_modifier(Modifier::REVERSED | Modifier::BOLD));

            let header = "     0              32              64              96             128             160             192             224             255";
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
                    buf.set_string(
                        (cx + 5) as u16,
                        scr_y,
                        "│",
                        Style::default().fg(Color::DarkGray),
                    );
                }
            }

            let mut cell_masks: HashMap<(usize, usize), u16> = HashMap::new();
            for &(oct1, oct2) in activity.dots.keys() {
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
                let cell_activity = activity.cells.get(&(cx, cy)).copied().unwrap_or(0);
                let style = get_color_and_style(cell_activity);

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

            match &app_mode {
                AppMode::Main => {}
                AppMode::ZoomInput { value, error } => {
                    let area_width = 60;
                    let area_height = 8;
                    let area = Rect::new(
                        size.width.saturating_sub(area_width) / 2,
                        size.height.saturating_sub(area_height) / 2,
                        area_width,
                        area_height,
                    );
                    f.render_widget(Clear, area);
                    let block = Block::default()
                        .title("Zoom /16")
                        .borders(Borders::ALL)
                        .border_style(Style::default().fg(Color::Cyan));
                    let mut lines = vec![
                        Line::from("Enter the first two octets in /16 form (e.g. 10.10)"),
                        Line::from(format!("> {}", value)),
                    ];
                    if let Some(err) = error {
                        lines.push(Line::from(Span::styled(err.clone(), Style::default().fg(Color::Red))));
                    }
                    lines.push(Line::from("Esc: cancel   Enter: open detail view"));
                    f.render_widget(block, area);
                    let inner = Rect::new(area.x + 2, area.y + 1, area.width.saturating_sub(4), area.height.saturating_sub(2));
                    f.render_widget(Paragraph::new(lines), inner);
                }
                AppMode::Detail { focus, .. } => {
                    let area_width = 92;
                    let area_height = 10;
                    let area = Rect::new(
                        size.width.saturating_sub(area_width) / 2,
                        size.height.saturating_sub(area_height) / 2,
                        area_width,
                        area_height,
                    );
                    f.render_widget(Clear, area);
                    let block = Block::default()
                        .borders(Borders::ALL)
                        .border_style(Style::default().fg(Color::Yellow));
                    let detail_activity = detail_activity_cells(*focus, &activity.networks)
                        .into_iter()
                        .map(|(network, count)| {
                            let pps = (count as f64 / hold_seconds.max(0.01)).round() as usize;
                            (network, pps)
                        })
                        .collect::<Vec<_>>();
                    let mut detail_lines = Vec::new();

                    for row_idx in 0..4 {
                        let mut cells = Vec::new();
                        for col_idx in 0..4 {
                            if !cells.is_empty() {
                                cells.push(Span::raw(" |"));
                            }
                            let idx = row_idx * 4 + col_idx;
                            let ((oct1, oct2), count) = detail_activity[idx];
                            let label = format!("{}.{}.0.0/16", oct1, oct2);
                            let score_style = get_color_and_style(count);
                            let cell = format!("{:<15} {:>4}", label, count);
                            cells.push(Span::styled(cell, score_style));
                        }
                        detail_lines.push(Line::from(cells));
                    }

                    detail_lines.push(Line::from(""));
                    detail_lines.push(Line::from("Esc: return to main view"));
                    f.render_widget(block, area);
                    let inner = Rect::new(area.x + 2, area.y + 1, area.width.saturating_sub(4), area.height.saturating_sub(2));
                    f.render_widget(Paragraph::new(detail_lines), inner);
                }
            }
        })?;

        thread::sleep(Duration::from_millis(33));
    }

    // Restore terminal configuration on exit
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    Ok(())
}
