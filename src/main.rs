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
                output.status.success()
                    && String::from_utf8_lossy(&output.stdout).trim() == "0"
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

    if iface.chars().any(|c| c.is_whitespace() || c == '/' || c == '\\') {
        return Err(format!("Invalid interface name: '{}'", iface));
    }

    #[cfg(target_os = "linux")]
    {
        let net_dir = std::path::Path::new("/sys/class/net");
        let entries = std::fs::read_dir(net_dir)
            .map_err(|_| format!("Unable to inspect system interfaces for '{}': /sys/class/net is not accessible", iface))?;

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
                        let pkt_ts = Duration::new(pkt_sec, (packet.header.ts.tv_usec * 1000) as u32);
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

                    if let Some((oct1, oct2)) =
                        parse_packet(packet.data, datalink, &ports, &omit_nets)
                    {
                        batch.push((oct1, oct2));
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
                            if let Some((oct1, oct2)) =
                                parse_packet(packet.data, datalink, &ports, &omit_nets)
                            {
                                batch.push((oct1, oct2));
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
    let mut active_dots: HashMap<(u8, u8), Instant> = HashMap::new();
    let mut cell_history: HashMap<(usize, usize), Vec<Instant>> = HashMap::new();
    let mut rir_counter: HashMap<&'static str, usize> = HashMap::new();

    let mut packet_count = 0;
    let mut pps = 0;
    let mut last_stats_calc = Instant::now();
    let mut is_paused = false;
    let mut current_time_str = String::from("-------------------");

    let mode_label = if let Some(ref f) = args.read_file {
        format!("PCAP: {}", f.display())
    } else {
        format!("Live: {}", iface)
    };

    // Main rendering loop
    loop {
        let now = Instant::now();

        // Key event handling
        if event::poll(Duration::from_millis(1))? {
            if let Event::Key(key) = event::read()? {
                match key.code {
                    KeyCode::Char('q') => break,
                    KeyCode::Char(' ') => is_paused = !is_paused,
                    KeyCode::Char('r') | KeyCode::Char('R') => {
                        active_dots.clear();
                        cell_history.clear();
                        rir_counter.clear();
                        packet_count = 0;
                        pps = 0;
                        last_stats_calc = Instant::now();
                        terminal.clear()?;
                    }
                    _ => {}
                }
            }
        }

        if is_paused {
            while rx.try_recv().is_ok() {}
        } else {
            while let Ok(update) = rx.try_recv() {
                packet_count += update.count;

                if let Some(exact_pps) = update.pps_stat {
                    pps = exact_pps;
                }

                if let Some(pcap_sec) = update.last_pcap_sec {
                    if let Some(dt) = DateTime::from_timestamp(pcap_sec, 0) {
                        let local_dt = Local.from_utc_datetime(&dt.naive_utc());
                        current_time_str = local_dt.format("%Y-%m-%d %H:%M:%S").to_string();
                    }
                }

                for (oct1, oct2) in update.dots {
                    active_dots.insert((oct1, oct2), now);

                    let rir = get_iana_rir(oct1);
                    *rir_counter.entry(rir).or_insert(0) += 1;

                    let char_y = (oct1 / 4) as usize;
                    let char_x = (oct2 / 2) as usize;
                    cell_history.entry((char_x, char_y)).or_default().push(now);
                }
            }

            if args.read_file.is_none() {
                current_time_str = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();

                if now.duration_since(last_stats_calc) >= Duration::from_secs(1) {
                    pps = packet_count;
                    packet_count = 0;
                    last_stats_calc = now;
                }
            }

            // Purge expired active dots and historical cell records
            active_dots.retain(|_, time| now.duration_since(*time) < hold_duration);
            cell_history.retain(|_, timestamps| {
                timestamps.retain(|t| now.duration_since(*t) < hold_duration);
                !timestamps.is_empty()
            });
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

            // 1. Draw outer frame and grid lines (DarkGray for vertical grid lines)
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

            // Map IP addresses to Unicode Braille bitmasks
            let mut cell_masks: HashMap<(usize, usize), u16> = HashMap::new();
            for &(oct1, oct2) in active_dots.keys() {
                let cy = (oct1 / 4) as usize;
                let cx = (oct2 / 2) as usize;
                let sub_y = (oct1 % 4) as usize;
                let sub_x = (oct2 % 2) as usize;

                let bit_val = BRAILLE_BIT_MAP[sub_y][sub_x];
                *cell_masks.entry((cx, cy)).or_insert(0) |= bit_val;
            }

            // 2. Overwrite grid cell with Braille character and packet color when active
            for ((cx, cy), mask) in cell_masks {
                let scr_x = (cx + 5) as u16;
                let scr_y = (cy + 3) as u16;

                let braille_char = std::char::from_u32(0x2800 + mask as u32).unwrap_or(' ');
                let cell_activity = cell_history.get(&(cx, cy)).map_or(0, |v| v.len());
                // The cell color is a relative activity score over the hold window,
                // not a literal per-/24 PPS readout for each dotted subnet.
                let style = get_color_and_style(cell_activity);

                buf.set_string(scr_x, scr_y, braille_char.to_string(), style);
            }

            // Render bottom status bar with RIR statistics
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

    // Restore terminal configuration on exit
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    Ok(())
}
