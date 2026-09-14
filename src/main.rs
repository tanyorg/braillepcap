// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Fuminori -Tany- Tanizaki

mod activity;
mod cli;
mod packet;
mod rir;
mod ui;

use chrono::{DateTime, Local, TimeZone};
use clap::Parser;
use crossterm::{
    cursor::Show,
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

use activity::{
    address_detail_activity_cells, detail_activity_cells, display_coordinates,
    parse_address_target, parse_zoom_target, ActivityBuckets,
};
use cli::Args;
use packet::{expand_path, parse_cidr, spawn_capture_thread, BatchUpdate, CapEngine, CidrMatcher};
use rir::get_iana_rir;
use ui::{get_color_and_style, BRAILLE_BIT_MAP, GRID_COLS, REQ_COLS, REQ_ROWS};

struct TerminalGuard;

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = execute!(io::stdout(), Show, LeaveAlternateScreen);
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
        focus: DetailFocus,
    },
}

#[derive(Clone, Debug)]
enum DetailFocus {
    Network16((u8, u8)),
    Address32((u8, u8, u8, u8)),
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

    let omit_nets: Vec<CidrMatcher> = args
        .omit
        .iter()
        .map(|cidr_str| {
            parse_cidr(cidr_str).map_err(|err| format!("Invalid omit CIDR '{}': {}", cidr_str, err))
        })
        .collect::<Result<Vec<_>, _>>()?;

    let observe_net = args
        .net
        .as_deref()
        .map(parse_cidr)
        .transpose()?
        .map(|matcher| {
            if matcher.mask != 0xffff_0000 {
                Err("--net only supports IPv4 networks with a /16 prefix".to_string())
            } else {
                Ok(matcher)
            }
        })
        .transpose()?;

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
        validate_interface_name(&iface)?;
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

    let (tx, rx) = mpsc::sync_channel::<BatchUpdate>(64);
    let ports = args.port.clone();
    let replay_speed = if args.speed.is_finite() {
        args.speed.clamp(0.0, 1000.0)
    } else {
        1.0
    };

    spawn_capture_thread(engine, tx, ports, replay_speed, omit_nets, observe_net);

    // Terminal display setup
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let _terminal_guard = TerminalGuard;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let hold_seconds = if args.hold_time.is_finite() {
        args.hold_time.clamp(0.01, 60.0)
    } else {
        0.5
    };
    let hold_duration = Duration::from_secs_f64(hold_seconds);

    let mut activity = ActivityBuckets::new(Instant::now(), hold_duration);
    let mut detail_network_pps: HashMap<(u8, u8), usize> = HashMap::new();
    let mut detail_pps_accumulator: HashMap<(u8, u8), usize> = HashMap::new();
    let mut detail_address_pps: HashMap<(u8, u8, u8, u8), usize> = HashMap::new();
    let mut detail_address_accumulator: HashMap<(u8, u8, u8, u8), usize> = HashMap::new();
    let mut detail_pps_window_start = Instant::now();
    let mut detail_has_complete_pps_window = false;
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
                            detail_network_pps.clear();
                            detail_pps_accumulator.clear();
                            detail_address_pps.clear();
                            detail_address_accumulator.clear();
                            detail_pps_window_start = Instant::now();
                            detail_has_complete_pps_window = false;
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
                        KeyCode::Enter if args.net.is_some() => match parse_address_target(value) {
                            Ok(address) => {
                                let ip = u32::from(Ipv4Addr::new(
                                    address.0, address.1, address.2, address.3,
                                ));
                                if observe_net.is_some_and(|net| net.matches(ip)) {
                                    app_mode = AppMode::Detail {
                                        focus: DetailFocus::Address32(address),
                                    };
                                } else {
                                    *error = Some(
                                        "Address is outside the observed /16 network.".to_string(),
                                    );
                                }
                            }
                            Err(msg) => *error = Some(msg),
                        },
                        KeyCode::Enter => match parse_zoom_target(value) {
                            Ok((oct1, oct2)) => {
                                app_mode = AppMode::Detail {
                                    focus: DetailFocus::Network16((oct1, oct2)),
                                };
                            }
                            Err(msg) => *error = Some(msg),
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
                    for _ in 0..64 {
                        let Ok(update) = rx.try_recv() else { break };
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

                        for octets @ (oct1, _, _, _) in update.dots {
                            let (y, x) = display_coordinates(args.net.is_some(), octets);
                            activity.record(y, x, now);

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
                for _ in 0..64 {
                    let Ok(update) = rx.try_recv() else { break };
                    if update.pps_stat.is_some() {
                        if detail_has_complete_pps_window {
                            if args.net.is_some() {
                                detail_address_pps =
                                    std::mem::take(&mut detail_address_accumulator);
                            } else {
                                detail_network_pps = std::mem::take(&mut detail_pps_accumulator);
                            }
                        } else {
                            if args.net.is_some() {
                                detail_address_accumulator.clear();
                            } else {
                                detail_pps_accumulator.clear();
                            }
                            detail_has_complete_pps_window = true;
                        }
                        detail_pps_window_start = now;
                    }
                    for (oct1, oct2, oct3, oct4) in update.dots {
                        if args.net.is_some() {
                            *detail_address_accumulator
                                .entry((oct1, oct2, oct3, oct4))
                                .or_insert(0) += 1;
                        } else {
                            *detail_pps_accumulator.entry((oct1, oct2)).or_insert(0) += 1;
                        }
                    }
                    if update.pps_stat.is_none()
                        && now.duration_since(detail_pps_window_start) >= Duration::from_secs(1)
                    {
                        if args.net.is_some() {
                            detail_address_pps = std::mem::take(&mut detail_address_accumulator);
                        } else {
                            detail_network_pps = std::mem::take(&mut detail_pps_accumulator);
                        }
                        detail_pps_window_start = now;
                    }
                }
            }
        }

        terminal.draw(|f| {
            let size = f.area();
            let required_rows = if args.net.is_some() { REQ_ROWS + 8 } else { REQ_ROWS };
            if size.width < REQ_COLS || size.height < required_rows {
                let msg = Span::raw(format!(
                    "Screen too small: {}x{} (Required: {}x{})",
                    size.width, size.height, REQ_COLS, required_rows
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
            let net_ind = observe_net
                .map(|matcher| format!(" [Net: {}/16]", Ipv4Addr::from(matcher.network)))
                .unwrap_or_default();
            let pause_ind = if is_paused { " [PAUSED]" } else { "" };
            let title_left = format!(
                " BraillePcap [{}{}]{}{} ",
                mode_label, pause_ind, net_ind, port_ind
            );
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
            for pos in [13, 21, 29, 37, 45, 53, 61, 69, 77, 85, 93, 101, 109, 117, 125] {
                top_chars[pos] = '+';
            }
            top_border = top_chars.into_iter().collect();
            buf.set_string(0, 2, &top_border, Style::default());
            let grid_rows = if args.net.is_some() { 64 } else { 56 };
            let bottom_border_y = grid_rows + 3;
            let status_y = bottom_border_y + 1;
            buf.set_string(0, bottom_border_y as u16, &top_border, Style::default());

            for y in 0..grid_rows {
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
            buf.set_string(0, status_y as u16, status_text, Style::default());

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
                    let prompt = if args.net.is_some() {
                        "Enter an IPv4 address in /32 form (e.g. 133.5.60.0)"
                    } else {
                        "Enter the first two octets in /16 form (e.g. 10.10)"
                    };
                    let mut lines = vec![
                        Line::from(prompt),
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
                    let mut detail_lines = Vec::new();
                    let detail_cells = match focus {
                        DetailFocus::Network16(focus) => detail_activity_cells(*focus, &detail_network_pps)
                            .into_iter()
                            .map(|((oct1, oct2), count)| {
                                (format!("{}.{}.0.0/16", oct1, oct2), count)
                            })
                            .collect::<Vec<_>>(),
                        DetailFocus::Address32(focus) => address_detail_activity_cells(*focus, &detail_address_pps)
                            .into_iter()
                            .map(|(start, end, count)| {
                                let label = if start.0 == end.0
                                    && start.1 == end.1
                                    && start.2 == end.2
                                {
                                    format!(
                                        "{}.{}.{}.{}-{}",
                                        start.0, start.1, start.2, start.3, end.3
                                    )
                                } else {
                                    format!(
                                        "{}.{}.{}.{}-{}.{}.{}.{}",
                                        start.0, start.1, start.2, start.3,
                                        end.0, end.1, end.2, end.3
                                    )
                                };
                                (
                                    label,
                                    count,
                                )
                            })
                            .collect::<Vec<_>>(),
                    };

                    for row_idx in 0..4 {
                        let mut cells = Vec::new();
                        for col_idx in 0..4 {
                            if !cells.is_empty() {
                                cells.push(Span::raw(" |"));
                            }
                            let idx = row_idx * 4 + col_idx;
                            let (label, count) = &detail_cells[idx];
                            let score_style = get_color_and_style(*count);
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

        thread::sleep(Duration::from_millis(100));
    }

    Ok(())
}
