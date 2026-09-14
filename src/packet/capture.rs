// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Fuminori -Tany- Tanizaki

use super::os::calculate_l2_offset;
use super::parser::{process_ip_payload, CidrMatcher};
use pcap::{Capture, Linktype};
use std::{
    sync::mpsc::SyncSender,
    thread,
    time::{Duration, Instant},
};

use super::BatchUpdate;

pub enum CapEngine {
    File(Capture<pcap::Offline>),
    Live(Capture<pcap::Active>),
}

pub fn spawn_capture_thread(
    engine: CapEngine,
    tx: SyncSender<BatchUpdate>,
    ports: Vec<u16>,
    replay_speed: f64,
    omit_nets: Vec<CidrMatcher>,
    observe_net: Option<CidrMatcher>,
) {
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
                    let Some(pkt_ts) = safe_packet_timestamp(
                        packet.header.ts.tv_sec,
                        i64::from(packet.header.ts.tv_usec),
                    ) else {
                        continue;
                    };
                    let pkt_sec = pkt_ts.as_secs();
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
                        if start_pcap_ts.is_none() {
                            start_pcap_ts = Some(pkt_ts);
                        }
                        let pcap_elapsed = pkt_ts
                            .checked_sub(start_pcap_ts.unwrap())
                            .unwrap_or(Duration::ZERO)
                            .div_f64(replay_speed);
                        let real_elapsed = start_real_ts.elapsed();

                        if pcap_elapsed > real_elapsed {
                            thread::sleep(pcap_elapsed - real_elapsed);
                        }
                    }

                    if observe_net.is_none() {
                        pcap_sec_count += 1;
                    }

                    if let Some((oct1, oct2, oct3, oct4)) = parse_packet(
                        packet.data,
                        datalink,
                        &ports,
                        &omit_nets,
                        observe_net.as_ref(),
                    ) {
                        if observe_net.is_some() {
                            pcap_sec_count += 1;
                        }
                        batch.push((oct1, oct2, oct3, oct4));
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
                            if let Some((oct1, oct2, oct3, oct4)) = parse_packet(
                                packet.data,
                                datalink,
                                &ports,
                                &omit_nets,
                                observe_net.as_ref(),
                            ) {
                                batch.push((oct1, oct2, oct3, oct4));
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
}

fn safe_packet_timestamp(sec: i64, usec: i64) -> Option<Duration> {
    if sec < 0 || !(0..1_000_000).contains(&usec) {
        return None;
    }

    Some(Duration::new(
        u64::try_from(sec).ok()?,
        u32::try_from(usec).ok()?.checked_mul(1_000)?,
    ))
}

/// Strip L2 header and pass remaining payload to the packet parser
pub fn parse_packet(
    data: &[u8],
    linktype: Linktype,
    target_ports: &[u16],
    omit_nets: &[CidrMatcher],
    observe_net: Option<&CidrMatcher>,
) -> Option<(u8, u8, u8, u8)> {
    let l2_offset = calculate_l2_offset(linktype, data)?;

    if data.len() < l2_offset + 20 {
        return None;
    }

    let ip_data = &data[l2_offset..];
    process_ip_payload(ip_data, target_ports, omit_nets, observe_net)
}

#[cfg(test)]
mod tests {
    use super::safe_packet_timestamp;
    use std::time::Duration;

    #[test]
    fn rejects_invalid_packet_timestamps() {
        assert_eq!(safe_packet_timestamp(-1, 0), None);
        assert_eq!(safe_packet_timestamp(1, -1), None);
        assert_eq!(safe_packet_timestamp(1, 1_000_000), None);
    }

    #[test]
    fn parses_valid_packet_timestamp() {
        assert_eq!(
            safe_packet_timestamp(12, 345_678),
            Some(Duration::new(12, 345_678_000))
        );
    }
}
