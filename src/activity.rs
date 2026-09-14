// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Fuminori -Tany- Tanizaki

use std::{
    collections::HashMap,
    net::Ipv4Addr,
    time::{Duration, Instant},
};

pub const ACTIVITY_BUCKET_WIDTH: Duration = Duration::from_millis(100);

pub fn display_coordinates(net_mode: bool, octets: (u8, u8, u8, u8)) -> (u8, u8) {
    if net_mode {
        (octets.2, octets.3)
    } else {
        (octets.0, octets.1)
    }
}

pub fn parse_zoom_target(value: &str) -> Result<(u8, u8), String> {
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
            if first > 252 || second > 252 {
                return Err("Zoom start must be between 0 and 252".to_string());
            }
            Ok((first, second))
        }
        4 => {
            let ip = host
                .parse::<Ipv4Addr>()
                .map_err(|_| "Invalid IPv4 address. Use a.b /16 or a.b.c.d/16".to_string())?;
            let octets = ip.octets();
            if octets[0] > 252 || octets[1] > 252 {
                return Err("Zoom start must be between 0 and 252".to_string());
            }
            Ok((octets[0], octets[1]))
        }
        _ => Err("Invalid IPv4 address. Use a.b /16 or a.b.c.d/16".to_string()),
    }
}

pub fn detail_activity_cells(
    focus: (u8, u8),
    activity_by_network: &HashMap<(u8, u8), usize>,
) -> Vec<((u8, u8), usize)> {
    let mut cells = Vec::with_capacity(16);

    for row in 0..4 {
        for col in 0..4 {
            let Some(oct1) = focus.0.checked_add(row as u8) else {
                continue;
            };
            let Some(oct2) = focus.1.checked_add(col as u8) else {
                continue;
            };
            let count = activity_by_network.get(&(oct1, oct2)).copied().unwrap_or(0);
            cells.push(((oct1, oct2), count));
        }
    }

    cells
}

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

pub struct ActivityBuckets {
    buckets: Vec<ActivityBucket>,
    current_index: usize,
    current_start: Instant,
    pub dots: HashMap<(u8, u8), usize>,
    pub cells: HashMap<(usize, usize), usize>,
    pub networks: HashMap<(u8, u8), usize>,
}

impl ActivityBuckets {
    pub fn new(now: Instant, hold_duration: Duration) -> Self {
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

    pub fn advance(&mut self, now: Instant) {
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

    pub fn record(&mut self, oct1: u8, oct2: u8, now: Instant) {
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

    pub fn reset(&mut self, now: Instant, hold_duration: Duration) {
        *self = Self::new(now, hold_duration);
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::HashMap,
        time::{Duration, Instant},
    };

    use super::{detail_activity_cells, display_coordinates, parse_zoom_target, ActivityBuckets};

    #[test]
    fn net_mode_displays_each_ipv4_address_as_a_dot() {
        let address = (192, 168, 12, 34);
        assert_eq!(display_coordinates(true, address), (12, 34));
        assert_eq!(display_coordinates(false, address), (192, 168));
    }

    #[test]
    fn parse_zoom_target_accepts_first_two_octets_in_16_form() {
        assert_eq!(parse_zoom_target("13.112").unwrap(), (13, 112));
        assert_eq!(parse_zoom_target("13.112/16").unwrap(), (13, 112));
        assert_eq!(parse_zoom_target("192.168").unwrap(), (192, 168));
        assert_eq!(parse_zoom_target("192.168/16").unwrap(), (192, 168));
        assert!(parse_zoom_target("192.168.0.0/16").is_ok());
        assert!(parse_zoom_target("192").is_err());
        assert!(parse_zoom_target("256.168").is_err());
        assert!(parse_zoom_target("253.0").is_err());
        assert!(parse_zoom_target("252.253/16").is_err());
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
