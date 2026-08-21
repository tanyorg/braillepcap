use ratatui::style::{Color, Modifier, Style};

pub const REQ_COLS: u16 = 134;
pub const REQ_ROWS: u16 = 62;
pub const GRID_COLS: [usize; 7] = [16, 32, 48, 64, 80, 96, 112];

// Bit pattern mapping for Unicode Braille characters (2x4 matrix)
pub const BRAILLE_BIT_MAP: [[u16; 2]; 4] = [[0x01, 0x08], [0x02, 0x10], [0x04, 0x20], [0x40, 0x80]];

// Determine terminal display style from the packet activity score for a Braille cell.
// This is a relative intensity measure for the current hold window, not an exact
// per-/24 PPS measurement for the underlying IPv4 network range.
pub fn get_color_and_style(cell_activity: usize) -> Style {
    match cell_activity {
        0..=5 => Style::default().fg(Color::Cyan),
        6..=20 => Style::default().fg(Color::Green),
        21..=100 => Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD),
        _ => Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
    }
}

#[cfg(test)]
mod tests {
    use super::get_color_and_style;
    use ratatui::style::{Color, Modifier, Style};

    #[test]
    fn color_mapping_tracks_relative_cell_activity_not_exact_pps() {
        assert_eq!(get_color_and_style(0), Style::default().fg(Color::Cyan));
        assert_eq!(get_color_and_style(6), Style::default().fg(Color::Green));
        assert_eq!(
            get_color_and_style(21),
            Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)
        );
        assert_eq!(
            get_color_and_style(101),
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)
        );
    }
}
