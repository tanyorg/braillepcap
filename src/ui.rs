use ratatui::style::{Color, Modifier, Style};

pub const REQ_COLS: u16 = 134;
pub const REQ_ROWS: u16 = 62;
pub const GRID_COLS: [usize; 7] = [16, 32, 48, 64, 80, 96, 112];

// Bit pattern mapping for Unicode Braille characters (2x4 matrix)
pub const BRAILLE_BIT_MAP: [[u16; 2]; 4] = [[0x01, 0x08], [0x02, 0x10], [0x04, 0x20], [0x40, 0x80]];

// Determine terminal display style based on packet hit frequency
pub fn get_color_and_style(pkt_count: usize) -> Style {
    match pkt_count {
        0..=5 => Style::default().fg(Color::Cyan),
        6..=20 => Style::default().fg(Color::Green),
        21..=100 => Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD),
        _ => Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
    }
}
