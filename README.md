# BraillePcap

Terminal-based IPv4 traffic visualizer in Rust using Unicode Braille characters.

![Demo](./demo.gif)

## Features

- Real-time packet capture display on a 224x256 IPv4 grid (Excludes Class D/E multicast & reserved space)
- Support for pcap files and live interfaces
- Regional Internet Registry (RIR) traffic statistics

## Requirements

- **Terminal Size**: Minimum **134 x 63** characters
- **Font**: Terminal font with Unicode Braille Patterns support (`U+2800`–`U+28FF`)

## Supported Platforms

Tested and confirmed working on:

- macOS (Apple Silicon)
- Ubuntu 24.04.4 LTS

## Prerequisites

### Ubuntu / Debian

Build dependencies for the `pcap` library:

```bash
sudo apt update
sudo apt install -y libpcap-dev pkg-config
```

## Options

| Option | Short | Description | Default |
| --- | --- | --- | --- |
| `--interface <INTERFACE>` | `-i` | Network interface for live capture | `en0` |
| `--read-file <FILE>` | `-r` | Read PCAP file or '-' for stdin | - |
| `--speed <SPEED>` | `-s` | Replay speed for PCAP file (0 = max speed) | `1.0` |
| `--hold-time <SECS>` | `-t` | Dot persistence duration in seconds | `0.5` |
| `--port <PORTS...>` | `-p` | Filter by port numbers (e.g., `-p 80 443`) | - |
| `--omit <CIDR...>` | `-o` | Exclude IP networks in CIDR notation | - |
| `--help` | `-h` | Print help information | - |
| `--version` | `-V` | Print version information | - |

## Usage

```bash
# Live capture
sudo cargo run --release -- -i en0

# Read pcap file
cargo run --release -- -r sample.pcap
```

## How to Read the Grid

- Vertical Axis (Y): First IPv4 Octet (0 – 223)
- Horizontal Axis (X): Second IPv4 Octet (0 – 255)
- Color Legend (Packet Frequency):
  - 🩵 Cyan: 1 – 5 packets
  - 🟩 Green: 6 – 20 packets
  - 🟨 Yellow (Bold): 21 – 100 packets
  - 🟥 Red (Bold): 101+ packets

## Keybindings

| Key | Action |
| --- | --- |
| `Space` | Pause / Resume visualization |
| `r` | Clear screen & reset packet counters |
| q | Quit application |

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

