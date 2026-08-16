# BraillePcap

Terminal-based IPv4 traffic visualizer in Rust using Unicode Braille characters.

![Demo](./demo.gif)

## Features
- Real-time packet capture display on a 256x256 IPv4 grid
- Support for pcap files and live interfaces
- Regional Internet Registry (RIR) traffic statistics

## Supported Platforms
Tested and confirmed working on:
- macOS (Apple Silicon)
- Ubuntu 24.04.4 LTS

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

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

