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
| `--interface <NAME>` | `-i` | Network interface to capture from | - |
| `--read-pcap <FILE>` | `-r` | Read packets from a pcap file | - |
| `--promisc` | `-p` | Enable promiscuous mode | `false` |
| `--snapshot-len <LEN>` | `-s` | Snapshot length (bytes) | `65535` |
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

