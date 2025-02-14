# BlitzMap - Fast Port Scanner

BlitzMap is a high-performance, asynchronous port scanner written in Rust. It provides detailed information about open ports, running services, and their versions.

## Features

- **Fast Scanning**: Utilizes asynchronous I/O for high-speed port scanning
- **Service Detection**: Identifies common services and their versions
- **Protocol Support**: Both TCP and UDP scanning capabilities
- **Flexible Port Selection**: Scan specific ports, ranges, or most common ports
- **Colorized Output**: Optional colored terminal output for better readability
- **Verbose Mode**: Detailed information about discovered services
- **Output to File**: Save scan results to a file
- **Progress Tracking**: Real-time progress bar showing scan status
- **IP Range Support**: Scan single IP or IP ranges
- **Localization**: Supports multiple languages for output formatting

## Installation

1. Make sure you have Rust installed on your system
2. Clone the repository
3. Build the project:
```bash
cargo build --release
```

## Usage

Basic usage:
```bash
blitzmap [OPTIONS] <target>
```

### Arguments

- `<target>`: IP address or IP range (e.g., 192.168.1.1 or 192.168.1.1-100)

### Options

- `-p, --ports <PORT>`: Port selection
  - `-p-`: Scan all ports (1-65535)
  - `-p <port>`: Scan specific port(s) (e.g., -p 80 or -p 80,443,8080)
  - No parameter: Scan most common ports
- `-t, --timeout <MS>`: Timeout in milliseconds (default: 850)
- `-c, --colored`: Enable colored output
- `-j, --jobs <NUM>`: Number of parallel scans (default: 1000)
- `-o, --output <FILE>`: Output file name (default: blitzmap-[date].txt)
- `-v, --verbose`: Enable verbose output mode

## Examples

1. Scan a single IP with default settings:
```bash
blitzmap 192.168.1.1
```

2. Scan specific ports with colored output:
```bash
blitzmap -p 80,443,3306 -c 192.168.1.1
```

3. Full port scan with verbose output:
```bash
blitzmap -p- -v 192.168.1.1
```

4. Scan IP range with custom timeout:
```bash
blitzmap -t 1000 192.168.1.1-254
```

## Core Functions

### Port Scanning
- `scan_tcp_port`: Asynchronously scans TCP ports
- `scan_udp_port`: Asynchronously scans UDP ports
- `scan_port_range`: Manages parallel port scanning operations

### Service Detection
- `get_service_info`: Identifies services running on open ports
- `get_protocol_probes`: Provides protocol-specific probes for service detection
- `get_known_services`: Retrieves information about known services from port database

### Output Formatting
- `format_port_info`: Formats port scan results for display
- `format_colored_text`: Handles colored output formatting
- `get_localized_time`: Provides localized time formatting

### Configuration
- `parse_port_argument`: Processes port selection arguments
- `load_port_data`: Loads service and port information from JSON database

## Contributing

Contributions are welcome! Please feel free to submit pull requests.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Built with Rust and Tokio for high-performance async I/O
- Uses various Rust crates for enhanced functionality:
  - tokio: Asynchronous runtime
  - clap: Command line argument parsing
  - colored: Terminal colors
  - indicatif: Progress bars
  - serde: JSON serialization
  - chrono: Time handling
  - locale_config: Localization support 