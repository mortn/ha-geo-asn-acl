# IP Geolocation CIDR Block Fetcher

A Rust command-line application that fetches IP geolocation data, verifies its integrity using SHA256 checksums, and filters CIDR blocks for specific countries (Denmark and Sweden).

## Features

- **Efficient Caching**: Only downloads the file if it's newer than the local cached version using HTTP `If-Modified-Since` headers
- **Integrity Verification**: Validates downloaded files using SHA256 checksums
- **Country Filtering**: Extracts and displays CIDR blocks specifically for Denmark (DK) and Sweden (SE)
- **Formatted Output**: Clean, tabular display of results with summary statistics
- **Error Handling**: Robust error handling for network issues and file corruption

## How It Works

1. **Local File Check**: Checks if a local copy of `haproxy_geo_ip.txt` exists and gets its modification time
2. **Conditional Download**: Sends an HTTP request with `If-Modified-Since` header to only download if the remote file is newer
3. **Integrity Verification**: Downloads and verifies the SHA256 checksum for any newly fetched files
4. **Data Processing**: Parses the file to extract CIDR blocks with country codes "DK" or "SE"
5. **Results Display**: Shows formatted results with summary statistics

## Prerequisites

- Rust 1.70+ (2021 edition)
- Internet connection for initial download

## Installation

1. Clone or create a new Rust project:
```bash
cargo new ip-geolocation-fetcher
cd ip-geolocation-fetcher
```

2. Replace the contents of `Cargo.toml` with:
```toml
[package]
name = "ip-geolocation-fetcher"
version = "0.1.0"
edition = "2021"

[dependencies]
reqwest = { version = "0.11", features = ["blocking"] }
sha2 = "0.10"
tokio = { version = "1", features = ["full"] }
httpdate = "1.0"
```

3. Replace `src/main.rs` with the provided source code

4. Build the application:
```bash
cargo build --release
```

## Usage

Simply run the application:
```bash
cargo run
```

Or run the compiled binary:
```bash
./target/release/ip-geolocation-fetcher
```

## Sample Output

```
Fetching IP geolocation data from: https://wetmore.ca/ip/haproxy_geo_ip.txt
New version of the file found, downloading...
Verifying integrity with SHA256 from: https://wetmore.ca/ip/haproxy_geo_ip.sha256
SHA256 verification successful!
Local file updated.

CIDR blocks for Denmark (DK) and Sweden (SE):
CIDR Block           Country Code
-----------------------------------
5.44.64.0/19         DK
5.45.96.0/19         DK
5.103.128.0/19       SE
5.135.0.0/16         SE
...

Summary:
Denmark (DK) CIDR blocks: 245
Sweden (SE) CIDR blocks: 312
Total matching blocks: 557
```

## Data Source

- **Primary Data**: https://wetmore.ca/ip/haproxy_geo_ip.txt
- **SHA256 Checksum**: https://wetmore.ca/ip/haproxy_geo_ip.sha256

The data file contains two columns:
1. **CIDR Block**: IP address range in CIDR notation
2. **Country Code**: Two-letter ISO country code

## File Structure

```
.
â”œâ”€â”€ Cargo.toml
â”œâ”€â”€ src/
â”‚   â””â”€â”€ main.rs
â”œâ”€â”€ haproxy_geo_ip.txt  # Cached data file (created after first run)
â””â”€â”€ README.md
```

## Dependencies

- **reqwest**: HTTP client for fetching remote files
- **sha2**: SHA-256 hashing for integrity verification
- **tokio**: Async runtime for efficient I/O operations
- **httpdate**: HTTP date parsing for conditional requests

## Error Handling

The application handles several error conditions:

- **Network failures**: Connection timeouts, DNS resolution issues
- **HTTP errors**: 404, 500, and other HTTP status codes
- **Checksum mismatches**: Corrupted downloads are detected and rejected
- **File I/O errors**: Permission issues, disk space problems

## Performance

- **Bandwidth Efficient**: Only downloads when files are updated
- **Fast Processing**: Async I/O for network operations
- **Memory Efficient**: Streams file processing without loading entire file into memory

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Changelog

### v0.1.0
- Initial release
- Basic file fetching and SHA256 verification
- Country code filtering for DK and SE
- Conditional downloading with caching

