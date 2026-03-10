# DNS Scanner - Python TUI Version

A modern, high-performance DNS scanner with a beautiful Terminal User Interface (TUI) built with Textual. This tool can scan millions of IP addresses to find working DNS servers with optional Slipstream proxy testing and automatic multi-platform client download.

![Python](https://img.shields.io/badge/python-3.11+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)

> [!TIP]
> If you cannot install Python dependencies on your system, you can download the **portable prebuilt binaries** for **Linux** and **macOS** from the **latest release** and use them directly without installing any additional requirements.
>
> **Latest release:** [Download portable builds](https://github.com/MortezaBashsiz/dnsScanner/releases/latest)


## ✨ Features

- 🎨 **Beautiful TUI Interface** - Modern Dracula-themed terminal interface
- ⚡ **High Performance** - Asynchronous scanning with configurable concurrency
- ⏸️ **Pause/Resume Support** - Pause and resume scans at any time without losing progress
- 📊 **Real-time Statistics** - Live progress tracking and scan metrics
- 🔍 **Smart DNS Detection** - Detects working DNS servers even with error responses (NXDOMAIN, NODATA)
- 🎲 **Random Subdomain Support** - Avoid cached responses with random subdomains
- 🌐 **Multiple DNS Types** - Supports A, AAAA, MX, TXT, NS records
- 🔌 **Slipstream Integration** - Optional proxy testing with parallel execution
- 🌍 **Multi-Platform Auto-Download** - Automatically downloads correct Slipstream client for your platform
- 📥 **Resume Downloads** - Smart download resume on network interruptions with retry logic
- 💾 **Auto-save Results** - Automatic JSON export of scan results
- 📁 **File Browser** - Built-in file picker for CIDR files
- ⚙️ **Configurable** - Adjustable concurrency, timeouts, and filters
- 🚀 **Memory Efficient** - Streaming IP generation without loading all IPs into memory
- 📝 **Optional Logging** - Disabled by default, easy to enable for troubleshooting

## 📋 Requirements

### Python Version
- Python 3.11 or higher

### Dependencies

```bash
# Core dependencies
textual>=0.47.0       # TUI framework
aiodns>=3.1.0         # Async DNS resolver
httpx[socks]>=0.25.0  # HTTP client with SOCKS5 support for proxy testing
orjson>=3.9.0         # Fast JSON serialization
loguru>=0.7.0         # Advanced logging
pyperclip>=1.8.0      # Clipboard support
```

### Optional
- **Slipstream Client** - For proxy testing functionality
  - **Automatic Download**: The application automatically detects your platform and downloads the correct client
  - **Smart Detection**: Detects existing installations (including legacy filenames)
  - **Resume Support**: Partial downloads are saved and can be resumed on retry
  - Supported platforms:
    - Linux (x86_64): `slipstream-client-linux-amd64`
    - Windows (x86_64): `slipstream-client-windows-amd64.exe`
    - macOS (ARM64): `slipstream-client-darwin-arm64`
    - macOS (Intel): `slipstream-client-darwin-amd64`
  - Manual download available from: [slipstream-rust-deploy releases](https://github.com/AliRezaBeigy/slipstream-rust-deploy/releases/latest)

## 🚀 Installation

### 1. Clone the Repository

```bash
git clone https://github.com/MortezaBashsiz/dnsScanner.git
cd dnsScanner/python
```

### 2. Install Python Dependencies

#### Option A: Using uv (Recommended - Fast!)

[uv](https://github.com/astral-sh/uv) is an extremely fast Python package installer and resolver, written in Rust.

```bash
# Install uv (if not already installed)
curl -LsSf https://astral.sh/uv/install.sh | sh

# Install dependencies with uv
uv pip install -r requirements.txt

# Or install directly
uv pip install textual aiodns httpx orjson loguru pyperclip
```

#### Option B: Using pip with requirements file
```bash
pip install -r requirements.txt
```

#### Option C: Using pip directly
```bash
pip install textual aiodns httpx[socks] orjson loguru pyperclip
```

#### Option D: Using Runflare Mirror (For Servers with Limited Access)

If you're on a server with restricted access to PyPI, use [Runflare](https://runflare.com/) mirror:

```bash
# Using Runflare as pip index
pip install -r requirements.txt -i https://pip.runflare.com/simple/ --trusted-host pip.runflare.com

# Or install directly
pip install textual aiodns httpx[socks] orjson loguru pyperclip -i https://pip.runflare.com/simple/ --trusted-host pip.runflare.com
```

#### Option E: Using conda
```bash
conda create -n dnsscanner python=3.11
conda activate dnsscanner
pip install -r requirements.txt
```

#### Option F: Using uv with virtual environment
```bash
# Create and activate venv with uv
uv venv
source .venv/bin/activate  # On Linux/macOS
# or
.venv\Scripts\activate  # On Windows

# Install dependencies
uv pip install -r requirements.txt
```

### 3. (Optional) Slipstream Auto-Download

**No manual setup required!** When you enable Slipstream testing in the UI for the first time:

1. The application automatically detects your platform (Windows/Linux/macOS and architecture)
2. Downloads the correct Slipstream client from GitHub
3. Shows download progress with visual progress bar
4. Supports resume if download is interrupted (slow/unstable internet)
5. Retries up to 5 times with exponential backoff
6. Saves partial downloads for future resume

**Supported Platforms:**
- ✅ Windows (AMD64)
- ✅ Linux (x86_64)
- ✅ macOS Apple Silicon (ARM64)
- ✅ macOS Intel (x86_64)

**Legacy Support:**
- Automatically detects existing `slipstream-client.exe` installations
- No need to re-download if you already have it

**Manual Download (Optional):**

If you prefer to download manually or have network restrictions:

```bash
# Windows (AMD64)
mkdir slipstream-client\windows
# Download: https://github.com/AliRezaBeigy/slipstream-rust-deploy/releases/latest/download/slipstream-client-windows-amd64.exe
# Or use your existing slipstream-client.exe

# Linux (x86_64)
mkdir -p slipstream-client/linux
# Download: https://github.com/AliRezaBeigy/slipstream-rust-deploy/releases/latest/download/slipstream-client-linux-amd64
chmod +x slipstream-client/linux/slipstream-client-linux-amd64

# macOS (Apple Silicon / ARM64)
mkdir -p slipstream-client/macos
# Download: https://github.com/AliRezaBeigy/slipstream-rust-deploy/releases/latest/download/slipstream-client-darwin-arm64
chmod +x slipstream-client/macos/slipstream-client-darwin-arm64

# macOS (Intel / x86_64)
mkdir -p slipstream-client/macos
# Download: https://github.com/AliRezaBeigy/slipstream-rust-deploy/releases/latest/download/slipstream-client-darwin-amd64
chmod +x slipstream-client/macos/slipstream-client-darwin-amd64
```

## 💻 Usage

### Basic Usage

```bash
python dnsscanner_tui.py
```

This will launch the interactive TUI where you can configure:
- **CIDR File**: Path to file containing IP ranges (CIDR notation)
- **Domain**: Domain to query (e.g., google.com)
- **DNS Type**: Record type (A, AAAA, MX, TXT, NS)
- **Concurrency**: Number of parallel workers (default: 100)
- **Random Subdomain**: Add random prefix to avoid cached responses
- **Slipstream Test**: Enable proxy testing for found DNS servers

### CIDR File Format

Create a text file with one CIDR range per line:

```
# Comments start with #
1.1.1.0/24
8.8.8.0/24
178.22.122.0/24
185.51.200.0/22
```

### Example Workflow

1. **Launch the application**:
   ```bash
   python dnsscanner_tui.py
   ```

2. **Configure scan parameters**:
   - Click "📂 Browse" to select your CIDR file
   - Enter domain (e.g., `google.com`)
   - Set concurrency (recommended: 100-500)
   - Enable options as needed

3. **Start scanning**:
   - Click "🚀 Start Scan"
   - Watch real-time progress and results
   - Use "⏸ Pause" to pause the scan at any time
   - Use "▶ Resume" to continue from where you paused

4. **View results**:
   - Sorted by response time (fastest first)
   - Green = fast (<100ms)
   - Yellow = medium (100-300ms)
   - Red = slow (>300ms)

5. **Save results**:
   - Results are auto-saved to `results/dns_scan_TIMESTAMP.json`
   - Press `s` or click "💾 Save Results" to save manually

## ⌨️ Keyboard Shortcuts

- `q` - Quit the application
- `s` - Save current results

## 🎮 Control Buttons

During an active scan:
- **⏸ Pause** - Pause the scan without losing progress
- **▶ Resume** - Continue scanning from where you paused
- **💾 Save Results** - Manually save current results
- **🛑 Quit** - Exit the application

## 🎛️ Configuration

### Logging

Logging is **disabled by default** to keep the interface clean and avoid unnecessary disk writes.

**To enable logging**, edit `dnsscanner_tui.py`:

```python
# Configure logging (disabled by default)
logger.remove()  # Remove default handler to disable logging
# Uncomment the line below to enable file logging
logger.add(
    "logs/dnsscanner_{time}.log",
    rotation="50 MB",
    compression="zip",
    level="DEBUG",
)
```

When enabled:
- Logs are saved to `logs/dnsscanner_TIMESTAMP.log`
- Auto-rotate at 50 MB
- Compressed automatically (zip)
- Includes DEBUG level details

### Concurrency Settings

Adjust based on your system and network:

- **Low (50-100)**: Conservative, suitable for slower systems
- **Medium (100-300)**: Balanced performance
- **High (300-500)**: Fast scanning, requires good hardware
- **Very High (500+)**: Maximum speed, may hit resource limits

### Slipstream Testing

The scanner supports parallel Slipstream proxy testing with automatic download:

```python
# In __init__ method
self.slipstream_max_concurrent = 3  # Max parallel proxy tests
self.slipstream_base_port = 10800   # Base port (uses 10800, 10801, 10802)
```

**Auto-Download Features:**
- Platform detection (Windows/Linux/macOS + architecture)
- Progress bar with download speed
- Resume on interruption (keeps `.partial` files)
- Retry with exponential backoff (up to 5 attempts)
- Legacy filename detection (`slipstream-client.exe`)

### DNS Timeout

DNS queries timeout after 2 seconds:

```python
# In _test_dns method
resolver = aiodns.DNSResolver(nameservers=[ip], timeout=2.0, tries=1)
```

## 📊 Output Format

Results are saved in JSON format:

```json
{
  "scan_time": "2026-01-26T10:30:45",
  "domain": "google.com",
  "dns_type": "A",
  "concurrency": 100,
  "total_scanned": 50000,
  "total_found": 42,
  "servers": [
    {
      "ip": "8.8.8.8",
      "response_time_ms": 45.2,
      "status": "Active",
      "proxy_test": "Success"
    }
  ]
}
```

## 🔍 How It Works

### DNS Detection Logic

The scanner considers a server as "working DNS" if:

1. **Successful Response**: Returns valid DNS answer in <2s
2. **DNS Error Responses**: Returns NXDOMAIN, NODATA, or NXRRSET in <2s
   - These errors mean the DNS server IS working, just the record doesn't exist

This approach catches more working DNS servers than tools that only accept successful responses.

### Performance Optimizations

- **Streaming IP Generation**: IPs are generated on-the-fly from CIDR ranges
- **Chunked Processing**: Processes IPs in batches of 500
- **Async I/O**: Non-blocking DNS queries using aiodns
- **Semaphore Control**: Limits concurrent operations to prevent resource exhaustion
- **Memory Mapping**: Fast CIDR file reading using mmap when possible

### Random Subdomain Feature

When enabled, queries use random prefixes:
```
original: google.com
random:   a1b2c3d4.google.com
```

**Use case**: Bypass cached DNS responses
**Requirement**: Target domain should have wildcard DNS (`*.example.com`)

## 📂 Directory Structure

```
python/
├── dnsscanner_tui.py          # Main application
├── README.md                   # This file
├── requirements.txt            # Python dependencies
├── iran-ipv4.cidrs            # Sample CIDR file
├── logs/                       # Application logs (when enabled)
│   └── dnsscanner_*.log
├── results/                    # Scan results (auto-created)
│   └── dns_scan_*.json
└── slipstream-client/          # Slipstream binaries (auto-downloaded)
    ├── windows/
    │   ├── slipstream-client-windows-amd64.exe  # Windows AMD64
    │   └── slipstream-client.exe                # Legacy (auto-detected)
    ├── linux/
    │   └── slipstream-client-linux-amd64        # Linux x86_64
    └── macos/
        ├── slipstream-client-darwin-arm64       # Apple Silicon (ARM64)
        └── slipstream-client-darwin-amd64       # Intel (x86_64)
```

## 🐛 Troubleshooting

### "No module named 'textual'"
```bash
pip install textual
```

### "File not found" error
- Ensure CIDR file path is correct
- Use absolute path or relative path from script location
- Use the built-in file browser (📂 Browse button)

### Slow scanning
- Reduce concurrency value
- Check network bandwidth
- Verify DNS timeout settings

### High memory usage
- The scanner uses streaming to minimize memory
- If issues persist, reduce chunk size in `_stream_ips_from_file`

### Slipstream download fails
- **Network issues**: The app automatically retries up to 5 times with exponential backoff
- **Resume**: Partial downloads are saved as `.partial` files - just run again to resume
- **Manual download**: Download from [slipstream-rust-deploy releases](https://github.com/AliRezaBeigy/slipstream-rust-deploy/releases/latest)
- **Check logs**: Enable logging (see Configuration section) for detailed error info
- **Firewall**: Ensure GitHub access is allowed

### Slipstream not detected
- Check platform-specific directory exists (`slipstream-client/windows/`, etc.)
- Verify filename matches (supports both new and legacy names)
- For legacy installs: Use `slipstream-client.exe` (auto-detected)
- Enable logging to see detection process

### Slipstream tests fail
- Verify executable has correct permissions (Linux/macOS: `chmod +x`)
- Check that ports 10800-10802 are available
- Review logs (if enabled) in `logs/` directory
- Test connectivity to DNS servers manually

## 📝 Logging

**Default: Disabled** - No logs are created to keep your system clean.

**To Enable Logging:**

1. Edit `dnsscanner_tui.py`
2. Uncomment the `logger.add()` section
3. Logs saved to `logs/dnsscanner_TIMESTAMP.log`

**Log Levels:**
- **DEBUG**: Detailed DNS query results, download progress
- **INFO**: Scan progress and statistics
- **WARNING**: Non-critical issues, retry attempts
- **ERROR**: Critical failures, download errors

**Features when enabled:**
- Auto-rotation at 50 MB
- Automatic compression (zip)
- Timestamped filenames
- No performance impact on scanning

## 🌍 Finding CIDR Lists

### Country IP Ranges

**IPv4**:
- https://www.ipdeny.com/ipblocks/data/aggregated/

**IPv6**:
- https://www.ipdeny.com/ipv6/ipaddresses/aggregated/

### Usage Example
```bash
# Download Iran IPv4 ranges
wget https://www.ipdeny.com/ipblocks/data/aggregated/ir-aggregated.zone -O iran-ipv4.cidrs

# Use in scanner
python dnsscanner_tui.py
# Then select iran-ipv4.cidrs in the file browser
```

## 🤝 Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues.

### Development Setup
```bash
git clone https://github.com/MortezaBashsiz/dnsScanner.git
cd dnsScanner/python
pip install -r requirements.txt
python dnsscanner_tui.py
```

## 📄 License

This project is licensed under the MIT License.

## 🙏 Acknowledgments

- Built with [Textual](https://github.com/Textualize/textual) by Textualize
- DNS resolution via [aiodns](https://github.com/saghul/aiodns)
- Inspired by the need for efficient DNS server discovery

## 📈 Performance Notes

Tested performance on various systems:

- **Small scan** (1,000 IPs): ~10-30 seconds
- **Medium scan** (50,000 IPs): ~5-10 minutes
- **Large scan** (1M+ IPs): ~1-3 hours

*Results vary based on network speed, concurrency settings, and system resources.*

## 🔐 Security Considerations

- Uses cryptographically secure random number generator (`secrets.SystemRandom`)
- No credentials or sensitive data are logged
- DNS queries are standard UDP/TCP port 53
- Slipstream proxy testing is optional and disabled by default

---

**Happy Scanning! 🚀**
