# DNS Scanner - Python TUI Version

A modern, high-performance DNS scanner with a beautiful Terminal User Interface (TUI) built with Textual. This tool can scan millions of IP addresses to find working DNS servers with optional Slipstream proxy testing.

![Python](https://img.shields.io/badge/python-3.13+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)

## ✨ Features

- 🎨 **Beautiful TUI Interface** - Modern Dracula-themed terminal interface
- ⚡ **High Performance** - Asynchronous scanning with configurable concurrency
- 📊 **Real-time Statistics** - Live progress tracking and scan metrics
- 🔍 **Smart DNS Detection** - Detects working DNS servers even with error responses (NXDOMAIN, NODATA)
- 🎲 **Random Subdomain Support** - Avoid cached responses with random subdomains
- 🌐 **Multiple DNS Types** - Supports A, AAAA, MX, TXT, NS records
- 🔌 **Slipstream Integration** - Optional proxy testing with parallel execution
- 💾 **Auto-save Results** - Automatic JSON export of scan results
- 📁 **File Browser** - Built-in file picker for CIDR files
- ⚙️ **Configurable** - Adjustable concurrency, timeouts, and filters
- 🚀 **Memory Efficient** - Streaming IP generation without loading all IPs into memory

## 📋 Requirements

### Python Version
- Python 3.8 or higher

### Dependencies

```bash
# Core dependencies
textual>=0.47.0       # TUI framework
aiodns>=3.1.0         # Async DNS resolver
httpx>=0.25.0         # HTTP client for proxy testing
orjson>=3.9.0         # Fast JSON serialization
loguru>=0.7.0         # Advanced logging
pyperclip>=1.8.0      # Clipboard support
```

### Optional
- **Slipstream Client** - For proxy testing functionality
  - Place `slipstream-client.exe` in `slipstream-client/windows/` directory
  - Or configure custom path in the code

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
pip install textual aiodns httpx orjson loguru pyperclip
```

#### Option D: Using conda
```bash
conda create -n dnsscanner python=3.11
conda activate dnsscanner
pip install -r requirements.txt
```

#### Option E: Using uv with virtual environment
```bash
# Create and activate venv with uv
uv venv
source .venv/bin/activate  # On Linux/macOS
# or
.venv\Scripts\activate  # On Windows

# Install dependencies
uv pip install -r requirements.txt
```

### 3. (Optional) Setup Slipstream

If you want to use the proxy testing feature:

```bash
# Windows
mkdir -p slipstream-client/windows
# Place slipstream-client.exe in the windows folder

# Linux
mkdir -p slipstream-client/linux
# Place slipstream-client binary in the linux folder
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

## 🎛️ Configuration

### Concurrency Settings

Adjust based on your system and network:

- **Low (50-100)**: Conservative, suitable for slower systems
- **Medium (100-300)**: Balanced performance
- **High (300-500)**: Fast scanning, requires good hardware
- **Very High (500+)**: Maximum speed, may hit resource limits

### Slipstream Testing

The scanner supports parallel Slipstream proxy testing:

```python
# In __init__ method
self.slipstream_max_concurrent = 3  # Max parallel proxy tests
self.slipstream_base_port = 10800   # Base port (uses 10800, 10801, 10802)
```

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
├── logs/                       # Application logs (auto-created)
│   └── dnsscanner_*.log
├── results/                    # Scan results (auto-created)
│   └── dns_scan_*.json
└── slipstream-client/          # Optional proxy client
    └── windows/
        └── slipstream-client.exe
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

### Slipstream tests fail
- Verify slipstream-client.exe exists in correct path
- Check that ports 10800-10802 are available
- Review logs in `logs/` directory

## 📝 Logging

Logs are automatically saved to `logs/dnsscanner_TIMESTAMP.log`:

- **DEBUG**: Detailed DNS query results
- **INFO**: Scan progress and statistics
- **WARNING**: Non-critical issues
- **ERROR**: Critical failures

Logs rotate at 50 MB and are compressed automatically.

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

## 👨‍💻 Author

**Morteza Bashsiz**
- Email: morteza.bashsiz@gmail.com
- GitHub: [@MortezaBashsiz](https://github.com/MortezaBashsiz)

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
