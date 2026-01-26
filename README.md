# DNS Scanner

A high-performance DNS server discovery tool that can scan millions of IP addresses to identify working DNS resolvers. Available in both **Bash** (command-line) and **Python** (TUI) versions.

![License](https://img.shields.io/badge/license-MIT-green.svg)
![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows%20%7C%20macOS-lightgrey.svg)

## 🎯 Overview

DNS Scanner is a powerful tool designed to discover and test DNS servers across large IP ranges. Whether you need to find open resolvers, test DNS infrastructure, or build a list of working DNS servers, this tool provides fast and reliable scanning capabilities.

## 📦 Available Versions

### 🐚 Bash Version
**Best for**: Linux/macOS users, server environments, automation scripts

- Pure Bash implementation
- Leverages GNU Parallel for concurrency
- Lightweight and fast
- No Python dependencies
- Command-line interface

[📖 Bash Documentation](bash/README.md)

### 🐍 Python Version (TUI)
**Best for**: Interactive use, detailed monitoring, Windows/Linux/macOS

- Beautiful Terminal User Interface (Textual)
- Real-time statistics and progress tracking
- Slipstream proxy testing integration
- Modern and user-friendly
- Cross-platform support

[📖 Python Documentation](python/README.md)

## ✨ Key Features

### Common Features (Both Versions)
- ⚡ High-performance parallel scanning
- 🔍 Multiple DNS record types (A, AAAA, MX, TXT, NS)
- 🎲 Random subdomain support to avoid caching
- 📊 CIDR notation support for IP ranges
- 💾 Results export
- 🚀 Configurable concurrency

### Python TUI Exclusive
- 🎨 Beautiful Dracula-themed interface
- 📈 Real-time statistics dashboard
- 🔌 Slipstream proxy testing
- 📁 Built-in file browser
- 💡 Smart DNS detection (catches NXDOMAIN responses)
- 🔄 Auto-save with JSON export

### Bash Exclusive
- 🔧 Zero Python dependencies
- 📦 Minimal footprint
- 🖥️ Perfect for servers and automation
- 🔁 Easy to integrate with shell scripts

## 🚀 Quick Start

### Python Version

```bash
# Clone repository
git clone https://github.com/MortezaBashsiz/dnsScanner.git
cd dnsScanner/python

# Install dependencies (choose one method)
pip install -r requirements.txt
# OR use uv (faster)
uv pip install -r requirements.txt

# Run
python dnsscanner_tui.py
```

### Bash Version

```bash
# Clone repository
git clone https://github.com/MortezaBashsiz/dnsScanner.git
cd dnsScanner/bash

# Make executable and install requirements
chmod +x *.sh
./install_requirements.sh

# Run
./dnsScanner.sh -p 80 -f iran-ipv4.cidrs -d google.com
```

## 📋 Requirements

### Python Version
- Python 3.8+
- textual, aiodns, httpx, orjson, loguru, pyperclip

### Bash Version
- Bash 4.0+
- GNU Parallel, dig, jq, bc, curl, shuf

## 💻 Usage Examples

### Python TUI

```bash
# Launch interactive interface
python dnsscanner_tui.py

# Configure in UI:
# - Select CIDR file
# - Enter domain (e.g., google.com)
# - Set concurrency (100-500)
# - Enable options
# - Click "Start Scan"
```

### Bash CLI

```bash
# Basic scan
./dnsScanner.sh -p 80 -f iran-ipv4.cidrs -d nic.ir

# With different DNS type
./dnsScanner.sh -p 80 -f iran-ipv4.cidrs -d nic.ir -t NS

# With random subdomain (avoid cache)
./dnsScanner.sh -p 80 -f iran-ipv4.cidrs -d example.com -r

# High concurrency
./dnsScanner.sh -p 200 -f large-subnet.cidrs -d google.com
```

## 📁 CIDR File Format

Both versions use the same CIDR file format:

```
# Comments start with #
1.1.1.0/24
8.8.8.0/24
178.22.122.0/24
185.51.200.0/22
```

### Getting Country IP Ranges

**IPv4**: https://www.ipdeny.com/ipblocks/data/aggregated/
**IPv6**: https://www.ipdeny.com/ipv6/ipaddresses/aggregated/

```bash
# Example: Download Iran IPv4 ranges
wget https://www.ipdeny.com/ipblocks/data/aggregated/ir-aggregated.zone -O iran-ipv4.cidrs
```

## 📊 Performance Comparison

| Metric | Python TUI | Bash CLI |
|--------|------------|----------|
| **Startup** | ~2 seconds | Instant |
| **Memory** | ~50-100 MB | ~20-50 MB |
| **Concurrency** | 500+ | 200+ |
| **UI** | Rich TUI | Terminal output |
| **Platforms** | All | Linux/macOS |
| **Ease of Use** | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐ |

## 🎨 Screenshots

### Python TUI
```
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ 🔍 DNS Scanner Configuration               ┃
┃                                             ┃
┃ CIDR File:  [iran-ipv4.cidrs    ] 📂 Browse┃
┃ Domain:     [google.com                   ]┃
┃ DNS Type:   [A (IPv4)          ▼]          ┃
┃ Concurrency:[100                          ]┃
┃ [ ] Random Subdomain                        ┃
┃ [✓] Test with Slipstream                   ┃
┃                                             ┃
┃        🚀 Start Scan    🛑 Exit             ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
```

## 🔍 Use Cases

- **Security Research**: Find open DNS resolvers
- **Network Testing**: Validate DNS infrastructure
- **Performance Analysis**: Compare DNS response times
- **Proxy Testing**: Test DNS servers with Slipstream
- **Network Mapping**: Discover DNS servers in IP ranges
- **Automation**: Integrate into CI/CD pipelines (Bash version)

## 🐛 Troubleshooting

### Common Issues

**Python: Module not found**
```bash
pip install textual aiodns httpx orjson loguru pyperclip
```

**Bash: Command not found**
```bash
./install_requirements.sh  # Auto-install dependencies
```

**Slow performance**
- Reduce concurrency value
- Check network bandwidth
- Use smaller IP ranges for testing

**High memory usage (Python)**
- The streaming implementation minimizes memory
- Reduce concurrency if needed
- Close other applications

## 🤝 Contributing

Contributions welcome! Please feel free to submit Pull Requests.

### Development

```bash
# Clone and setup
git clone https://github.com/MortezaBashsiz/dnsScanner.git
cd dnsScanner

# For Python version
cd python
pip install -r requirements.txt

# For Bash version
cd bash
./install_requirements.sh
```

## 📄 License

MIT License - see LICENSE file for details

## 👨‍💻 Author

**Morteza Bashsiz**
- Email: morteza.bashsiz@gmail.com
- GitHub: [@MortezaBashsiz](https://github.com/MortezaBashsiz)

## 🙏 Acknowledgments

- [Textual](https://github.com/Textualize/textual) - Modern TUI framework
- [GNU Parallel](https://www.gnu.org/software/parallel/) - Parallel processing
- [aiodns](https://github.com/saghul/aiodns) - Async DNS resolver
- Open-source community

## 📚 Documentation

- [Python Version Documentation](python/README.md)
- [Bash Version Documentation](bash/README.md)

---

**Choose your version and start scanning! 🚀**

