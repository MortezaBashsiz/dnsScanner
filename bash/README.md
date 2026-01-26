# DNS Scanner - Bash Version

A high-performance DNS scanner written in pure Bash that can scan millions of IP addresses to find working DNS servers. Uses GNU Parallel for concurrent processing.

![Bash](https://img.shields.io/badge/bash-4.0+-green.svg)
![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS-lightgrey.svg)
![License](https://img.shields.io/badge/license-MIT-blue.svg)

## ✨ Features

- ⚡ **High Performance** - Leverages GNU Parallel for concurrent scanning
- 🔍 **Multiple DNS Types** - Supports A, AAAA, MX, TXT, NS, and more
- 🎲 **Random Subdomain Support** - Avoid cached DNS responses
- 📊 **Real-time Progress** - Visual progress tracking during scan
- 💾 **Result Export** - Saves working DNS servers to file
- 🔧 **Pure Bash** - No Python or heavy dependencies
- 🚀 **CIDR Support** - Scans entire subnets from CIDR notation
- 📁 **Batch Processing** - Process multiple IP ranges efficiently

## 📋 Requirements

You have to install the following packages:

| Package | Description | Link |
|---------|-------------|------|
| **getopt** | Command-line option parsing | [Documentation](https://linux.die.net/man/3/getopt) |
| **jq** | JSON processor | [Website](https://stedolan.github.io/jq/) |
| **git** | Version control | [Website](https://git-scm.com/) |
| **tput** | Terminal control | [Documentation](https://command-not-found.com/tput) |
| **bc** | Calculator for Bash | [GNU BC](https://www.gnu.org/software/bc/) |
| **curl** | HTTP client | [Website](https://curl.se/download.html) |
| **parallel** | GNU Parallel (version > 20220515) | [Website](https://www.gnu.org/software/parallel/) |
| **shuf** | Shuffle lines | [GNU Coreutils](https://www.gnu.org/software/coreutils/) |
| **dig** | DNS lookup utility | [Documentation](https://linux.die.net/man/1/dig) |

### System Requirements

- **OS**: Linux or macOS
- **Bash**: Version 4.0 or higher
- **Memory**: Depends on concurrency level
- **Network**: Stable internet connection

## 🚀 Installation

### 1. Clone the Repository

```bash
git clone https://github.com/MortezaBashsiz/dnsScanner.git
```

### 2. Change Directory and Make Executable

```bash
cd dnsScanner/bash
chmod +x ./dnsScanner.sh ./install_requirements.sh
```

### 3. Install Requirements (Recommended)

The script will attempt to install missing dependencies:

```bash
./install_requirements.sh
```

This will check and install (if needed):
- GNU Parallel
- dig (dnsutils)
- jq
- bc
- Other required utilities

### Manual Installation

**Debian/Ubuntu:**
```bash
sudo apt-get update
sudo apt-get install parallel dnsutils jq bc coreutils curl git
```

**RHEL/CentOS/Fedora:**
```bash
sudo yum install parallel bind-utils jq bc coreutils curl git
```

**macOS (Homebrew):**
```bash
brew install parallel bind jq bc coreutils curl git
```

## 💻 Usage

### Basic Syntax

```bash
./dnsScanner.sh -h
```

```
Usage: dnsScanner
    [ -p|--thread <int> ]          # Number of parallel threads
    [ -f|--file <string> ]         # CIDR file path
    [ -d|--domain <string> ]       # Domain to query
    [ -t|--type <string> ]         # DNS record type (A, AAAA, MX, TXT, NS)
    [ -r|--random-subdomain ]      # Add random subdomain prefix
    [ -h|--help ]                  # Show this help message
```

### Examples

#### Basic Scan (A Records)

```bash
./dnsScanner.sh -p 80 -f iran-ipv4.cidrs -d nic.ir
```

This will:
- Use 80 parallel threads
- Scan IPs from `iran-ipv4.cidrs`
- Query for A records of `nic.ir`

#### Different DNS Type (NS Records)

```bash
./dnsScanner.sh -p 80 -f iran-ipv4.cidrs -d nic.ir -t NS
```

Query for NS (nameserver) records instead of A records.

#### Avoid Cached DNS Responses

```bash
./dnsScanner.sh -p 80 -f iran-ipv4.cidrs -d example.com -t TXT -r
```

> **Note**: `-r/--random-subdomain` is intended to be used with a **wildcard DNS record** (e.g., `*.example.com`) so all random subdomains resolve.

The `-r` flag adds a random prefix like: `a1b2c3d4.example.com`

#### High Concurrency Scan

```bash
./dnsScanner.sh -p 200 -f large-subnet.cidrs -d google.com
```

Use 200 parallel threads for faster scanning of large IP ranges.

## 📁 CIDR File Format

Create a text file with one CIDR range per line:

```
# Iran IPv4 Addresses
# Comments start with #

1.1.1.0/24
8.8.8.0/24
178.22.122.0/24
185.51.200.0/22
```

### Getting Country IP Ranges

**IPv4 Addresses:**
- https://www.ipdeny.com/ipblocks/data/aggregated/

**IPv6 Addresses:**
- https://www.ipdeny.com/ipv6/ipaddresses/aggregated/

**Example - Download Iran IP ranges:**
```bash
wget https://www.ipdeny.com/ipblocks/data/aggregated/ir-aggregated.zone -O iran-ipv4.cidrs
```

## 📊 Output

### Console Output

The scanner provides real-time feedback:
```
[INFO] Starting DNS scan...
[INFO] Total IPs to scan: 254000
[PROGRESS] ████████████░░░░░░░░ 60%
[SUCCESS] Found DNS: 178.22.122.5 (45ms)
[SUCCESS] Found DNS: 185.51.200.2 (67ms)
```

### Results File

Working DNS servers are saved to a results file:
```
results_TIMESTAMP.txt
```

Example content:
```
# DNS Scan Results
# Date: 2026-01-26 10:30:45
# Domain: google.com
# Type: A
# Total Found: 42

178.22.122.5
185.51.200.2
8.8.8.8
1.1.1.1
```

## ⚙️ Configuration

### Parallel Threads

Adjust based on your system:

- **Low (10-50)**: Conservative, slower systems
- **Medium (50-100)**: Balanced performance
- **High (100-200)**: Fast scanning, good hardware
- **Very High (200+)**: Maximum speed, requires powerful system

### DNS Types Supported

- **A**: IPv4 address
- **AAAA**: IPv6 address
- **MX**: Mail exchange
- **TXT**: Text records
- **NS**: Nameserver
- **CNAME**: Canonical name
- **SOA**: Start of authority
- **PTR**: Pointer record

## 🔍 How It Works

1. **Parse CIDR Ranges**: Converts CIDR notation to individual IPs
2. **Shuffle IPs**: Randomizes scan order to distribute load
3. **Parallel Processing**: Uses GNU Parallel for concurrent DNS queries
4. **DNS Query**: Uses `dig` to query each IP
5. **Filter Results**: Validates responses and filters working DNS servers
6. **Save Output**: Writes results to file

### DNS Detection

The script identifies working DNS servers by:
- Checking for successful DNS responses
- Validating response codes
- Measuring query response time
- Filtering out timeouts and errors

## 📈 Performance

Typical performance metrics:

| IP Count | Threads | Estimated Time |
|----------|---------|----------------|
| 1,000    | 50      | 30 seconds     |
| 10,000   | 100     | 3-5 minutes    |
| 100,000  | 150     | 20-30 minutes  |
| 1,000,000| 200     | 2-4 hours      |

*Times vary based on network speed and system resources*

## 🐛 Troubleshooting

### "parallel: command not found"

```bash
# Install GNU Parallel
sudo apt-get install parallel   # Debian/Ubuntu
sudo yum install parallel        # RHEL/CentOS
brew install parallel            # macOS
```

### "dig: command not found"

```bash
# Install dig utility
sudo apt-get install dnsutils    # Debian/Ubuntu
sudo yum install bind-utils      # RHEL/CentOS
brew install bind                # macOS
```

### Slow Performance

- Reduce thread count (`-p` option)
- Check network bandwidth
- Use smaller CIDR ranges
- Verify system resources (CPU, memory)

### Permission Denied

```bash
chmod +x ./dnsScanner.sh
```

### Script Errors

Check Bash version:
```bash
bash --version   # Should be 4.0 or higher
```

## 📝 Advanced Usage

### Custom Output File

Modify the script to specify output location:
```bash
# Edit dnsScanner.sh
OUTPUT_FILE="my_dns_results.txt"
```

### Filtering by Response Time

You can modify the script to only save fast DNS servers:
```bash
# Add time threshold in the filtering section
if [ $RESPONSE_TIME -lt 100 ]; then
    echo $IP >> results.txt
fi
```

### Integration with Other Tools

Pipe results to other commands:
```bash
./dnsScanner.sh -p 80 -f iran.cidrs -d google.com | grep "178\."
```

## 🤝 Contributing

Contributions are welcome! Areas for improvement:

- IPv6 support enhancement
- Additional DNS record types
- Performance optimizations
- Better error handling
- Progress bar improvements

## 📄 License

This project is licensed under the MIT License.

## 👨‍💻 Author

**Morteza Bashsiz**
- Email: morteza.bashsiz@gmail.com
- GitHub: [@MortezaBashsiz](https://github.com/MortezaBashsiz)

## 🙏 Acknowledgments

- GNU Parallel for efficient concurrent processing
- ISC BIND utilities for DNS functionality
- The open-source community

## 📚 Additional Resources

- [GNU Parallel Tutorial](https://www.gnu.org/software/parallel/parallel_tutorial.html)
- [dig Command Guide](https://linux.die.net/man/1/dig)
- [CIDR Notation Explained](https://en.wikipedia.org/wiki/Classless_Inter-Domain_Routing)

---

**Happy Scanning! 🚀**

