## Requirements
You have to install the following packages:

[getopt](https://linux.die.net/man/3/getopt)<br>
[jq](https://stedolan.github.io/jq/)<br>
[git](https://git-scm.com/)<br>
[tput](https://command-not-found.com/tput)<br>
[bc](https://www.gnu.org/software/bc/)<br>
[curl](https://curl.se/download.html)<br>
[parallel (version > 20220515)](https://www.gnu.org/software/parallel/)<br>
[shuf](https://www.gnu.org/software/coreutils/)
[dig](https://linux.die.net/man/1/dig)

## How to run
### 1. clone

```shell
[~]>$ git clone https://github.com/MortezaBashsiz/dnsScanner.git
```

### 2. Change directory and make them executable

```shell
[~]>$ cd dnsScanner/bash
[~/dnsScanner/bash]> chmod +x ./dnsScanner.sh ./install_requirements.sh
```

### 3. Install requirements (recommended)

```shell
[~/dnsScanner/bash]> ./install_requirements.sh
```

### 4. Use it

```shell
[~/dnsScanner/bash]> ./dnsScanner.sh -h
Usage: dnsScanner
    [ -p|--thread <int> ]
    [ -f|--file <string> ]
    [ -d|--domain <string> ]
    [ -t|--type <string> ]
    [ -r|--random-subdomain ]
    [ -h|--help ]

```
Example
```shell
[~/dnsScanner/bash]> ./dnsScanner.sh -p 80 -f iran-ipv4.cidrs -d nic.ir
```

Example (different DNS type)

```shell
[~/dnsScanner/bash]> ./dnsScanner.sh -p 80 -f iran-ipv4.cidrs -d nic.ir -t NS
```

Example (avoid cached DNS responses)

> Note: `-r/--random-subdomain` is intended to be used with a **wildcard DNS record** (e.g. `*.example.com`) so all random subdomains resolve.

```shell
[~/dnsScanner/bash]> ./dnsScanner.sh -p 80 -f iran-ipv4.cidrs -d example.com -t TXT -r
```

To list countries IP addresses use following links

IPv4

https://www.ipdeny.com/ipblocks/data/aggregated/

IPv6

https://www.ipdeny.com/ipv6/ipaddresses/aggregated/

