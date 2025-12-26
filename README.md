# DuckDB PCAP Extension

A high-performance DuckDB extension to query `.pcap` and `.pcapng` files using SQL. This extension allows you to analyze network traffic with the speed of DuckDB, featuring native BPF (Berkeley Packet Filter) pushdown for efficient data loading.

## Features

* **Direct PCAP Scanning**: Read packets directly into DuckDB relations.
* **BPF Pushdown**: Filters like `src_port = 80` are converted into BPF bytecode and applied at the `libpcap` level, significantly reducing IO and processing time.
* **VLAN Support**: Automatically detects and parses 802.1Q tagged frames.
* **IPv4 & IPv6**: Supports both address families.
* **TCP/UDP Metadata**: Extracts ports, TCP sequence numbers, flags, and window sizes.

## Installation

### Prerequisites

* `libpcap-dev` (Linux) or `libpcap` (macOS via Homebrew)
* DuckDB development headers

### Build

To build the extension, use the standard DuckDB extension build process:

```bash
make

```

## Usage

Once loaded, you can use the `read_pcap_packets` table function.

```sql
INSTALL pcap_duckdb from community;
LOAD pcap_duckdb;

-- Count packets from a specific IP
SELECT count(*) 
FROM read_pcap_packets('capture.pcap') 
WHERE src_ip = '192.168.1.10';

-- Analyze TCP flags for a specific port
SELECT tcp_flags, count(*)
FROM read_pcap_packets('traffic.pcap')
WHERE protocol = 'TCP' 
  AND dst_port = 443
GROUP BY ALL;

```

## Schema

The `read_pcap_packets` function returns the following columns:

| Column | Type | Description |
| --- | --- | --- |
| `ts` | TIMESTAMP | Packet arrival timestamp |
| `interface_id` | INTEGER | Interface index (if available) |
| `src_ip` | VARCHAR | Source IP address (IPv4 or IPv6) |
| `dst_ip` | VARCHAR | Destination IP address (IPv4 or IPv6) |
| `src_port` | INTEGER | TCP/UDP source port |
| `dst_port` | INTEGER | TCP/UDP destination port |
| `protocol` | VARCHAR | Protocol name (TCP, UDP, or OTHER) |
| `length` | INTEGER | Packet capture length |
| `tcp_flags` | INTEGER | Raw TCP flags |
| `tcp_seq` | BIGINT | TCP sequence number |
| `tcp_ack` | BIGINT | TCP acknowledgement number |
| `tcp_window` | INTEGER | TCP window size |

## Optimization: BPF Pushdown

This extension translates SQL `WHERE` clauses into BPF filters. For example:

```sql
SELECT * FROM read_pcap_packets('large.pcap') 
WHERE src_port IN (80, 443) AND protocol = 'TCP';

```

The extension automatically compiles `(src port 80 or src port 443) and (tcp or tcp6)` into the pcap handle. This ensures only relevant packets are ever moved from the pcap buffer into DuckDB's memory.

## Limitations

* Currently supports Ethernet-based PCAPs (DLT_EN10MB).
* Does not yet support full packet payload extraction (Raw bytes).
