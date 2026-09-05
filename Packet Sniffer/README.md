# Advanced Packet Sniffer + ARP Spoofing Detector

This is my internship project for monitoring local network traffic and detecting possible ARP spoofing attacks. It uses Python and Scapy for live packet capture, keeps a small IP-to-MAC memory, and raises alerts when the same IP suddenly appears with a different MAC address.

The tool is defensive only. It does not perform ARP spoofing.

## Main Features

- Live packet sniffing with Scapy
- ARP spoofing detection using learned and trusted IP/MAC mappings
- Gateway protection for detecting fake router replies
- Optional active ARP verification when an alert appears
- Offline PCAP analysis for network forensics
- JSONL alert logs, JSON session reports, and optional CSV summaries
- Known-host database with trust, remove, list, and export commands
- Protocol counters for ARP, IPv4, IPv6, TCP, UDP, ICMP, DNS, HTTP, and HTTPS
- Top talkers, top ports, DNS query summary, and HTTP host summary
- Demo mode so the project can be shown even without live capture permission

## Requirements

Install Python dependencies:

```bash
python -m pip install -r requirements.txt
```

For live sniffing on Windows, Npcap is also needed. During Npcap setup, enable **WinPcap API-compatible Mode**. Run the terminal as Administrator when capturing packets.

## First Setup

```bash
python packet_guard.py init
```

This creates the config, known host database, report folder, and PCAP folder.

## Useful Commands

Show network interfaces:

```bash
python packet_guard.py interfaces
```

Run a quick live capture:

```bash
python packet_guard.py sniff --count 100
```

If Windows says WinPcap is not installed, install/reinstall Npcap with WinPcap API-compatible mode enabled.

Watch a specific gateway:

```bash
python packet_guard.py sniff --gateway 192.168.1.1
```

Save captured packets for later:

```bash
python packet_guard.py sniff --count 200 --pcap --csv
```

Analyze a saved PCAP:

```bash
python packet_guard.py analyze pcaps/capture_20260704_101756.pcap --gateway 192.168.1.1
```

Run the built-in demonstration:

```bash
python packet_guard.py demo --csv
```

## Trusted Hosts

If the router IP and MAC are known, save them as trusted:

```bash
python packet_guard.py hosts trust 192.168.1.1 aa:bb:cc:dd:ee:01
```

List learned hosts:

```bash
python packet_guard.py hosts list
```

Export learned hosts:

```bash
python packet_guard.py hosts export
```

## How Detection Works

The program watches ARP packets and stores normal IP-to-MAC mappings. If a later ARP packet claims that the same IP belongs to a different MAC address, it creates an alert.

Severity is increased when:

- The changed IP is the gateway
- The IP/MAC pair is marked trusted
- The same IP changes MAC address many times in a short time

Reports are saved inside `sniffer_reports/`. Packet captures are saved inside `pcaps/` only when `--pcap` is used.

## Ethical Notice

Use this only on networks you own or have permission to monitor. Packet capture can expose private traffic and may be illegal or against policy in some places.
