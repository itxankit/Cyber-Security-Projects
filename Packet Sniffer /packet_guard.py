from __future__ import annotations

import argparse
import csv
import json
import sys
import time
from collections import Counter, deque
from dataclasses import asdict, dataclass, field
from datetime import datetime
from ipaddress import ip_address
from pathlib import Path
from types import SimpleNamespace
from typing import Any


APP_DIR = Path(__file__).resolve().parent
DATA_DIR = APP_DIR / "sniffer_data"
REPORT_DIR = APP_DIR / "sniffer_reports"
PCAP_DIR = APP_DIR / "pcaps"

CONFIG_FILE = DATA_DIR / "config.json"
KNOWN_HOSTS_FILE = DATA_DIR / "known_hosts.json"

DEFAULT_CONFIG = {
    "gateway_ip": "",
    "trusted_hosts": {},
    "ignored_macs": ["00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"],
    "auto_learn": True,
    "cooldown_seconds": 20,
    "burst_window_seconds": 180,
    "burst_change_limit": 3,
    "update_known_after_change": False,
}


def now_text() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def file_stamp() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def ensure_folders() -> None:
    DATA_DIR.mkdir(exist_ok=True)
    REPORT_DIR.mkdir(exist_ok=True)
    PCAP_DIR.mkdir(exist_ok=True)


def load_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return default


def save_json(path: Path, data: Any) -> None:
    path.parent.mkdir(exist_ok=True)
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def normalize_mac(value: str) -> str:
    cleaned = value.strip().lower().replace("-", ":")
    parts = cleaned.split(":")
    if len(parts) == 6:
        return ":".join(part.zfill(2) for part in parts)
    return cleaned


def clean_ip(value: str) -> str | None:
    try:
        return str(ip_address(value))
    except ValueError:
        return None


def load_config() -> dict[str, Any]:
    config = DEFAULT_CONFIG.copy()
    saved = load_json(CONFIG_FILE, {})
    if isinstance(saved, dict):
        config.update(saved)
    config["trusted_hosts"] = {
        clean_ip(ip) or ip: normalize_mac(mac)
        for ip, mac in config.get("trusted_hosts", {}).items()
        if ip and mac
    }
    config["ignored_macs"] = [normalize_mac(mac) for mac in config.get("ignored_macs", [])]
    if config.get("gateway_ip"):
        config["gateway_ip"] = clean_ip(config["gateway_ip"]) or config["gateway_ip"]
    return config


def save_config(config: dict[str, Any]) -> None:
    save_json(CONFIG_FILE, config)


def load_known_hosts(path: Path = KNOWN_HOSTS_FILE) -> dict[str, Any]:
    data = load_json(path, {"created_at": now_text(), "hosts": {}})
    data.setdefault("created_at", now_text())
    data.setdefault("hosts", {})
    return data


def load_scapy():
    try:
        from scapy.all import ARP, DNSQR, ICMP, IP, IPv6, Raw, TCP, UDP
        from scapy.all import Ether, PcapWriter, conf, get_if_list, rdpcap, sniff, srp
    except ImportError as exc:
        raise SystemExit(
            "Scapy is not installed. Install it with: python -m pip install -r requirements.txt"
        ) from exc

    return SimpleNamespace(
        ARP=ARP,
        DNSQR=DNSQR,
        ICMP=ICMP,
        IP=IP,
        IPv6=IPv6,
        Raw=Raw,
        TCP=TCP,
        UDP=UDP,
        Ether=Ether,
        PcapWriter=PcapWriter,
        conf=conf,
        get_if_list=get_if_list,
        rdpcap=rdpcap,
        sniff=sniff,
        srp=srp,
    )


@dataclass
class Alert:
    alert_id: str
    time: str
    severity: str
    title: str
    ip: str
    expected_mac: str
    observed_mac: str
    source: str
    reason: str
    details: dict[str, Any] = field(default_factory=dict)


@dataclass
class TrafficStats:
    started_at: str = field(default_factory=now_text)
    packets: int = 0
    arp: int = 0
    ipv4: int = 0
    ipv6: int = 0
    tcp: int = 0
    udp: int = 0
    icmp: int = 0
    dns: int = 0
    http: int = 0
    https: int = 0
    other: int = 0
    sources: Counter[str] = field(default_factory=Counter)
    destinations: Counter[str] = field(default_factory=Counter)
    ports: Counter[str] = field(default_factory=Counter)
    dns_queries: Counter[str] = field(default_factory=Counter)
    http_hosts: Counter[str] = field(default_factory=Counter)

    def update(self, packet: Any, scapy: Any) -> None:
        self.packets += 1
        matched = False

        if packet.haslayer(scapy.ARP):
            self.arp += 1
            matched = True

        if packet.haslayer(scapy.IP):
            ip_layer = packet[scapy.IP]
            self.ipv4 += 1
            self.sources[str(ip_layer.src)] += 1
            self.destinations[str(ip_layer.dst)] += 1
            matched = True

        if packet.haslayer(scapy.IPv6):
            ip6_layer = packet[scapy.IPv6]
            self.ipv6 += 1
            self.sources[str(ip6_layer.src)] += 1
            self.destinations[str(ip6_layer.dst)] += 1
            matched = True

        if packet.haslayer(scapy.TCP):
            tcp = packet[scapy.TCP]
            self.tcp += 1
            self.ports[str(int(tcp.dport))] += 1
            if int(tcp.dport) == 80 or int(tcp.sport) == 80:
                self.http += 1
                host = extract_http_host(packet, scapy)
                if host:
                    self.http_hosts[host] += 1
            if int(tcp.dport) == 443 or int(tcp.sport) == 443:
                self.https += 1
            matched = True

        if packet.haslayer(scapy.UDP):
            udp = packet[scapy.UDP]
            self.udp += 1
            self.ports[str(int(udp.dport))] += 1
            matched = True

        if packet.haslayer(scapy.ICMP):
            self.icmp += 1
            matched = True

        if packet.haslayer(scapy.DNSQR):
            self.dns += 1
            qname = packet[scapy.DNSQR].qname
            if isinstance(qname, bytes):
                qname = qname.decode("utf-8", "ignore")
            self.dns_queries[str(qname).rstrip(".")] += 1
            matched = True

        if not matched:
            self.other += 1

    def report(self) -> dict[str, Any]:
        return {
            "started_at": self.started_at,
            "finished_at": now_text(),
            "counts": {
                "packets": self.packets,
                "arp": self.arp,
                "ipv4": self.ipv4,
                "ipv6": self.ipv6,
                "tcp": self.tcp,
                "udp": self.udp,
                "icmp": self.icmp,
                "dns": self.dns,
                "http": self.http,
                "https": self.https,
                "other": self.other,
            },
            "top_sources": self.sources.most_common(10),
            "top_destinations": self.destinations.most_common(10),
            "top_ports": self.ports.most_common(10),
            "dns_queries": self.dns_queries.most_common(15),
            "http_hosts": self.http_hosts.most_common(15),
        }


class ArpSpoofDetector:
    def __init__(
        self,
        config: dict[str, Any],
        known_path: Path = KNOWN_HOSTS_FILE,
        alert_path: Path | None = None,
    ) -> None:
        self.config = config
        self.known_path = known_path
        self.known_data = load_known_hosts(known_path)
        self.hosts = self.known_data["hosts"]
        self.alert_path = alert_path
        self.alerts: list[Alert] = []
        self.cooldown: dict[str, float] = {}
        self.recent_changes: dict[str, deque[float]] = {}
        self.dirty = False

    def observe_arp(self, ip: str, mac: str, op: str = "arp", source: str = "live") -> Alert | None:
        clean = clean_ip(ip)
        if not clean:
            return None

        mac = normalize_mac(mac)
        if mac in set(self.config.get("ignored_macs", [])):
            return None

        trusted = self.config.get("trusted_hosts", {})
        trusted_mac = trusted.get(clean)
        record = self.hosts.get(clean)

        if not record:
            if trusted_mac:
                record = self._new_record(clean, trusted_mac, trusted=True)
                self.hosts[clean] = record
                self.dirty = True
            elif self.config.get("auto_learn", True):
                self.hosts[clean] = self._new_record(clean, mac, trusted=False)
                self.dirty = True
                return None
            else:
                return None

        expected_mac = normalize_mac(trusted_mac or record.get("mac", ""))
        if mac == expected_mac:
            record["last_seen"] = now_text()
            record["last_op"] = op
            self.dirty = True
            return None

        return self._handle_mismatch(clean, expected_mac, mac, record, op, source, bool(trusted_mac))

    def _handle_mismatch(
        self,
        ip: str,
        expected_mac: str,
        observed_mac: str,
        record: dict[str, Any],
        op: str,
        source: str,
        trusted: bool,
    ) -> Alert | None:
        t = time.time()
        window = int(self.config.get("burst_window_seconds", 180))
        recent = self.recent_changes.setdefault(ip, deque())
        recent.append(t)
        while recent and t - recent[0] > window:
            recent.popleft()

        record["changes"] = int(record.get("changes", 0)) + 1
        record["last_conflict_mac"] = observed_mac
        record["last_conflict_at"] = now_text()
        record["last_op"] = op
        record.setdefault("mac_history", [])
        if observed_mac not in record["mac_history"]:
            record["mac_history"].append(observed_mac)

        if self.config.get("update_known_after_change", False) and not trusted:
            record["mac"] = observed_mac

        self.dirty = True

        key = f"{ip}|{observed_mac}"
        cooldown = int(self.config.get("cooldown_seconds", 20))
        if t - self.cooldown.get(key, 0) < cooldown:
            return None
        self.cooldown[key] = t

        gateway_ip = self.config.get("gateway_ip", "")
        burst_limit = int(self.config.get("burst_change_limit", 3))

        if trusted or ip == gateway_ip:
            severity = "critical"
            title = "Gateway or trusted host MAC changed"
        elif len(recent) >= burst_limit:
            severity = "high"
            title = "Repeated ARP identity changes"
        else:
            severity = "medium"
            title = "IP to MAC mapping changed"

        reason = f"{ip} was known as {expected_mac}, now seen as {observed_mac}"
        alert = Alert(
            alert_id=f"ARP-{datetime.now().strftime('%H%M%S')}-{len(self.alerts) + 1}",
            time=now_text(),
            severity=severity,
            title=title,
            ip=ip,
            expected_mac=expected_mac,
            observed_mac=observed_mac,
            source=source,
            reason=reason,
            details={
                "arp_operation": op,
                "changes_for_ip": record.get("changes", 0),
                "recent_changes_in_window": len(recent),
            },
        )
        self.alerts.append(alert)
        self._append_alert(alert)
        return alert

    def _new_record(self, ip: str, mac: str, trusted: bool) -> dict[str, Any]:
        return {
            "ip": ip,
            "mac": normalize_mac(mac),
            "first_seen": now_text(),
            "last_seen": now_text(),
            "changes": 0,
            "trusted": trusted,
            "mac_history": [],
        }

    def _append_alert(self, alert: Alert) -> None:
        if not self.alert_path:
            return
        self.alert_path.parent.mkdir(exist_ok=True)
        with self.alert_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(asdict(alert)) + "\n")

    def save(self) -> None:
        if not self.dirty:
            return
        self.known_data["updated_at"] = now_text()
        self.known_data["hosts"] = dict(sorted(self.hosts.items()))
        save_json(self.known_path, self.known_data)
        self.dirty = False


def extract_http_host(packet: Any, scapy: Any) -> str:
    if not packet.haslayer(scapy.Raw):
        return ""
    payload = bytes(packet[scapy.Raw].load[:700])
    for line in payload.splitlines():
        if line.lower().startswith(b"host:"):
            return line.split(b":", 1)[1].strip().decode("latin-1", "ignore")[:120]
    return ""


def print_alert(alert: Alert) -> None:
    print(f"\n[{alert.severity.upper()}] {alert.title}")
    print(f"IP       : {alert.ip}")
    print(f"Expected : {alert.expected_mac}")
    print(f"Observed : {alert.observed_mac}")
    print(f"Reason   : {alert.reason}")


def print_status(stats: TrafficStats, detector: ArpSpoofDetector) -> None:
    report = stats.report()
    counts = report["counts"]
    print(
        f"[status] packets={counts['packets']} arp={counts['arp']} "
        f"tcp={counts['tcp']} udp={counts['udp']} alerts={len(detector.alerts)}"
    )


def capture_driver_message(error: Exception) -> str:
    text = str(error).lower()
    if "winpcap" in text or "npcap" in text or "layer 2" in text:
        return (
            "Live ARP capture needs Npcap on Windows. Install Npcap, enable "
            "'WinPcap API-compatible Mode' during setup, then reopen the terminal "
            "as Administrator and try again."
        )
    return f"Capture failed: {error}. Try --no-filter or check Npcap/libpcap."


def active_verify(ip: str, iface: str | None, scapy: Any, timeout: float = 2.0) -> list[str]:
    packet = scapy.Ether(dst="ff:ff:ff:ff:ff:ff") / scapy.ARP(pdst=ip)
    answers, _ = scapy.srp(packet, iface=iface, timeout=timeout, retry=0, verbose=False)
    macs: set[str] = set()
    for _sent, received in answers:
        if received.haslayer(scapy.ARP):
            macs.add(normalize_mac(received[scapy.ARP].hwsrc))
    return sorted(macs)


class PacketMonitor:
    def __init__(
        self,
        detector: ArpSpoofDetector,
        scapy: Any,
        source: str,
        pcap_writer: Any = None,
        iface: str | None = None,
        active_check: bool = False,
        status_every: int = 10,
    ) -> None:
        self.detector = detector
        self.scapy = scapy
        self.source = source
        self.pcap_writer = pcap_writer
        self.iface = iface
        self.active_check = active_check
        self.status_every = max(0, status_every)
        self.next_status = time.time() + self.status_every if self.status_every else 0
        self.stats = TrafficStats()

    def handle(self, packet: Any) -> None:
        if self.pcap_writer:
            self.pcap_writer.write(packet)

        self.stats.update(packet, self.scapy)
        self._check_arp(packet)

        if self.status_every and time.time() >= self.next_status:
            print_status(self.stats, self.detector)
            self.next_status = time.time() + self.status_every

    def _check_arp(self, packet: Any) -> None:
        if not packet.haslayer(self.scapy.ARP):
            return

        arp = packet[self.scapy.ARP]
        ip = str(getattr(arp, "psrc", ""))
        mac = str(getattr(arp, "hwsrc", ""))
        op_number = int(getattr(arp, "op", 0))
        op_name = {1: "who-has", 2: "is-at"}.get(op_number, str(op_number))

        alert = self.detector.observe_arp(ip, mac, op=op_name, source=self.source)
        if not alert:
            return

        if self.active_check:
            try:
                alert.details["active_verify_macs"] = active_verify(alert.ip, self.iface, self.scapy)
            except Exception as exc:
                alert.details["active_verify_error"] = str(exc)
        print_alert(alert)


def choose_pcap_path(value: str) -> Path | None:
    if not value:
        return None
    if value == "auto":
        return PCAP_DIR / f"capture_{file_stamp()}.pcap"
    return Path(value)


def save_session_report(mode: str, stats: TrafficStats, alerts: list[Alert], extra: dict[str, Any]) -> Path:
    ensure_folders()
    path = REPORT_DIR / f"{mode}_{file_stamp()}.json"
    report = {
        "mode": mode,
        "created_at": now_text(),
        "extra": extra,
        "traffic": stats.report(),
        "alerts": [asdict(alert) for alert in alerts],
    }
    save_json(path, report)
    return path


def save_csv_summary(stats: TrafficStats, alerts: list[Alert], mode: str) -> Path:
    ensure_folders()
    path = REPORT_DIR / f"{mode}_{file_stamp()}.csv"
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["section", "name", "value"])
        for key, value in stats.report()["counts"].items():
            writer.writerow(["count", key, value])
        for alert in alerts:
            writer.writerow(["alert", alert.ip, f"{alert.expected_mac} -> {alert.observed_mac}"])
    return path


def guess_gateway(scapy: Any) -> str:
    try:
        route = scapy.conf.route.route("0.0.0.0")
        if len(route) >= 3:
            return clean_ip(str(route[2])) or ""
    except Exception:
        return ""
    return ""


def init_project(_args: argparse.Namespace) -> None:
    ensure_folders()
    config = load_config()
    if not CONFIG_FILE.exists():
        save_config(config)
    if not KNOWN_HOSTS_FILE.exists():
        save_json(KNOWN_HOSTS_FILE, {"created_at": now_text(), "hosts": {}})
    print("Project files are ready.")
    print(f"Config      : {CONFIG_FILE}")
    print(f"Known hosts : {KNOWN_HOSTS_FILE}")


def list_interfaces(_args: argparse.Namespace) -> None:
    scapy = load_scapy()
    print("Available interfaces:")
    for iface in scapy.get_if_list():
        marker = " (default)" if iface == scapy.conf.iface else ""
        print(f" - {iface}{marker}")


def sniff_command(args: argparse.Namespace) -> None:
    ensure_folders()
    scapy = load_scapy()
    config = load_config()

    if args.gateway:
        config["gateway_ip"] = clean_ip(args.gateway) or args.gateway
    elif not config.get("gateway_ip"):
        config["gateway_ip"] = guess_gateway(scapy)

    alert_path = REPORT_DIR / f"alerts_{file_stamp()}.jsonl"
    detector = ArpSpoofDetector(config, alert_path=alert_path)

    pcap_path = choose_pcap_path(args.pcap)
    writer = scapy.PcapWriter(str(pcap_path), append=False, sync=True) if pcap_path else None
    monitor = PacketMonitor(
        detector=detector,
        scapy=scapy,
        source="live",
        pcap_writer=writer,
        iface=args.iface,
        active_check=args.active_verify,
        status_every=args.status_every,
    )

    packet_filter = None if args.no_filter else args.filter
    print("Starting capture. Press Ctrl+C to stop.")
    if config.get("gateway_ip"):
        print(f"Gateway watch: {config['gateway_ip']}")
    if pcap_path:
        print(f"PCAP saving  : {pcap_path}")

    try:
        scapy.sniff(
            iface=args.iface,
            prn=monitor.handle,
            store=False,
            count=args.count,
            timeout=args.timeout,
            filter=packet_filter,
        )
    except PermissionError as exc:
        raise SystemExit("Packet capture needs administrator permission on this machine.") from exc
    except RuntimeError as exc:
        raise SystemExit(capture_driver_message(exc)) from exc
    except OSError as exc:
        raise SystemExit(capture_driver_message(exc)) from exc
    finally:
        detector.save()
        if writer:
            writer.close()

    report_path = save_session_report(
        "live_capture",
        monitor.stats,
        detector.alerts,
        {"interface": args.iface, "filter": packet_filter, "pcap": str(pcap_path) if pcap_path else ""},
    )
    csv_path = save_csv_summary(monitor.stats, detector.alerts, "live_capture") if args.csv else None
    print_finish(report_path, csv_path, detector, monitor.stats, alert_path)


def analyze_pcap(args: argparse.Namespace) -> None:
    ensure_folders()
    scapy = load_scapy()
    pcap = Path(args.pcap)
    if not pcap.exists():
        raise SystemExit("PCAP file not found.")

    config = load_config()
    if args.gateway:
        config["gateway_ip"] = clean_ip(args.gateway) or args.gateway

    alert_path = REPORT_DIR / f"alerts_pcap_{file_stamp()}.jsonl"
    detector = ArpSpoofDetector(config, alert_path=alert_path)
    monitor = PacketMonitor(detector, scapy, source=str(pcap), status_every=0)

    print(f"Reading PCAP: {pcap}")
    for packet in scapy.rdpcap(str(pcap)):
        monitor.handle(packet)

    detector.save()
    report_path = save_session_report("pcap_analysis", monitor.stats, detector.alerts, {"pcap": str(pcap)})
    csv_path = save_csv_summary(monitor.stats, detector.alerts, "pcap_analysis") if args.csv else None
    print_finish(report_path, csv_path, detector, monitor.stats, alert_path)


def demo_command(args: argparse.Namespace) -> None:
    ensure_folders()
    config = load_config()
    config["gateway_ip"] = "192.168.1.1"
    config["trusted_hosts"] = {"192.168.1.1": "aa:bb:cc:dd:ee:01"}

    demo_known = DATA_DIR / "demo_known_hosts.json"
    save_json(demo_known, {"created_at": now_text(), "hosts": {}})

    alert_path = REPORT_DIR / f"alerts_demo_{file_stamp()}.jsonl"
    detector = ArpSpoofDetector(config, known_path=demo_known, alert_path=alert_path)

    events = [
        ("192.168.1.1", "aa:bb:cc:dd:ee:01", "is-at"),
        ("192.168.1.10", "aa:bb:cc:dd:ee:10", "is-at"),
        ("192.168.1.20", "aa:bb:cc:dd:ee:20", "is-at"),
        ("192.168.1.1", "66:66:66:66:66:66", "is-at"),
        ("192.168.1.20", "77:77:77:77:77:77", "is-at"),
        ("192.168.1.20", "88:88:88:88:88:88", "is-at"),
        ("192.168.1.20", "99:99:99:99:99:99", "is-at"),
    ]

    print("Demo ARP stream")
    for ip, mac, op in events:
        print(f"seen {ip:15} {mac}")
        alert = detector.observe_arp(ip, mac, op=op, source="demo")
        if alert:
            print_alert(alert)
        time.sleep(args.delay)

    detector.save()
    stats = TrafficStats()
    stats.arp = len(events)
    stats.packets = len(events)
    report_path = save_session_report("demo", stats, detector.alerts, {"events": len(events)})
    csv_path = save_csv_summary(stats, detector.alerts, "demo") if args.csv else None
    print_finish(report_path, csv_path, detector, stats, alert_path)


def print_finish(
    report_path: Path,
    csv_path: Path | None,
    detector: ArpSpoofDetector,
    stats: TrafficStats,
    alert_path: Path,
) -> None:
    counts = stats.report()["counts"]
    print("\nSession finished")
    print(f"Packets      : {counts['packets']}")
    print(f"ARP packets  : {counts['arp']}")
    print(f"Alerts       : {len(detector.alerts)}")
    print(f"Report       : {report_path}")
    print(f"Alert log    : {alert_path}")
    if csv_path:
        print(f"CSV summary  : {csv_path}")


def hosts_list(_args: argparse.Namespace) -> None:
    data = load_known_hosts()
    hosts = data.get("hosts", {})
    if not hosts:
        print("No known hosts saved yet.")
        return

    print(f"{'IP':16} {'MAC':17} {'TRUST':5} {'CHG':3} LAST SEEN")
    for ip, item in sorted(hosts.items()):
        print(
            f"{ip:16} {item.get('mac', ''):17} "
            f"{str(item.get('trusted', False)):5} {int(item.get('changes', 0)):3} "
            f"{item.get('last_seen', '')}"
        )


def hosts_trust(args: argparse.Namespace) -> None:
    ip = clean_ip(args.ip)
    if not ip:
        raise SystemExit("Invalid IP address.")

    mac = normalize_mac(args.mac)
    config = load_config()
    config.setdefault("trusted_hosts", {})
    config["trusted_hosts"][ip] = mac
    save_config(config)

    data = load_known_hosts()
    data["hosts"][ip] = {
        "ip": ip,
        "mac": mac,
        "first_seen": now_text(),
        "last_seen": now_text(),
        "changes": 0,
        "trusted": True,
        "mac_history": [],
    }
    save_json(KNOWN_HOSTS_FILE, data)

    print(f"Trusted host saved: {ip} -> {mac}")


def hosts_remove(args: argparse.Namespace) -> None:
    ip = clean_ip(args.ip)
    if not ip:
        raise SystemExit("Invalid IP address.")

    data = load_known_hosts()
    removed = data.get("hosts", {}).pop(ip, None)
    save_json(KNOWN_HOSTS_FILE, data)

    if args.trusted:
        config = load_config()
        config.get("trusted_hosts", {}).pop(ip, None)
        save_config(config)

    if removed:
        print(f"Removed saved host: {ip}")
    else:
        print("Host was not in known hosts.")


def hosts_export(args: argparse.Namespace) -> None:
    data = load_known_hosts()
    path = Path(args.output)
    rows = sorted(data.get("hosts", {}).items())
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["ip", "mac", "trusted", "changes", "first_seen", "last_seen"])
        for ip, item in rows:
            writer.writerow(
                [
                    ip,
                    item.get("mac", ""),
                    item.get("trusted", False),
                    item.get("changes", 0),
                    item.get("first_seen", ""),
                    item.get("last_seen", ""),
                ]
            )
    print(f"Exported {len(rows)} hosts to {path}")


def hosts_help(_args: argparse.Namespace) -> None:
    print("usage: packet_guard.py hosts {list,trust,remove,export} ...")
    print()
    print("Commands:")
    print("  list                 show known hosts")
    print("  trust IP MAC         mark an IP/MAC pair as trusted")
    print("  remove IP            remove an IP from known hosts")
    print("  export [OUTPUT]      export known hosts to CSV")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Advanced Packet Sniffer + ARP Spoofing Detector",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    sub = parser.add_subparsers(dest="command")

    init = sub.add_parser("init", help="create config and data folders")
    init.set_defaults(func=init_project)

    interfaces = sub.add_parser("interfaces", help="show available capture interfaces")
    interfaces.set_defaults(func=list_interfaces)

    sniff = sub.add_parser("sniff", help="start live packet capture")
    sniff.add_argument("--iface", help="network interface name")
    sniff.add_argument("--filter", default="arp or ip or ip6", help="BPF capture filter")
    sniff.add_argument("--no-filter", action="store_true", help="capture without BPF filter")
    sniff.add_argument("--count", type=int, default=0, help="stop after this many packets, 0 means manual stop")
    sniff.add_argument("--timeout", type=int, help="stop after seconds")
    sniff.add_argument("--gateway", help="gateway IP to protect")
    sniff.add_argument("--pcap", nargs="?", const="auto", default="", help="save packets to PCAP")
    sniff.add_argument("--active-verify", action="store_true", help="send one ARP check when an alert appears")
    sniff.add_argument("--status-every", type=int, default=10, help="status line interval in seconds")
    sniff.add_argument("--csv", action="store_true", help="also save a CSV summary")
    sniff.set_defaults(func=sniff_command)

    analyze = sub.add_parser("analyze", help="analyze a saved PCAP file")
    analyze.add_argument("pcap")
    analyze.add_argument("--gateway", help="gateway IP to protect while analyzing")
    analyze.add_argument("--csv", action="store_true", help="also save a CSV summary")
    analyze.set_defaults(func=analyze_pcap)

    demo = sub.add_parser("demo", help="run a presentation demo without live capture")
    demo.add_argument("--delay", type=float, default=0.2, help="pause between fake ARP packets")
    demo.add_argument("--csv", action="store_true", help="also save a CSV summary")
    demo.set_defaults(func=demo_command)

    hosts = sub.add_parser("hosts", help="manage learned and trusted hosts")
    host_sub = hosts.add_subparsers(dest="host_command")
    hosts.set_defaults(func=hosts_help)

    host_list = host_sub.add_parser("list", help="show known hosts")
    host_list.set_defaults(func=hosts_list)

    trust = host_sub.add_parser("trust", help="mark an IP/MAC pair as trusted")
    trust.add_argument("ip")
    trust.add_argument("mac")
    trust.set_defaults(func=hosts_trust)

    remove = host_sub.add_parser("remove", help="remove an IP from known hosts")
    remove.add_argument("ip")
    remove.add_argument("--trusted", action="store_true", help="also remove from trusted list")
    remove.set_defaults(func=hosts_remove)

    export = host_sub.add_parser("export", help="export known hosts to CSV")
    export.add_argument("output", nargs="?", default=str(REPORT_DIR / "known_hosts.csv"))
    export.set_defaults(func=hosts_export)

    return parser


def main() -> None:
    ensure_folders()
    parser = build_parser()
    args = parser.parse_args()
    if not hasattr(args, "func"):
        parser.print_help()
        return
    args.func(args)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nStopped.")
        sys.exit(1)
