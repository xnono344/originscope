#!/usr/bin/env python3
"""OriginScope: local, metadata-only connection attribution prototype."""

import argparse
import datetime as dt
import http.client
import ipaddress
import json
import os
from pathlib import Path
import queue
import re
import shutil
import socket
import subprocess
import tempfile
import threading
import time
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

try:
    import yaml
except ImportError:
    yaml = None

ROOT = Path(__file__).resolve().parent
FIELDS = ("frame.time_epoch", "ip.src", "ipv6.src", "tcp.srcport", "udp.srcport",
          "ip.dst", "ipv6.dst", "tcp.dstport", "udp.dstport", "_ws.col.Protocol",
          "tcp.flags.syn", "tcp.flags.ack")
HEADER_NAMES = ("forwarded", "x-forwarded-for", "x-real-ip", "cf-connecting-ip", "true-client-ip")
PORT_NAMES = {22: "SSH", 53: "DNS", 80: "HTTP", 443: "HTTPS", 8080: "HTTP", 18080: "HTTP", 18081: "HTTP", 18765: "HTTP"}


def ip_value(value):
    try:
        return str(ipaddress.ip_address(value.strip().strip('"').strip("[]")))
    except (ValueError, AttributeError):
        return None


def forwarded_ips(value):
    result = []
    for part in value.split(","):
        for item in part.split(";"):
            if item.strip().lower().startswith("for="):
                raw = item.split("=", 1)[1].strip().strip('"')
                if raw.startswith("["):
                    raw = raw.split("]", 1)[0][1:]
                elif raw.count(":") == 1 and "." in raw:
                    raw = raw.rsplit(":", 1)[0]
                result.append(ip_value(raw))
    return [v for v in result if v]


def trust_analysis(peer, headers, trusted_nets, cloudflare_nets):
    """Trust only the nearest asserted address from a configured, observed peer."""
    peer_ip = ipaddress.ip_address(peer)
    trusted_peer = any(peer_ip in net for net in trusted_nets)
    cf_peer = any(peer_ip in net for net in cloudflare_nets)
    claims = []
    for name in HEADER_NAMES:
        if name in headers:
            claims.append({"header": name, "value": headers[name][:512]})
    evidence = [f"Observed TCP peer: {peer} (VERIFIED)"]
    client = None
    via = None
    if not trusted_peer:
        for item in claims:
            evidence.append(f"{item['header']}: supplied by an untrusted peer")
        return {"trusted_client": None, "reported": claims, "classification": "DIRECT" if not claims else "UNTRUSTED HEADER",
                "confidence": "VERIFIED" if not claims else "UNTRUSTED", "evidence": evidence, "topology": [peer, "OriginScope demo"]}

    evidence.append(f"Immediate peer {peer} matches a configured trusted proxy range")
    # Provider-specific headers are accepted only from that provider's published ranges.
    if cf_peer and "cf-connecting-ip" in headers:
        client = ip_value(headers["cf-connecting-ip"])
        via = "CF-Connecting-IP"
    if client is None:
        for name, values in (("Forwarded", forwarded_ips(headers.get("forwarded", ""))),
                             ("X-Forwarded-For", [ip_value(x) for x in headers.get("x-forwarded-for", "").split(",")])):
            valid = [v for v in values if v]
            if valid:
                # Traverse from the peer backwards; earlier hops can be attacker-controlled.
                for candidate in reversed(valid):
                    client = candidate
                    if not any(ipaddress.ip_address(candidate) in net for net in trusted_nets):
                        break
                via = name
                break
    if client is None:
        for name in ("x-real-ip", "true-client-ip"):
            if name in headers:
                client = ip_value(headers[name])
                via = name
                if client:
                    break
    if client:
        evidence.append(f"{via} reports {client} through the trusted immediate peer")
        evidence.append("Reported client was not observed as a direct TCP peer")
        return {"trusted_client": client, "reported": claims, "classification": "PROXIED", "confidence": "HIGH",
                "evidence": evidence, "topology": [client, f"Trusted proxy {peer}", "OriginScope demo"]}
    for item in claims:
        evidence.append(f"{item['header']}: no valid accepted client address")
    return {"trusted_client": None, "reported": claims, "classification": "PROXY", "confidence": "MEDIUM",
            "evidence": evidence, "topology": [f"Unknown client", f"Trusted proxy {peer}", "OriginScope demo"]}


def parse_tshark(line):
    cells = line.rstrip("\n").split("\t")
    if len(cells) != len(FIELDS):
        return None
    stamp, ip4s, ip6s, tcps, udps, ip4d, ip6d, tcpd, udpd, app, syn, ack = cells
    src, dst = ip_value(ip4s or ip6s), ip_value(ip4d or ip6d)
    if not src or not dst:
        return None
    transport = "TCP" if tcps and tcpd else "UDP" if udps and udpd else None
    if not transport or (transport == "TCP" and not (syn.lower() in ("1", "true") and ack.lower() not in ("1", "true"))):
        return None
    try:
        return {"timestamp": dt.datetime.fromtimestamp(float(stamp), dt.timezone.utc).isoformat(),
                "source_ip": src, "source_port": int(tcps or udps), "destination_ip": dst,
                "destination_port": int(tcpd or udpd), "transport": transport,
                "protocol": app if app and app != "TCP" and app != "UDP" else PORT_NAMES.get(int(tcpd or udpd), transport)}
    except (ValueError, OverflowError):
        return None


class App:
    def __init__(self, config):
        self.config = config
        self.events = deque(maxlen=int(config["storage"]["max_connections"]))
        self.lock = threading.Lock()
        self.clients = []
        self.next_id = 0
        self.flow_seen = {}
        self.flow_lock = threading.Lock()
        try:
            interfaces = [name for _, name in socket.if_nameindex()]
        except OSError:
            interfaces = []
        self.status = {"capture": "starting", "interfaces": interfaces, "engine": "tshark" if shutil.which("tshark") else "ss"}
        self.trusted_nets = [ipaddress.ip_network(x, strict=False) for x in config["trusted_proxies"]]
        self.cloudflare_nets = self.load_networks(ROOT / config["data"]["cloudflare_ranges"])
        self.tor_exits = self.load_ips(ROOT / config["data"]["tor_exits"])
        self.enrich_queue = queue.Queue(maxsize=1000)
        self.cache = {}
        self.capture_proc = None
        self.local_ips = {"127.0.0.1", "::1"}
        try:
            output = subprocess.run(["ip", "-j", "addr"], capture_output=True, text=True, timeout=3, check=True)
            self.local_ips.update(a["local"] for iface in json.loads(output.stdout) for a in iface.get("addr_info", []))
        except (OSError, subprocess.SubprocessError, ValueError, KeyError):
            pass
        self.mmdb = {}
        try:
            import maxminddb
            for kind, key in (("asn", "asn_db"), ("country", "country_db")):
                path = ROOT / config["data"][key]
                if path.is_file():
                    self.mmdb[kind] = maxminddb.open_database(str(path))
        except Exception as exc:
            print(f"Enrichment database unavailable: {exc}", flush=True)
            pass
        threading.Thread(target=self.enrich_worker, daemon=True).start()

    @staticmethod
    def load_networks(path):
        try:
            return [ipaddress.ip_network(line.strip()) for line in path.read_text().splitlines() if line.strip() and not line.startswith("#")]
        except (OSError, ValueError):
            return []

    @staticmethod
    def load_ips(path):
        try:
            return {str(ipaddress.ip_address(line.strip())) for line in path.read_text().splitlines() if line.strip() and not line.startswith("#")}
        except (OSError, ValueError):
            return set()

    def emit(self, event):
        with self.lock:
            self.next_id += 1
            event["id"] = self.next_id
            self.events.append(event)
            for client in list(self.clients):
                try:
                    client.put_nowait(event)
                except queue.Full:
                    self.clients.remove(client)
        if self.config["enrichment"]["enabled"]:
            try:
                self.enrich_queue.put_nowait((event["id"], event["source_ip"]))
            except queue.Full:
                pass
        return event

    def observe(self, data, kind="CAPTURE", attribution=None):
        source = data["source_ip"]
        if kind == "CAPTURE" and data["destination_ip"] not in self.local_ips:
            return None
        if kind == "CAPTURE" and source in self.local_ips and data["destination_port"] not in (self.config["demo"]["port"], self.config["demo"]["proxy_port"], self.config["ui"]["port"]):
            return None
        if kind in ("CAPTURE", "PCAP"):
            # ponytail: one event per flow for 30s; add counters only if packet rates are needed.
            key = (kind, source, data["source_port"], data["destination_ip"], data["destination_port"], data["transport"])
            now = time.monotonic() if kind == "CAPTURE" else dt.datetime.fromisoformat(data["timestamp"]).timestamp()
            with self.flow_lock:
                if now - self.flow_seen.get(key, float("-inf")) < 30:
                    return None
                self.flow_seen[key] = now
                if len(self.flow_seen) > 20000:
                    self.flow_seen = {k: t for k, t in self.flow_seen.items() if now - t < 30}
        base = {**data, "kind": kind, "hostname": None, "asn": None, "network": None, "country": None,
                "reported": [], "trusted_client": None, "classification": "UNKNOWN", "confidence": "VERIFIED",
                "topology": [source, data["destination_ip"]], "evidence": [f"Observed source IP: {source}"]}
        if source in self.tor_exits:
            base["classification"] = "TOR EXIT"
            base["evidence"].append("Source matches local Tor exit list")
        elif any(ipaddress.ip_address(source) in net for net in self.cloudflare_nets):
            base["classification"] = "CDN / PROXY"
            base["evidence"].append("Source matches local Cloudflare address range list")
        elif kind == "HTTP":
            base["classification"] = "DIRECT"
        if attribution:
            base.update(attribution)
        return self.emit(base)

    def enrich_worker(self):
        while True:
            event_id, source = self.enrich_queue.get()
            if source not in self.cache:
                info = {"hostname": None, "asn": None, "network": None, "country": None}
                try:
                    if self.config["enrichment"]["reverse_dns"] and ipaddress.ip_address(source).is_global:
                        lookup = subprocess.run(["getent", "hosts", source], capture_output=True, text=True, timeout=2)
                        if lookup.returncode == 0 and lookup.stdout.split():
                            info["hostname"] = lookup.stdout.split(maxsplit=1)[1].strip().split()[0]
                except (OSError, ValueError, subprocess.TimeoutExpired, IndexError):
                    pass
                try:
                    asn = self.mmdb.get("asn").get(source) if self.mmdb.get("asn") else None
                    country = self.mmdb.get("country").get(source) if self.mmdb.get("country") else None
                    if asn:
                        info["asn"] = asn.get("autonomous_system_number") or asn.get("as_number")
                        info["network"] = asn.get("autonomous_system_organization") or asn.get("as_organization")
                    if country:
                        info["country"] = country.get("country", {}).get("names", {}).get("en")
                except Exception:
                    pass
                if len(self.cache) > 4096:
                    self.cache.clear()
                self.cache[source] = info
            with self.lock:
                event = next((x for x in self.events if x["id"] == event_id), None)
                if event:
                    event.update(self.cache[source])
                    for client in list(self.clients):
                        try:
                            client.put_nowait(event)
                        except queue.Full:
                            self.clients.remove(client)


def tshark_command(interface=None, pcap=None):
    cmd = ["tshark", "-n", "-l", "-T", "fields", "-E", "separator=\t", "-E", "occurrence=f"]
    for field in FIELDS:
        cmd += ["-e", field]
    if pcap:
        cmd += ["-r", str(pcap)]
    else:
        cmd += ["-i", interface or "any", "-f", "tcp or udp"]
    return cmd


def capture_loop(app):
    if not app.config["capture"]["enabled"]:
        app.status["capture"] = "disabled by config"
        return
    if not shutil.which("tshark"):
        app.status["capture"] = "tshark missing; using ss socket observation"
        ss_loop(app)
        return
    cmd = tshark_command(app.config["interface"])
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)
        app.capture_proc = proc
        app.status["capture"] = "starting tshark"
        for line in proc.stdout:
            if app.status["capture"] != "live capture running":
                app.status["capture"] = "live capture running"
            packet = parse_tshark(line)
            if packet:
                app.observe(packet)
        err = proc.stderr.read().strip()[-600:]
        app.status["capture"] = f"tshark stopped: {err or proc.returncode}; using ss observation"
    except OSError as exc:
        app.status["capture"] = f"tshark failed: {exc}; using ss observation"
    ss_loop(app)


def split_endpoint(value):
    host, _, port = value.rpartition(":")
    return ip_value(host.strip("[]")), int(port) if port.isdigit() else None


def ss_loop(app):
    seen = set()
    while True:
        try:
            listeners = subprocess.run(["ss", "-H", "-ltn"], capture_output=True, text=True, timeout=3, check=True).stdout
            ports = {split_endpoint(x.split()[3])[1] for x in listeners.splitlines() if len(x.split()) >= 4}
            rows = subprocess.run(["ss", "-H", "-tn", "state", "established"], capture_output=True, text=True, timeout=3, check=True).stdout
            current = set()
            for row in rows.splitlines():
                cells = row.split()
                if len(cells) < 5:
                    continue
                dst, dport = split_endpoint(cells[3])
                src, sport = split_endpoint(cells[4])
                if not (dst and src and dport in ports and sport):
                    continue
                key = (src, sport, dst, dport)
                current.add(key)
                if key not in seen:
                    app.observe({"timestamp": dt.datetime.now(dt.timezone.utc).isoformat(), "source_ip": src,
                                 "source_port": sport, "destination_ip": dst, "destination_port": dport,
                                 "transport": "TCP", "protocol": PORT_NAMES.get(dport, "TCP")}, "SOCKET")
            seen = current
            if "live capture running" not in app.status["capture"]:
                app.status["capture"] += " (socket polling active)" if "socket polling active" not in app.status["capture"] else ""
        except (OSError, subprocess.SubprocessError):
            app.status["capture"] = "ss socket observation unavailable"
        time.sleep(0.5)


class UIHandler(BaseHTTPRequestHandler):
    app = None

    def log_message(self, *_):
        pass

    def send_json(self, data, code=200):
        body = json.dumps(data).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = urlsplit(self.path).path
        if path == "/api/status":
            self.send_json({**self.app.status, "count": len(self.app.events), "trusted_proxies": [str(n) for n in self.app.trusted_nets],
                            "asn_db": "asn" in self.app.mmdb, "country_db": "country" in self.app.mmdb,
                            "cloudflare_ranges": len(self.app.cloudflare_nets), "tor_exits": len(self.app.tor_exits)})
        elif path == "/api/events":
            with self.app.lock:
                self.send_json(list(self.app.events))
        elif path == "/api/stream":
            client = queue.Queue(maxsize=256)
            with self.app.lock:
                self.app.clients.append(client)
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.end_headers()
            try:
                while True:
                    try:
                        event = client.get(timeout=15)
                        self.wfile.write(b"data: " + json.dumps(event).encode() + b"\n\n")
                    except queue.Empty:
                        self.wfile.write(b": keepalive\n\n")
                    self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError):
                pass
            finally:
                with self.app.lock:
                    if client in self.app.clients:
                        self.app.clients.remove(client)
        elif path == "/" or path == "/index.html":
            body = (ROOT / "static" / "index.html").read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_error(404)

    def do_POST(self):
        if self.path != "/api/import":
            return self.send_error(404)
        if not shutil.which("tshark"):
            return self.send_json({"error": "Install tshark to import PCAP files"}, 503)
        try:
            size = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            return self.send_json({"error": "Invalid Content-Length"}, 400)
        if size < 24 or size > 50 * 1024 * 1024:
            return self.send_json({"error": "PCAP must be between 24 bytes and 50 MiB"}, 400)
        data = self.rfile.read(size)
        if data[:4] not in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x0a\x0d\x0d\x0a", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"):
            return self.send_json({"error": "Not a PCAP or PCAPNG file"}, 400)
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as temp:
            temp.write(data)
            name = temp.name
        count = 0
        try:
            result = subprocess.run(tshark_command(pcap=name), capture_output=True, text=True, timeout=30)
            if result.returncode:
                return self.send_json({"error": result.stderr[-300:] or "tshark could not read file"}, 400)
            for line in result.stdout.splitlines():
                packet = parse_tshark(line)
                if packet:
                    self.app.observe(packet, "PCAP")
                    count += 1
            self.send_json({"imported": count})
        except subprocess.TimeoutExpired:
            self.send_json({"error": "Import exceeded 30 seconds"}, 408)
        finally:
            os.unlink(name)


class DemoHandler(BaseHTTPRequestHandler):
    app = None

    def log_message(self, *_):
        pass

    def do_GET(self):
        peer, sport = self.client_address[:2]
        headers = {name: self.headers.get(name, "") for name in HEADER_NAMES if self.headers.get(name)}
        analysis = trust_analysis(peer, headers, self.app.trusted_nets, self.app.cloudflare_nets)
        local, dport = self.connection.getsockname()[:2]
        event = self.app.observe({"timestamp": dt.datetime.now(dt.timezone.utc).isoformat(), "source_ip": peer,
                                  "source_port": sport, "destination_ip": local, "destination_port": dport,
                                  "transport": "TCP", "protocol": "HTTP"}, "HTTP",
                                 {**analysis, "request": {"method": "GET", "path": urlsplit(self.path).path[:128]}})
        body = json.dumps({"event_id": event["id"], **analysis}, indent=2).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class ProxyHandler(BaseHTTPRequestHandler):
    target_port = 18080

    def log_message(self, *_):
        pass

    def do_GET(self):
        # The demo proxy discards caller-supplied attribution headers, then asserts its observed peer.
        conn = http.client.HTTPConnection("127.0.0.1", self.target_port, timeout=5, source_address=("127.0.0.2", 0))
        try:
            conn.request("GET", self.path, headers={"X-Forwarded-For": self.client_address[0]})
            response = conn.getresponse()
            body = response.read()
            self.send_response(response.status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except OSError as exc:
            self.send_error(502, str(exc))
        finally:
            conn.close()


def serve(handler, host, port):
    server = ThreadingHTTPServer((host, port), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def load_config(path):
    if yaml is None:
        raise SystemExit("PyYAML is required. Install with: python3 -m pip install PyYAML")
    config = yaml.safe_load(Path(path).read_text())
    if not isinstance(config, dict):
        raise SystemExit("Configuration must be a YAML mapping")
    for key in ("capture", "demo", "ui", "storage", "enrichment", "data", "trusted_proxies"):
        if key not in config:
            raise SystemExit(f"Missing config key: {key}")
    return config


def main():
    parser = argparse.ArgumentParser(description="OriginScope local network attribution")
    parser.add_argument("--config", default=str(ROOT / "config.yaml"))
    args = parser.parse_args()
    config = load_config(args.config)
    app = App(config)
    UIHandler.app = DemoHandler.app = app
    ProxyHandler.target_port = config["demo"]["port"]
    servers = [serve(UIHandler, config["ui"]["host"], config["ui"]["port"]),
               serve(DemoHandler, config["demo"]["host"], config["demo"]["port"]),
               serve(ProxyHandler, config["demo"]["host"], config["demo"]["proxy_port"])]
    threading.Thread(target=capture_loop, args=(app,), daemon=True).start()
    print(f"OriginScope UI: http://{config['ui']['host']}:{config['ui']['port']}", flush=True)
    print(f"Demo direct: http://{config['demo']['host']}:{config['demo']['port']}", flush=True)
    print(f"Demo proxy:  http://{config['demo']['host']}:{config['demo']['proxy_port']}", flush=True)
    print("Interfaces:", ", ".join(app.status["interfaces"]), flush=True)
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        if app.capture_proc and app.capture_proc.poll() is None:
            app.capture_proc.terminate()
        for server in servers:
            server.shutdown()


if __name__ == "__main__":
    main()
