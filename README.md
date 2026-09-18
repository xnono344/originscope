# OriginScope

OriginScope is a local network traffic attribution prototype. It shows the IP address that reached your machine, the route a trusted HTTP proxy reports, and the evidence behind each claim. It does **not** reveal an identity hidden behind a VPN, Tor exit, NAT, or relay.

![OriginScope live attribution view](screenshot.png)

## Quick start

Linux with Python 3.11+, `tshark`, and capture permission is recommended. Fedora:

```sh
sudo dnf install wireshark-cli python3
sudo usermod -aG wireshark "$USER"
./scripts/setup.sh
./originscope
```

The app itself runs in your normal user session. If new `wireshark` group membership has not reached that session yet, OriginScope activates the group only for its TShark capture child. Fedora's Wireshark package grants the narrow network capabilities to `dumpcap`, which is accessible only to the `wireshark` group. See [Wireshark's capture permission guide](https://wiki.wireshark.org/capturesetup/captureprivileges).

Open **http://127.0.0.1:18765**. Run from the project directory. `./originscope` is the single startup command after installation. Stop it with Ctrl+C.

If `tshark` or capture permission is missing, the UI and HTTP demo still run. The backend explains the capture failure and polls `ss` for established local TCP sockets. That fallback cannot see UDP or very short lived sockets. PCAP import requires `tshark`.

The setup script creates `.venv`, installs PyYAML and `maxminddb`, and downloads local Cloudflare ranges, Tor exit addresses, and DB-IP Lite ASN/country databases. Later starts do not need internet. Refresh data with `.venv/bin/python scripts/update_data.py`. Data files are intentionally excluded from Git; setup downloads them for a new checkout. `config.yaml` is editable. The documented default ports are 18765 (UI), 18080 (test server), and 18081 (test proxy).

## Try attribution

While OriginScope is running, send these requests in another terminal:

```sh
curl http://127.0.0.1:18080/direct
curl -H 'X-Forwarded-For: 203.0.113.9' http://127.0.0.1:18080/spoof
curl -H 'X-Forwarded-For: 203.0.113.9' http://127.0.0.1:18081/via-proxy
```

The first is **DIRECT** with observed TCP peer `127.0.0.1`. The second is **UNTRUSTED HEADER**: `203.0.113.9` is displayed as a claim and never accepted as the client. The third is **PROXIED**: the built-in proxy removes supplied attribution headers, forwards the request from `127.0.0.2`, and reports its observed client as `127.0.0.1`. Only `127.0.0.2/32` is trusted by default. This separate loopback address keeps a direct `127.0.0.1` request from accidentally becoming trusted.

The test server returns a JSON explanation and adds the event to the live UI. Click a row to see the observed source, reported headers, accepted client if any, topology, confidence, and evidence. Use the search, protocol, application, source classification, ASN, country, and destination port filters. Use **Import PCAP** to load a `.pcap` or `.pcapng` up to 50 MiB; imported connection starts use the same parser and enrichment pipeline.

## Application sockets and calls

OriginScope also polls Linux `ss -tunp` to show **which local process owns an active TCP or connected UDP socket** when the OS exposes that owner. Filter by app name or select **APP SOCKET**. The detail panel shows the process name/PID, local socket, remote network endpoint, and an estimated country for that endpoint when the local database has a match. A web app usually appears as `firefox` or another browser process, not as its own tab. A phone's app identity is not available from packets observed on this PC; sockets owned by other users or hidden by OS permissions may also lack a process name.

For WhatsApp or another messaging app, the remote address may be an app server, CDN, or call relay. Packet metadata does not contain a reliable caller phone number or true physical location. OriginScope explicitly shows those as **Unavailable from packets**. A number visible in an app's own UI would require that app to provide an authorized event or export; it cannot be inferred universally from network traffic. [WhatsApp documents end-to-end encryption](https://faq.whatsapp.com/820124435853543/) and [call relaying](https://faq.whatsapp.com/2635108359972899/), which are concrete reasons for this limit. The country shown is about the network endpoint's IP allocation, not the person who contacted you.

## Architecture and reused components

```text
Network interface ── TShark / dumpcap ── field output ──┐
PCAP / PCAPNG ──────── TShark ─────────── field output ──┼─ normalize + deduplicate
HTTP demo ─────────── Python HTTP server ────────────────┤          │
Local app sockets ─── Linux ss -tunp ────────────────────┘          │
                                                                  ├─ trust rules + evidence
                                                                  ├─ local DNS / MMDB / lists
                                                                  └─ bounded memory → SSE → browser
```

| Candidate | MVP fit | Decision |
| --- | --- | --- |
| [TShark / Wireshark](https://www.wireshark.org/docs/man-pages/tshark) | Live capture, protocol fields, PCAP and PCAPNG import; [GPLv2+](https://www.wireshark.org/about.html) separate executable | **Use**; no packet decoder in OriginScope |
| [tcpdump / libpcap](https://www.tcpdump.org/) | Solid capture, less convenient structured protocol output | Installed backup option, no adapter needed |
| [Zeek](https://zeek.org/) and [Suricata](https://suricata.io/) | Rich network telemetry, larger deployment and configuration surface | Skip for a single-machine MVP |
| [nDPI](https://github.com/ntop/nDPI) | Deep protocol classification | Skip until the TShark protocol guess proves insufficient |

The app is Python standard library plus PyYAML for editable YAML and `maxminddb` for local MMDB lookups. The browser UI uses native HTML, CSS, JavaScript, and Server-Sent Events. There is no database, cloud service, framework, or payload store. `ss` is a reduced fallback when packet capture is unavailable.

## Trust model

The observed source is the peer visible at this host; it is always shown separately from claimed client addresses. `Forwarded` ([RFC 7239](https://datatracker.ietf.org/doc/html/rfc7239)), `X-Forwarded-For`, `X-Real-IP`, `CF-Connecting-IP`, and `True-Client-IP` are displayed as evidence. A claim is accepted only if the immediate TCP peer belongs to a configured `trusted_proxies` CIDR. For `Forwarded` and `X-Forwarded-For`, OriginScope walks from the closest hop backwards and stops at the nearest untrusted address. `CF-Connecting-IP` is accepted only when the peer also matches the downloaded Cloudflare ranges. Cloudflare's [header guidance](https://developers.cloudflare.com/fundamentals/reference/http-headers/) explains that header's meaning.

**A trusted proxy must remove untrusted incoming attribution headers and write its own.** Trusting a proxy IP without controlling its header behavior can still admit spoofed claims. The included proxy does this. A local process can also bind `127.0.0.2`, so the loopback demo is a teaching fixture, not a security boundary. For production, place the origin behind a network boundary that accepts traffic only from the intended proxy.

`config.yaml` controls the capture interface, ports, trusted proxy CIDRs, history cap, enrichment, and data paths. It never grants automatic trust to all Cloudflare ranges: the downloaded list classifies an observed peer, while trust requires explicit configuration. No origin is inferred behind a Tor exit or other relay. A Tor label means only that the observed peer matched the local exit list at the time it was downloaded.

## Data, privacy, and limitations

- [DB-IP Lite](https://db-ip.com/db/lite.php) ASN/country data is **CC BY 4.0**, updated monthly, with reduced accuracy and coverage. Attribution is in this README and the UI. The local files are unmodified copies. Country is an estimate, not proof of a person's location. The ASN organization is a network owner and may differ from the retail ISP.
- Cloudflare publishes its [IPv4](https://www.cloudflare.com/ips-v4) and [IPv6](https://www.cloudflare.com/ips-v6) ranges. The [Tor Project bulk exit list](https://check.torproject.org/torbulkexitlist) is a snapshot and does not include every possible relay or destination-specific exit policy. Refresh these files regularly.
- No packet bodies, cookies, credentials, TLS plaintext, or HTTP message bodies are stored by OriginScope. TShark inspects traffic transiently to report metadata. Imported PCAP files can contain sensitive payloads supplied by the operator; OriginScope holds the uploaded bytes in a temporary file only while TShark reads them, then deletes it. Do not import captures you are not authorized to analyze.
- The UI and test servers bind to `127.0.0.1` by default. Changing that exposes unauthenticated local endpoints; add your own access control before binding publicly.
- One capture event represents a TCP connection start or first UDP datagram in a 30-second flow window. App socket events represent active sockets discovered by one-second polling, which can miss short connections. These are not packet or call counters. The in-memory history is capped at 10,000 observations and disappears on restart.
- Reverse DNS can be absent or misleading. The lookup worker has a two-second timeout and never blocks capture. Offline lists and databases keep ASN/country/Tor/CDN enrichment available without an API request for each observed IP.
- PROXY protocol v1/v2 ingestion, STUN/TURN/ICE analysis, TLS interception, VPN detection, and relay deanonymization are outside this MVP. The UI reports **UNKNOWN** when evidence is insufficient.

## Verification

```sh
.venv/bin/python -m unittest -v test_app.py
curl -fsS http://127.0.0.1:18765/api/status
```

The included checks cover untrusted headers, trusted proxy hop selection, Cloudflare header gating, malformed TShark records, and app socket parsing. For manual verification, run the three demo requests above, check the live table and detail panel, filter to **APP SOCKET**, and import a PCAP captured on an interface you may monitor. The screenshot above shows a tested application socket and the explicit caller-identity limits.

## Project files

`app.py` is the backend, `static/index.html` is the UI, `config.example.yaml` is the configuration template, `scripts/setup.sh` installs local dependencies, and `scripts/update_data.py` refreshes public datasets. `readme.txt` is the requested implementation plan; `progress.txt` records verified progress.
