OriginScope: implementation plan
================================

Goal
----
Build a single-machine prototype that shows incoming connection metadata and explains what can, and cannot, be inferred about a source. It must distinguish the observed network peer from client addresses reported by proxies. Capture and analyze only traffic on systems and interfaces the operator is authorized to monitor. Do not attempt to bypass VPNs, Tor, relays, encryption, or access controls.

Scope and acceptance criteria
-----------------------------
* Start the backend and UI with one documented command. Detect available capture interfaces, and give actionable errors when a capture engine or permissions are missing.
* Display incoming TCP and UDP connections with timestamp, addresses, ports, transport, protocol guess, and available reverse DNS, ASN, network organization, and country data.
* Show an evidence list, attribution confidence label (VERIFIED, HIGH, MEDIUM, LOW, UNTRUSTED, UNKNOWN), and direct/proxy/relay/unknown classification. Never label a reported address as the original IP without reliable evidence.
* Provide a local HTTP demo server that records the actual TCP peer and parses Forwarded, X-Forwarded-For, X-Real-IP, CF-Connecting-IP, True-Client-IP, and, if supported by a mature library or proxy, PROXY protocol metadata. Only accept a claimed client address when the immediate peer is configured as a trusted proxy; preserve each hop's evidence and uncertainty.
* Provide a dark, responsive live table, detail panel, topology/evidence view, and filters for transport/protocol, source IP, ASN, country, classification, destination port, and free text.
* Import pcap/pcapng through an established parser if practical; route imported and live observations through the same normalization and attribution path.
* Default to metadata only. Never collect or persist payload bodies, passwords, cookies, credentials, or decrypted TLS content.

1. Research and select components
---------------------------------
Time-box this step, then build. Compare tshark/Wireshark, tcpdump/libpcap, Zeek, Suricata, and nDPI against the MVP needs: availability on Linux, structured output, live capture and pcap support, protocol metadata, licensing, and setup burden. Check authoritative documentation and actual installed tools before committing to a choice. Evaluate local GeoIP/ASN database options, reverse DNS, Tor exit data, and provider-published proxy ranges. Record exact licenses and data-update requirements. Prefer a proven capture/decoder executable such as tshark if it yields the needed metadata with the least custom code. Build a small adapter around it, never a packet decoder.

2. Build the observation pipeline
--------------------------------
Create a single local backend service. On startup load an editable YAML configuration with sane defaults, validate it, detect interfaces and capture dependencies, and report Linux permission requirements without requiring the entire application to run as root. Stream packet metadata from the chosen engine into a bounded queue. Normalize it into one connection schema shared by live capture, pcap import, and HTTP demo observations. Handle parser errors, malformed records, child-process exits, queue overflow, and shutdown cleanly. Prefer incremental events over retaining unbounded history.

3. Add attribution and enrichment
---------------------------------
Store the observed socket peer separately from every header or proxy claim. Resolve trusted proxies by configured CIDRs and named providers whose ranges have a documented source and refresh strategy. Parse proxy chains from the nearest trusted hop outward, stopping at the first untrusted boundary; retain raw claims only as untrusted evidence. Report the visible chain and confidence without claiming to see through relays. Enrich source IPs asynchronously with reverse DNS, ASN/network organization, country, and optional Tor exit classification. Cache successes and failures; bound lookup time and concurrency; continue operating offline or when enrichment fails. Use local databases where feasible and show UNKNOWN when unavailable.

4. Build the UI and local demo
------------------------------
Serve the UI from the same local application when possible. Implement a live connections table with the requested columns and filters, a detail panel with observed/reported/trusted addresses and evidence, and a simple visual hop chain. Add a local HTTP test server on a configurable port. Include a reproducible local reverse-proxy setup or test fixture so a normal request, a spoofed forwarded header, and a trusted-proxy request visibly produce different outcomes. Label the actual peer and proxy trust at every step.

5. Document and verify
----------------------
Provide README.md, LICENSE, .gitignore, config.example.yaml, an architecture diagram, UI screenshot, dependency and license notes, exact installation/start commands, Linux capture permissions, trusted-proxy setup, privacy model, and limitations. Use a small repository layout; avoid Kubernetes, microservices, cloud services, complex auth, and a database unless evidence shows it is needed. Run the app and verify: startup, interface discovery, live capture on a local request, pcap import if included, HTTP direct request, fake X-Forwarded-For from an untrusted peer, trusted proxy chain, filters, enrichment failure, and malformed input. Fix observed runtime defects and state any environment limits explicitly.

Suggested configuration and data model
--------------------------------------
config.example.yaml should expose interface: auto; capture.enabled; demo server bind/port; trusted_proxies as explicit CIDRs and optional named published ranges; enrichment toggles and local database paths; bounded history/queue settings. Avoid hardcoded machine-specific paths, interfaces, and addresses. A normalized observation should include id, timestamp, transport, protocol guess, observed source/destination, optional HTTP method/path metadata (without body), reported client claims, accepted trusted client if evidence allows, proxy hops, classification, confidence label, evidence, and enrichment with source/version/availability.

Suggested build order
---------------------
Research decision -> running backend with live metadata -> normalized event stream -> HTTP trust demo -> UI -> enrichment -> optional pcap import -> documentation and end-to-end verification. Keep each stage runnable. If a component proves too costly, preserve the verified core and document the omitted feature rather than replacing it with a misleading mock.
