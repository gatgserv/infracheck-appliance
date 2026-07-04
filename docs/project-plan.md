# Infracheck Project Plan

Infracheck is a containerized network diagnostic stack for small IT support teams and MSPs. It runs inside a customer network and provides automated checks, local metrics, Grafana dashboards, reports, and a local API for future mobile clients.

## Version 1 Scope

- WAN and internet quality checks: latency, jitter, packet loss, and capped throughput checks.
- DNS diagnostics.
- HTTP and TCP availability checks.
- Local throughput testing with iperf3.
- Basic LAN inventory and safe discovery.
- New and missing device detection.
- Prometheus metrics.
- Provisioned Grafana dashboards.
- Local REST API.
- SQLite storage on a mounted volume.
- HTML reports.
- Alerting baseline through Prometheus rules and Alertmanager.

The Android application, Wi-Fi heatmaps, Wi-Fi survey flows, automatic packet capture, and aggressive network scanning are explicitly out of scope for v1.

## Product Structure

- `container/`: Go agent, Docker image, compose stack, Prometheus, Grafana, dashboards, reports, and docs.
- `mobile/`: reserved for the later Android application.

## Runtime Target

v1 officially targets Linux Docker hosts. The agent uses host networking so diagnostics see the network from the host perspective instead of Docker NAT.

The stack may request limited Linux network capabilities such as `NET_RAW` and `NET_ADMIN`. It must not require `--privileged` by default.

## Initial Implementation

The first implementation delivers:

- `GET /healthz`
- `GET /readyz`
- `GET /metrics`
- `GET /api/v1/info`
- Internal scheduler.
- Basic scheduled ping tests for gateway and internet targets.
- Basic scheduled DNS diagnostics for system and public resolvers.
- Initial verdict engine with gateway, WAN, DNS, health score, and recommendation APIs.
- Scheduled HTTP/HTTPS service checks with TLS expiry metrics and verdicts.
- Scheduled WAN speed tests with download/upload metrics and APIs.
- iperf3 server start, stop, status API, and Prometheus server-up metric.
- Safe LAN discovery using ARP table and optional arp-scan, with device inventory APIs and metrics.
- LAN inventory verdicts for new and missing devices.
- HTML report generation, report listing, and report retrieval APIs.
- Mobile bootstrap and summary endpoints for the future app.
- Prometheus alert rules and Alertmanager baseline.
- Prometheus metrics for ping latency, packet loss, jitter, and target reachability.
- Prometheus health score metrics.
- SQLite storage in a mounted volume.
- Dockerfile and Docker Compose stack.
- Prometheus scrape configuration.
- Grafana datasource and dashboard provisioning.
- Provisioned Grafana dashboards for executive summary, WAN quality, DNS, LAN inventory, and technician tools.
- Config YAML with early security token fields and a separate example template.

## Milestones

1. Bootstrap repo and compose stack.
2. Config, logging, SQLite storage, and security token shape.
3. Ping runner and Prometheus metrics.
4. DNS diagnostics.
5. HTTP and HTTPS service checks.
6. iperf3 server support.
7. Safe LAN discovery.
8. Verdict engine.
9. Grafana dashboards.
10. HTML reports.
11. Alerting.
12. Security baseline.
13. Packaging and installation docs.
14. API preparation for mobile app integration.

## Definition of Done for v1

- The stack starts with Docker Compose on a Linux Docker host.
- The agent runs reliably and does not crash when a test fails.
- Prometheus scrapes agent metrics.
- Grafana dashboards are provisioned automatically.
- Ping, DNS, and HTTP checks run on schedule.
- iperf3 server support works.
- Safe LAN discovery works.
- Verdicts and recommendations are available through the API.
- HTML reports can be generated.
- Prometheus alerts are loaded and Alertmanager is reachable.
- Docs explain installation, configuration, troubleshooting, and security.
- Unit tests cover config and verdict rules.
- No secrets are hardcoded.
