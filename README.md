# Infracheck Appliance

Free, local-first network monitoring appliance for IT support teams, MSPs, and technicians who need evidence for network troubleshooting.

Website: [infracheck.app](https://infracheck.app/)  
Product documentation: [infracheck.app/docs.html](https://infracheck.app/docs.html)  
Start free: [infracheck.app/start-free.html](https://infracheck.app/start-free.html)

Related guides:

- [Docker network monitoring appliance](https://infracheck.app/docker-network-monitoring-appliance.html)
- [Local-first network monitoring](https://infracheck.app/local-first-network-monitoring.html)
- [Self-hosted MSP monitoring](https://infracheck.app/self-hosted-msp-monitoring.html)
- [Network evidence reports](https://infracheck.app/network-evidence-reports.html)
- [Customer network health reports](https://infracheck.app/customer-network-health-report.html)

## What it does

Infracheck Appliance is a Docker-based local telemetry stack that runs inside a customer network. It helps diagnose Wi-Fi complaints, WAN instability, DNS failures, HTTP/TLS issues, packet loss, unknown LAN devices, and intermittent support problems that are hard to prove from the outside.

The appliance is designed to complement the Infracheck Android app:

- The app shows what the technician or user phone experiences.
- The appliance shows what the customer network experiences continuously from inside the LAN.
- Together they help separate client-side Wi-Fi symptoms from site-wide network faults.

## Best fit

- MSP network monitoring for customer sites
- Wi-Fi troubleshooting and roaming complaint investigation
- Small business and branch network diagnostics
- WAN, DNS, HTTP/TLS, packet loss, and latency monitoring
- LAN device inventory and new or missing device checks
- Customer-ready network evidence reports
- Local-first monitoring where customer data should stay on site

## Features

- Docker Compose deployment for Linux hosts
- Local web UI for health, alerts, checks, inventory, tools, and reports
- WAN speed checks, latency, packet loss, jitter, DNS, HTTP, and TLS checks
- LAN discovery and Device Intelligence with evidence-based categories, confidence, attention flags, port/service history, hostname overrides, and technician notes
- Explicitly uploaded Android Wi-Fi site surveys with SSID/BSSID, security, band, channel, and RSSI evidence
- Vendor-neutral authenticated Wi-Fi observation API for controller adapters and exported controller data
- Coordinated Standard/Wi-Fi/VoIP Site AutoTest profiles for the Android field app
- Authenticated phone-to-appliance HTTP throughput and temporary token-gated UDP echo tests
- Progressive ICMP/TCP/UDP path sampling with stable path hashes and optional MTU discovery
- DHCP server discovery, cross-resolver DNS integrity checks, and SNMP/LLDP neighbor collection
- Per-device expected-state baselines for authorization, IP, category, ports, services, and maintenance windows
- Health score, verdict engine, triage hints, and recommendations
- Alertmanager, Prometheus, Grafana, and blackbox-exporter integration
- PDF/HTML evidence reports for support tickets and customer reviews
- Token-protected admin actions and optional protected read endpoints
- Local-first data model, with no forced vendor-hosted cloud dependency

## Quick start

Use the installer on a Linux Docker host inside the target network:

```bash
git clone https://github.com/gatgserv/infracheck-appliance.git
cd infracheck-appliance
sh scripts/install-linux.sh
```

Or start manually:

```bash
cp .env.example .env
cp config/config.example.yaml config/config.yaml
docker compose up -d --build
```

Open the services:

- Infracheck appliance UI: `http://localhost:8080/ui`
- Agent API: `http://localhost:8080`
- Grafana: `http://localhost:3000`
- Prometheus: `http://localhost:9090`
- Alertmanager: `http://localhost:9093`

### Wi-Fi survey and controller ingestion

Android uploads use the paired Appliance automatically after technician confirmation. Controller adapters can use the same normalized, admin-token-protected endpoint without placing controller credentials in InfraCheck:

```http
POST /api/v1/wifi/observations
Authorization: Bearer <admin-token>
Content-Type: application/json

{"source":"unifi-controller","observations":[{"ssid":"Office","bssid":"aa:bb:cc:dd:ee:ff","security":"WPA2/WPA3","band":"5 GHz","channel":36,"frequency_mhz":5180,"rssi_dbm":-55}]}
```

Use source names such as `unifi-controller`, `omada-controller`, or `aruba-controller`. The endpoint stores normalized observations locally and does not contact controller or cloud services itself.

For a full installation guide, see [docs/install-linux.md](docs/install-linux.md).

## Common troubleshooting workflows

### "The internet is slow, but only sometimes"

Use the appliance to monitor WAN speed, packet loss, gateway latency, DNS response time, HTTP reachability, and alert history from inside the site.

### "Wi-Fi drops when users move between rooms"

Use the Android app for RSSI, BSSID, channel, and roaming evidence, then compare with appliance telemetry to determine whether the issue is local Wi-Fi/client-side or site-wide.

### "Something appeared on the network"

Use LAN discovery and Device Intelligence to identify new or missing devices, classify observed roles, review changed ports and attention flags, and record owner/location notes.

### "We need a customer report"

Generate reports with health score, findings, checks, alerts, recommendations, and inventory snapshots.

Sample/report-related assets:

- Generated reports are available from the appliance UI and `/api/v1/reports`.
- The product report workflow is explained at [network evidence reports](https://infracheck.app/network-evidence-reports.html).
- Release packages can include a bundled installation and operations guide alongside the appliance kit.

## Documentation

- [Linux installation](docs/install-linux.md)
- [Configuration](docs/configuration.md)
- [Security model](docs/security.md)
- [Troubleshooting](docs/troubleshooting.md)
- [Project scope and roadmap notes](docs/project-plan.md)
- [Product documentation website](https://infracheck.app/docs.html)

## Configuration

Copy the example config before first use:

```bash
cp config/config.example.yaml config/config.yaml
```

Important settings:

- `INFRACHECK_ADMIN_TOKEN`
- `INFRACHECK_READ_TOKEN`
- `INFRACHECK_PROTECT_METRICS`
- `INFRACHECK_ALLOW_PUBLIC_READS`
- `INFRACHECK_SITE_ID`
- `INFRACHECK_SNMP_COMMUNITY` (optional; used only when the API request omits a community)

The UDP VoIP-readiness echo listens on port `5202` only during a short authenticated test session. If host networking is replaced with explicit Docker port mappings, publish `5202/udp` as well as the web/API port.
- `INFRACHECK_SITE_NAME`
- `INFRACHECK_SITE_LOCATION`
- discovery CIDRs under `targets.discovery.cidrs`
- DNS, HTTP, TLS, ping, gateway, and speed test targets

See [docs/configuration.md](docs/configuration.md).

## Security notes

- Do not expose the appliance directly to the public internet without a reverse proxy, authentication, and network restrictions.
- Do not commit real `.env` files, generated tokens, reports, or customer-specific configuration.
- Mutating API actions require the admin token.
- Metrics are public by default for Prometheus scraping, but can be protected.
- Read-only API endpoints can be protected by configuration.

See [SECURITY.md](SECURITY.md) and [docs/security.md](docs/security.md).

## Releases

Every release should include a changelog, screenshots when the UI changes, known limitations, upgrade notes, and a tested installation path.

## Relationship to Infracheck Premium

This repository contains the free local appliance. The planned Premium License is a self-hosted central operations layer for multiple appliances, alert routing, white label reporting, roles, API access, and MSP workflows. The free appliance remains useful independently.

Premium roadmap overview: [infracheck.app](https://infracheck.app/#premium)

## Keywords

network troubleshooting, Wi-Fi troubleshooting, MSP network monitoring, local network monitoring appliance, Docker network monitoring, self-hosted network monitoring, WAN monitoring, DNS troubleshooting, HTTP monitoring, TLS monitoring, packet loss monitoring, LAN inventory, customer network reports, local-first infrastructure telemetry.
