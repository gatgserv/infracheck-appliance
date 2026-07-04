# Infracheck Appliance

Local-first infrastructure telemetry appliance for Infracheck.

The appliance runs as a Docker-based stack inside the customer network and provides:

- WAN, DNS, HTTP/TLS, packet loss, and latency checks
- LAN discovery and device inventory
- Local history, health scoring, alerts, and PDF reports
- Prometheus, Alertmanager, Grafana, and blackbox-exporter integration
- Token-protected admin actions and optional protected read endpoints

## Quick Start

```bash
cp .env.example .env
cp config/config.example.yaml config/config.yaml
docker compose up -d --build
```

Open:

- Infracheck agent: `http://localhost:8080`
- Prometheus: `http://localhost:9090`
- Alertmanager: `http://localhost:9093`
- Grafana: `http://localhost:3000`

For Linux installs, see [docs/install-linux.md](docs/install-linux.md).

## Configuration

Edit `config/config.yaml` after copying it from `config/config.example.yaml`.

Do not commit real `.env` files, generated tokens, or customer-specific configuration.

## Security

See [docs/security.md](docs/security.md).

Admin actions require an admin token. Metrics are public by default for Prometheus scraping, but can be protected through configuration.
