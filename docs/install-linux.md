# Linux Installation

Infracheck v1 targets Linux Docker hosts.

```sh
cd container
sh scripts/install-linux.sh
```

The installer creates `.env` with generated tokens if it does not exist, creates `config/config.yaml` from the example if needed, fixes the mounted data directory ownership, opens common firewalld ports when firewalld is active, and starts Docker Compose.

Open:

- Agent: `http://localhost:8080`
- Prometheus: `http://localhost:9090`
- Alertmanager: `http://localhost:9093`
- Grafana: `http://localhost:3000`

The iperf3 server listens on TCP `5201` when started through the API.

Update `container/.env` before real deployments.
