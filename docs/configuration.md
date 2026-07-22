# Configuration

The default config file is mounted at `/etc/infracheck/config.yaml`.

Use `container/config/config.yaml` for local deployment. The example template lives at `container/config/config.example.yaml`.

Important environment overrides:

- `INFRACHECK_CONFIG`
- `INFRACHECK_ADMIN_TOKEN`
- `INFRACHECK_READ_TOKEN`
- `INFRACHECK_PROTECT_METRICS`
- `INFRACHECK_ALLOW_PUBLIC_READS`
- `INFRACHECK_NETWORK_DNS` (the DNS server learned from the site network; `system`/`auto` checks use this address instead of Docker's internal DNS proxy)
- `INFRACHECK_STORAGE_PATH`
- `INFRACHECK_SITE_ID`
- `INFRACHECK_SITE_NAME`
- `INFRACHECK_SITE_LOCATION`
- `INFRACHECK_PORT`

The Linux installer detects the active network DNS server and writes it to `INFRACHECK_NETWORK_DNS`. For manual or Docker Desktop deployments, set this value explicitly to the DNS server supplied by DHCP or the router, for example `INFRACHECK_NETWORK_DNS=192.168.1.1`. Explicit public resolver targets such as `1.1.1.1` and `8.8.8.8` remain unchanged for comparison.

Reports are written to `reports.path`, defaulting to `/var/lib/infracheck/reports`.

WAN speed checks are configured under `targets.speedtest`. The default uses capped Cloudflare HTTP download/upload probes and runs every six hours. Adjust `download_bytes`, `upload_bytes`, or disable the target if the customer site has a small data cap.

LAN discovery scan ranges are configured under `targets.discovery.cidrs`. When the list is empty, the agent auto-detects directly connected IPv4 networks and caps broad masks to `/24`. For routed sites or multiple VLANs, configure every desired range explicitly, for example:

```yaml
targets:
  discovery:
    cidrs:
      - "192.168.10.0/24"
      - "192.168.20.0/24"
      - "10.20.0.0/23"
```

Prometheus alert rules live in `container/prometheus/rules/`. Alertmanager starts with a no-op receiver so alerts are visible in the Alertmanager UI without sending external notifications until a receiver is configured.
