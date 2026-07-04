# Security

The first implementation includes token configuration early.

- Read endpoints can remain public on the LAN by default.
- Mutating endpoints require the admin token.
- Current mutating endpoints are manual ping, DNS, HTTP test runs, iperf3 server start/stop, manual LAN discovery, and report generation.
- Metrics are public by default so Prometheus can scrape the agent. Set `security.protect_metrics: true` or `INFRACHECK_PROTECT_METRICS=true` to require the read or admin token on `/metrics`.
- Set `security.allow_public_reads: false` or `INFRACHECK_ALLOW_PUBLIC_READS=false` to require the read or admin token on read-only API endpoints.
- The agent accepts `Authorization: Bearer <token>` and `X-Infracheck-Token: <token>`.
- The stack uses host networking on Linux.
- The agent requests limited network capabilities and does not require `--privileged` by default.
- Do not commit real `.env` files or production tokens.
