# Security

The first implementation includes token configuration early.

- Read endpoints can remain public on the LAN by default.
- Mutating endpoints require the admin token.
- Mutating endpoints include manual diagnostics, Site AutoTest, expected-state baselines, temporary throughput/UDP sessions, SNMP/LLDP queries, LAN discovery, and report generation.
- Metrics are public by default so Prometheus can scrape the agent. Set `security.protect_metrics: true` or `INFRACHECK_PROTECT_METRICS=true` to require the read or admin token on `/metrics`.
- Set `security.allow_public_reads: false` or `INFRACHECK_ALLOW_PUBLIC_READS=false` to require the read or admin token on read-only API endpoints.
- The agent accepts `Authorization: Bearer <token>` and `X-Infracheck-Token: <token>`.
- The stack uses host networking on Linux.
- The agent requests limited network capabilities and does not require `--privileged` by default.
- The UDP echo service is disabled until an authenticated request creates a short-lived random-token session. Packets without that token are not echoed, which avoids exposing a permanent UDP reflection service.
- SNMP v2c communities supplied in requests are used only for that query and are not stored or returned. The optional `INFRACHECK_SNMP_COMMUNITY` environment variable can provide a site-local default; use a read-only community and restrict SNMP access to management hosts.
- Local throughput payloads are capped at 64 MiB per request and all field-test endpoints require the admin token.
- Do not commit real `.env` files or production tokens.
