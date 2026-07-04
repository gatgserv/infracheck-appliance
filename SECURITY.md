# Security Policy

Infracheck Appliance is designed as a local-first network monitoring appliance that runs inside a customer network.

## Deployment guidance

- Do not expose the appliance directly to the public internet.
- Use a VPN, private management network, or authenticated reverse proxy for remote access.
- Keep `.env`, generated tokens, reports, and customer-specific configuration private.
- Rotate `INFRACHECK_ADMIN_TOKEN` before production use.
- Protect metrics with `INFRACHECK_PROTECT_METRICS=true` when Prometheus scraping does not require public LAN access.
- Set `INFRACHECK_ALLOW_PUBLIC_READS=false` when read-only API access should require a token.

## Token model

Mutating actions require the admin token. The agent accepts:

```text
Authorization: Bearer <token>
X-Infracheck-Token: <token>
```

Examples of mutating actions:

- manual ping, DNS, HTTP, and discovery runs
- iperf3 server start and stop
- report generation
- configuration changes
- alert acknowledge, suppress, and close actions

## Reporting security issues

For security issues, contact:

```text
george@atgserv.ro
```

Please include the affected version, deployment context, reproduction steps, and impact. Do not include real customer tokens, private reports, or sensitive network data.

## Product security documentation

See also:

- [docs/security.md](docs/security.md)
- [Infracheck product documentation](https://infracheck.app/docs.html)
