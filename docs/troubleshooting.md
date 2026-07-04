# Troubleshooting

Check logs:

```sh
cd container
docker compose logs -f
```

Check agent health:

```sh
curl http://localhost:8080/healthz
curl http://localhost:8080/readyz
```

Check metrics:

```sh
curl http://localhost:8080/metrics
```

Check current diagnosis:

```sh
curl http://localhost:8080/api/v1/health
curl http://localhost:8080/api/v1/verdicts/latest
curl http://localhost:8080/api/v1/recommendations
```

Check latest HTTP service checks:

```sh
curl http://localhost:8080/api/v1/tests/http/latest
```

Start a local throughput test server:

```sh
curl -X POST http://localhost:8080/api/v1/iperf/server/start \
  -H "Authorization: Bearer $INFRACHECK_ADMIN_TOKEN"
iperf3 -c <agent-ip>
curl -X POST http://localhost:8080/api/v1/iperf/server/stop \
  -H "Authorization: Bearer $INFRACHECK_ADMIN_TOKEN"
```

Run safe LAN discovery:

```sh
curl -X POST http://localhost:8080/api/v1/discovery/run \
  -H "Authorization: Bearer $INFRACHECK_ADMIN_TOKEN"
curl http://localhost:8080/api/v1/devices
```

Generate and fetch an HTML report:

```sh
curl -X POST http://localhost:8080/api/v1/reports/generate \
  -H "Authorization: Bearer $INFRACHECK_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"type":"daily","hours":24}'
curl http://localhost:8080/api/v1/reports
curl http://localhost:8080/api/v1/reports/<report-id>
```

If gateway auto-detection fails, set `targets.gateway.address` explicitly in the config.
