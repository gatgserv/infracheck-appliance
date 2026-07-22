#!/usr/bin/env sh
set -eu

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$ROOT_DIR"

if ! command -v docker >/dev/null 2>&1; then
  echo "docker is required before running this installer" >&2
  exit 1
fi

if ! docker compose version >/dev/null 2>&1; then
  echo "docker compose plugin is required before running this installer" >&2
  exit 1
fi

random_token() {
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -base64 36 | tr -d '\n'
    return
  fi
  tr -dc 'A-Za-z0-9' </dev/urandom | head -c 48
}

detect_network_dns() {
  if command -v resolvectl >/dev/null 2>&1; then
    resolvectl dns 2>/dev/null | awk '
      {
        for (i = 3; i <= NF; i++) {
          if ($i !~ /^127\./ && $i != "::1" && $i != "127.0.0.53") {
            print $i
            exit
          }
        }
      }'
  fi
  awk '/^nameserver[[:space:]]+/ && $2 !~ /^127\./ && $2 != "::1" { print $2; exit }' /etc/resolv.conf 2>/dev/null || true
}

if [ ! -f .env ]; then
  admin_token="$(random_token)"
  read_token="$(random_token)"
  grafana_password="$(random_token)"
  sed \
    -e "s#replace-with-a-long-random-admin-token#$admin_token#g" \
    -e "s#replace-with-a-long-random-read-token#$read_token#g" \
    -e "s#replace-this-password#$grafana_password#g" \
    .env.example >.env
  echo "created .env with generated tokens"
else
  echo "kept existing .env"
fi

if ! grep -q '^INFRACHECK_NETWORK_DNS=.' .env; then
  network_dns="$(detect_network_dns | head -n 1)"
  if [ -n "$network_dns" ]; then
    if grep -q '^INFRACHECK_NETWORK_DNS=' .env; then
      sed -i "s#^INFRACHECK_NETWORK_DNS=.*#INFRACHECK_NETWORK_DNS=$network_dns#" .env
    else
      printf '\nINFRACHECK_NETWORK_DNS=%s\n' "$network_dns" >>.env
    fi
    echo "configured network DNS resolver: $network_dns"
  else
    echo "warning: network DNS could not be detected; set INFRACHECK_NETWORK_DNS in .env" >&2
  fi
fi

if [ ! -f config/config.yaml ]; then
  cp config/config.example.yaml config/config.yaml
  echo "created config/config.yaml"
else
  echo "kept existing config/config.yaml"
fi

mkdir -p data
if [ "$(id -u)" -eq 0 ]; then
  chown -R 10001:10001 data
elif command -v sudo >/dev/null 2>&1; then
  sudo chown -R 10001:10001 data
else
  echo "warning: could not chown data directory without root or sudo" >&2
fi

if command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
  for port in 8080 9090 9093 3000 9115 5201; do
    firewall-cmd --permanent --add-port="${port}/tcp" >/dev/null || true
  done
  firewall-cmd --reload >/dev/null || true
  echo "updated firewalld ports"
fi

docker compose up -d --build

echo "Infracheck is starting."
echo "Agent: http://localhost:8080"
echo "Prometheus: http://localhost:9090"
echo "Alertmanager: http://localhost:9093"
echo "Grafana: http://localhost:3000"
