FROM golang:1.26.4-alpine AS build

WORKDIR /src
COPY agent/go.mod agent/go.sum* ./agent/
WORKDIR /src/agent
RUN go mod download

COPY agent/ ./
RUN CGO_ENABLED=0 GOOS=linux go build -o /out/infracheck-agent ./cmd/infracheck-agent

FROM alpine:3.21

RUN apk add --no-cache \
    arp-scan \
    bind-tools \
    ca-certificates \
    curl \
    fping \
    iperf3 \
    libcap \
    iproute2 \
    iputils \
    mtr \
    nmap \
    net-snmp-tools \
    samba-client \
    traceroute \
    tzdata

RUN addgroup -S -g 10001 infracheck && adduser -S -D -H -u 10001 -G infracheck infracheck
RUN mkdir -p /etc/infracheck /var/lib/infracheck && chown -R infracheck:infracheck /var/lib/infracheck
RUN for tool in arp-scan nmap ping fping; do \
      path="$(command -v "$tool" || true)"; \
      if [ -n "$path" ]; then setcap cap_net_raw,cap_net_admin+eip "$path" || true; fi; \
    done

COPY --from=build /out/infracheck-agent /usr/local/bin/infracheck-agent
COPY config/config.example.yaml /etc/infracheck/config.yaml

USER infracheck
EXPOSE 8080 5201 5202/udp
ENTRYPOINT ["/usr/local/bin/infracheck-agent"]
