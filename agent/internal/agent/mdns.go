package agent

import (
	"context"
	"fmt"
	"log/slog"
	"regexp"
	"strings"

	"github.com/grandcat/zeroconf"
	"github.com/infracheck/infracheck/container/agent/internal/config"
)

func StartMDNS(ctx context.Context, cfg config.Config, logger *slog.Logger) {
	if cfg.Agent.Port <= 0 {
		return
	}
	name := "Infracheck " + firstNonEmptyString(cfg.Site.Name, cfg.Site.ID, "Appliance")
	name = sanitizeMDNSName(name)
	txt := []string{
		"site_id=" + cfg.Site.ID,
		"site_name=" + cfg.Site.Name,
		"path=/ui",
		"api=/api/v1",
	}
	server, err := zeroconf.Register(name, "_infracheck._tcp", "local.", cfg.Agent.Port, txt, nil)
	if err != nil {
		logger.Warn("failed to publish mdns service", "error", err)
		return
	}
	logger.Info("mdns service published", "name", name, "service", "_infracheck._tcp", "port", cfg.Agent.Port)
	go func() {
		<-ctx.Done()
		server.Shutdown()
	}()
}

func sanitizeMDNSName(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "Infracheck Appliance"
	}
	re := regexp.MustCompile(`[^A-Za-z0-9 _.-]+`)
	value = re.ReplaceAllString(value, "")
	if len(value) > 50 {
		value = value[:50]
	}
	return value
}

func firstNonEmptyString(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return fmt.Sprint(values)
}
