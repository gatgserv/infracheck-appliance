package storage

import (
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

type DB struct {
	conn *sql.DB
}

type PingResult struct {
	ID          int64     `json:"id"`
	Timestamp   time.Time `json:"timestamp"`
	SiteID      string    `json:"site_id"`
	TargetName  string    `json:"target_name"`
	TargetHost  string    `json:"target_host"`
	TargetType  string    `json:"target_type"`
	Up          bool      `json:"up"`
	LatencyMS   float64   `json:"latency_ms"`
	LossPercent float64   `json:"loss_percent"`
	JitterMS    float64   `json:"jitter_ms"`
	Error       string    `json:"error,omitempty"`
}

type DNSResult struct {
	ID              int64     `json:"id"`
	Timestamp       time.Time `json:"timestamp"`
	SiteID          string    `json:"site_id"`
	ResolverName    string    `json:"resolver_name"`
	ResolverAddress string    `json:"resolver_address"`
	Domain          string    `json:"domain"`
	RecordType      string    `json:"record_type"`
	Success         bool      `json:"success"`
	DurationMS      float64   `json:"duration_ms"`
	AnswerCount     int       `json:"answer_count"`
	Error           string    `json:"error,omitempty"`
}

type HTTPResult struct {
	ID                 int64     `json:"id"`
	Timestamp          time.Time `json:"timestamp"`
	SiteID             string    `json:"site_id"`
	Name               string    `json:"name"`
	URL                string    `json:"url"`
	Up                 bool      `json:"up"`
	StatusCode         int       `json:"status_code"`
	DurationMS         float64   `json:"duration_ms"`
	TLSValid           bool      `json:"tls_valid"`
	TLSDaysUntilExpiry int       `json:"tls_days_until_expiry"`
	Error              string    `json:"error,omitempty"`
}

type SpeedtestResult struct {
	ID                 int64     `json:"id"`
	Timestamp          time.Time `json:"timestamp"`
	SiteID             string    `json:"site_id"`
	TargetName         string    `json:"target_name"`
	DownloadURL        string    `json:"download_url"`
	UploadURL          string    `json:"upload_url,omitempty"`
	Success            bool      `json:"success"`
	DownloadMbps       float64   `json:"download_mbps"`
	UploadMbps         float64   `json:"upload_mbps"`
	DownloadBytes      int64     `json:"download_bytes"`
	UploadBytes        int64     `json:"upload_bytes"`
	DownloadDurationMS float64   `json:"download_duration_ms"`
	UploadDurationMS   float64   `json:"upload_duration_ms"`
	DownloadError      string    `json:"download_error,omitempty"`
	UploadError        string    `json:"upload_error,omitempty"`
}

type AdvancedResult struct {
	ID         int64     `json:"id"`
	Timestamp  time.Time `json:"timestamp"`
	SiteID     string    `json:"site_id"`
	CheckType  string    `json:"check_type"`
	TargetName string    `json:"target_name"`
	Target     string    `json:"target"`
	Success    bool      `json:"success"`
	DurationMS float64   `json:"duration_ms"`
	Severity   string    `json:"severity"`
	Summary    string    `json:"summary"`
	Details    string    `json:"details,omitempty"`
	Error      string    `json:"error,omitempty"`
}

type AlertRecord struct {
	Fingerprint     string     `json:"fingerprint"`
	Source          string     `json:"source"`
	Severity        string     `json:"severity"`
	State           string     `json:"state"`
	Category        string     `json:"category"`
	Title           string     `json:"title"`
	Summary         string     `json:"summary"`
	Recommendation  string     `json:"recommendation"`
	Evidence        []string   `json:"evidence"`
	Labels          string     `json:"labels,omitempty"`
	Annotations     string     `json:"annotations,omitempty"`
	Active          bool       `json:"active"`
	Acknowledged    bool       `json:"acknowledged"`
	FirstSeen       time.Time  `json:"first_seen"`
	LastSeen        time.Time  `json:"last_seen"`
	AcknowledgedAt  *time.Time `json:"acknowledged_at"`
	ClearedAt       *time.Time `json:"cleared_at"`
	SuppressedUntil *time.Time `json:"suppressed_until"`
}

type Device struct {
	ID                       int64              `json:"id"`
	SiteID                   string             `json:"site_id"`
	IP                       string             `json:"ip"`
	MAC                      string             `json:"mac"`
	Vendor                   string             `json:"vendor,omitempty"`
	Hostname                 string             `json:"hostname,omitempty"`
	FirstSeen                time.Time          `json:"first_seen"`
	LastSeen                 time.Time          `json:"last_seen"`
	SeenCount                int                `json:"seen_count"`
	Source                   string             `json:"source"`
	OpenPorts                string             `json:"open_ports,omitempty"`
	Services                 string             `json:"services,omitempty"`
	Notes                    string             `json:"notes,omitempty"`
	MonitorMissing           bool               `json:"monitor_missing"`
	KnownAt                  time.Time          `json:"known_at,omitempty"`
	New                      bool               `json:"new"`
	Missing                  bool               `json:"missing"`
	Category                 string             `json:"category,omitempty"`
	ClassificationConfidence string             `json:"classification_confidence,omitempty"`
	ClassificationEvidence   []string           `json:"classification_evidence,omitempty"`
	RiskFlags                []string           `json:"risk_flags,omitempty"`
	ClassificationVersion    string             `json:"classification_version,omitempty"`
	ClassifiedAt             time.Time          `json:"classified_at,omitempty"`
	PortsObservedAt          time.Time          `json:"ports_observed_at,omitempty"`
	Expectation              *DeviceExpectation `json:"expectation,omitempty"`
	SwitchHost               string             `json:"switch_host,omitempty"`
	SwitchPort               string             `json:"switch_port,omitempty"`
	SwitchIfName             string             `json:"switch_if_name,omitempty"`
	VLAN                     string             `json:"vlan,omitempty"`
}

type DeviceExpectation struct {
	DeviceID         int64     `json:"device_id"`
	SiteID           string    `json:"site_id"`
	Authorization    string    `json:"authorization"`
	ExpectedCategory string    `json:"expected_category,omitempty"`
	ExpectedIP       string    `json:"expected_ip,omitempty"`
	ExpectedPorts    []int     `json:"expected_ports,omitempty"`
	ExpectedServices []string  `json:"expected_services,omitempty"`
	ExpectedVLAN     string    `json:"expected_vlan,omitempty"`
	ExpectedAP       string    `json:"expected_ap,omitempty"`
	ExpectedSwitch   string    `json:"expected_switch,omitempty"`
	ExpectedPort     string    `json:"expected_port,omitempty"`
	MaintenanceUntil time.Time `json:"maintenance_until,omitempty"`
	UpdatedAt        time.Time `json:"updated_at"`
}

type DeviceEvent struct {
	ID        int64     `json:"id"`
	Timestamp time.Time `json:"timestamp"`
	SiteID    string    `json:"site_id"`
	DeviceID  int64     `json:"device_id"`
	Type      string    `json:"type"`
	Severity  string    `json:"severity"`
	Summary   string    `json:"summary"`
	Before    string    `json:"before,omitempty"`
	After     string    `json:"after,omitempty"`
}

type WiFiObservation struct {
	SiteID              string    `json:"site_id"`
	BSSID               string    `json:"bssid"`
	SSID                string    `json:"ssid"`
	OUI                 string    `json:"oui,omitempty"`
	Security            string    `json:"security,omitempty"`
	Capabilities        string    `json:"capabilities,omitempty"`
	Band                string    `json:"band,omitempty"`
	Channel             int       `json:"channel"`
	FrequencyMHz        int       `json:"frequency_mhz"`
	RSSIDBm             int       `json:"rssi_dbm"`
	Connected           bool      `json:"connected"`
	LocallyAdministered bool      `json:"locally_administered"`
	Source              string    `json:"source"`
	FirstSeen           time.Time `json:"first_seen"`
	LastSeen            time.Time `json:"last_seen"`
}

type Report struct {
	ID          string    `json:"id"`
	SiteID      string    `json:"site_id"`
	Type        string    `json:"type"`
	Title       string    `json:"title"`
	PeriodStart time.Time `json:"period_start"`
	PeriodEnd   time.Time `json:"period_end"`
	Format      string    `json:"format"`
	Path        string    `json:"path"`
	CreatedAt   time.Time `json:"created_at"`
}

func Open(path string) (*DB, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	conn, err := sql.Open("sqlite", path+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)")
	if err != nil {
		return nil, err
	}
	db := &DB{conn: conn}
	if err := db.migrate(); err != nil {
		conn.Close()
		return nil, err
	}
	return db, nil
}

func (db *DB) Close() error {
	return db.conn.Close()
}

func (db *DB) migrate() error {
	_, err := db.conn.Exec(`
CREATE TABLE IF NOT EXISTS ping_results (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	timestamp TEXT NOT NULL,
	site_id TEXT NOT NULL,
	target_name TEXT NOT NULL,
	target_host TEXT NOT NULL,
	target_type TEXT NOT NULL,
	up INTEGER NOT NULL,
	latency_ms REAL NOT NULL,
	loss_percent REAL NOT NULL,
	jitter_ms REAL NOT NULL,
	error TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ping_results_target_time ON ping_results(target_name, timestamp DESC);
CREATE TABLE IF NOT EXISTS dns_results (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	timestamp TEXT NOT NULL,
	site_id TEXT NOT NULL,
	resolver_name TEXT NOT NULL,
	resolver_address TEXT NOT NULL,
	domain TEXT NOT NULL,
	record_type TEXT NOT NULL,
	success INTEGER NOT NULL,
	duration_ms REAL NOT NULL,
	answer_count INTEGER NOT NULL,
	error TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_dns_results_lookup_time ON dns_results(resolver_name, domain, record_type, timestamp DESC);
CREATE TABLE IF NOT EXISTS http_results (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	timestamp TEXT NOT NULL,
	site_id TEXT NOT NULL,
	name TEXT NOT NULL,
	url TEXT NOT NULL,
	up INTEGER NOT NULL,
	status_code INTEGER NOT NULL,
	duration_ms REAL NOT NULL,
	tls_valid INTEGER NOT NULL,
	tls_days_until_expiry INTEGER NOT NULL,
	error TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_http_results_target_time ON http_results(name, url, timestamp DESC);
CREATE TABLE IF NOT EXISTS speedtest_results (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	timestamp TEXT NOT NULL,
	site_id TEXT NOT NULL,
	target_name TEXT NOT NULL,
	download_url TEXT NOT NULL,
	upload_url TEXT NOT NULL,
	success INTEGER NOT NULL,
	download_mbps REAL NOT NULL,
	upload_mbps REAL NOT NULL,
	download_bytes INTEGER NOT NULL,
	upload_bytes INTEGER NOT NULL,
	download_duration_ms REAL NOT NULL,
	upload_duration_ms REAL NOT NULL,
	download_error TEXT NOT NULL,
	upload_error TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_speedtest_results_time ON speedtest_results(site_id, timestamp DESC);
CREATE TABLE IF NOT EXISTS advanced_results (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	timestamp TEXT NOT NULL,
	site_id TEXT NOT NULL,
	check_type TEXT NOT NULL,
	target_name TEXT NOT NULL,
	target TEXT NOT NULL,
	success INTEGER NOT NULL,
	duration_ms REAL NOT NULL,
	severity TEXT NOT NULL,
	summary TEXT NOT NULL,
	details TEXT NOT NULL,
	error TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_advanced_results_type_time ON advanced_results(check_type, timestamp DESC);
CREATE TABLE IF NOT EXISTS alert_records (
	fingerprint TEXT PRIMARY KEY,
	source TEXT NOT NULL,
	severity TEXT NOT NULL,
	state TEXT NOT NULL,
	category TEXT NOT NULL,
	title TEXT NOT NULL,
	summary TEXT NOT NULL,
	recommendation TEXT NOT NULL,
	evidence TEXT NOT NULL,
	labels TEXT NOT NULL,
	annotations TEXT NOT NULL,
	active INTEGER NOT NULL,
	acknowledged INTEGER NOT NULL,
	acknowledged_at TEXT NOT NULL DEFAULT '',
	first_seen TEXT NOT NULL,
	last_seen TEXT NOT NULL,
	cleared_at TEXT NOT NULL DEFAULT '',
	suppressed_until TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_alert_records_last_seen ON alert_records(last_seen DESC);
CREATE TABLE IF NOT EXISTS devices (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	site_id TEXT NOT NULL,
	ip TEXT NOT NULL,
	mac TEXT NOT NULL,
	vendor TEXT NOT NULL,
	hostname TEXT NOT NULL,
	first_seen TEXT NOT NULL,
	last_seen TEXT NOT NULL,
	seen_count INTEGER NOT NULL,
	source TEXT NOT NULL,
	open_ports TEXT NOT NULL,
	services TEXT NOT NULL,
	notes TEXT NOT NULL,
	monitor_missing INTEGER NOT NULL DEFAULT 0,
	known_at TEXT NOT NULL DEFAULT '',
	UNIQUE(site_id, mac)
);
CREATE INDEX IF NOT EXISTS idx_devices_last_seen ON devices(site_id, last_seen DESC);
CREATE TABLE IF NOT EXISTS reports (
	id TEXT PRIMARY KEY,
	site_id TEXT NOT NULL,
	type TEXT NOT NULL,
	title TEXT NOT NULL,
	period_start TEXT NOT NULL,
	period_end TEXT NOT NULL,
	format TEXT NOT NULL,
	path TEXT NOT NULL,
	created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_reports_created_at ON reports(site_id, created_at DESC);
CREATE TABLE IF NOT EXISTS events (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	timestamp TEXT NOT NULL,
	category TEXT NOT NULL,
	message TEXT NOT NULL,
	details TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS device_intelligence (
	device_id INTEGER PRIMARY KEY,
	category TEXT NOT NULL,
	confidence TEXT NOT NULL,
	evidence TEXT NOT NULL,
	risk_flags TEXT NOT NULL,
	classifier_version TEXT NOT NULL,
	classified_at TEXT NOT NULL,
	ports_observed_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS device_events (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	timestamp TEXT NOT NULL,
	site_id TEXT NOT NULL,
	device_id INTEGER NOT NULL,
	type TEXT NOT NULL,
	severity TEXT NOT NULL,
	summary TEXT NOT NULL,
	before_value TEXT NOT NULL,
	after_value TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_device_events_site_time ON device_events(site_id, timestamp DESC);
CREATE TABLE IF NOT EXISTS wifi_observations (
	site_id TEXT NOT NULL,
	bssid TEXT NOT NULL,
	ssid TEXT NOT NULL,
	oui TEXT NOT NULL,
	security TEXT NOT NULL,
	capabilities TEXT NOT NULL,
	band TEXT NOT NULL,
	channel INTEGER NOT NULL,
	frequency_mhz INTEGER NOT NULL,
	rssi_dbm INTEGER NOT NULL,
	connected INTEGER NOT NULL,
	locally_administered INTEGER NOT NULL,
	source TEXT NOT NULL,
	first_seen TEXT NOT NULL,
	last_seen TEXT NOT NULL,
	PRIMARY KEY(site_id, bssid)
);
CREATE INDEX IF NOT EXISTS idx_wifi_observations_site_time ON wifi_observations(site_id, last_seen DESC);
CREATE TABLE IF NOT EXISTS device_expectations (
	device_id INTEGER PRIMARY KEY,
	site_id TEXT NOT NULL,
	authorization TEXT NOT NULL,
	expected_category TEXT NOT NULL,
	expected_ip TEXT NOT NULL,
	expected_ports TEXT NOT NULL,
	expected_services TEXT NOT NULL,
	expected_vlan TEXT NOT NULL,
	expected_ap TEXT NOT NULL,
	expected_switch TEXT NOT NULL DEFAULT '',
	expected_port TEXT NOT NULL DEFAULT '',
	maintenance_until TEXT NOT NULL,
	updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_device_expectations_site ON device_expectations(site_id);
CREATE TABLE IF NOT EXISTS app_settings (
	key TEXT PRIMARY KEY,
	value TEXT NOT NULL,
	updated_at TEXT NOT NULL
);`)
	if err != nil {
		return err
	}
	for _, stmt := range []string{
		`ALTER TABLE alert_records ADD COLUMN acknowledged_at TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE alert_records ADD COLUMN cleared_at TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE alert_records ADD COLUMN suppressed_until TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE devices ADD COLUMN monitor_missing INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE devices ADD COLUMN known_at TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE device_expectations ADD COLUMN expected_switch TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE device_expectations ADD COLUMN expected_port TEXT NOT NULL DEFAULT ''`,
	} {
		if _, err := db.conn.Exec(stmt); err != nil && !strings.Contains(err.Error(), "duplicate column name") {
			return err
		}
	}
	if _, err := db.conn.Exec(`UPDATE devices SET known_at = first_seen WHERE known_at = '' AND first_seen != ''`); err != nil {
		return err
	}
	return nil
}

func (db *DB) Setting(key string) (string, bool, error) {
	var value string
	err := db.conn.QueryRow(`SELECT value FROM app_settings WHERE key = ?`, key).Scan(&value)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return value, true, nil
}

func (db *DB) SetSetting(key, value string) error {
	if key == "" {
		return errors.New("setting key is required")
	}
	_, err := db.conn.Exec(`
INSERT INTO app_settings(key, value, updated_at)
VALUES (?, ?, ?)
ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`,
		key, value, time.Now().UTC().Format(time.RFC3339Nano))
	return err
}

func (db *DB) SaveReport(report Report) error {
	_, err := db.conn.Exec(`
INSERT INTO reports(id, site_id, type, title, period_start, period_end, format, path, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		report.ID,
		report.SiteID,
		report.Type,
		report.Title,
		report.PeriodStart.UTC().Format(time.RFC3339Nano),
		report.PeriodEnd.UTC().Format(time.RFC3339Nano),
		report.Format,
		report.Path,
		report.CreatedAt.UTC().Format(time.RFC3339Nano),
	)
	return err
}

func (db *DB) Reports(siteID string, limit int) ([]Report, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := db.conn.Query(`
SELECT id, site_id, type, title, period_start, period_end, format, path, created_at
FROM reports
WHERE site_id = ?
ORDER BY created_at DESC
LIMIT ?`, siteID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanReports(rows)
}

func (db *DB) Report(siteID, id string) (Report, error) {
	rows, err := db.conn.Query(`
SELECT id, site_id, type, title, period_start, period_end, format, path, created_at
FROM reports
WHERE site_id = ? AND id = ?`, siteID, id)
	if err != nil {
		return Report{}, err
	}
	defer rows.Close()
	reports, err := scanReports(rows)
	if err != nil {
		return Report{}, err
	}
	if len(reports) == 0 {
		return Report{}, sql.ErrNoRows
	}
	return reports[0], nil
}

func (db *DB) DeleteReportsBefore(siteID string, cutoff time.Time) (int, error) {
	rows, err := db.conn.Query(`
SELECT id, site_id, type, title, period_start, period_end, format, path, created_at
FROM reports
WHERE site_id = ? AND created_at < ?`, siteID, cutoff.UTC().Format(time.RFC3339Nano))
	if err != nil {
		return 0, err
	}
	reports, err := scanReports(rows)
	_ = rows.Close()
	if err != nil {
		return 0, err
	}
	for _, report := range reports {
		if report.Path != "" {
			_ = os.Remove(report.Path)
		}
	}
	result, err := db.conn.Exec(`DELETE FROM reports WHERE site_id = ? AND created_at < ?`, siteID, cutoff.UTC().Format(time.RFC3339Nano))
	if err != nil {
		return 0, err
	}
	affected, err := result.RowsAffected()
	return int(affected), err
}

func (db *DB) DeleteClosedAlertsBefore(cutoff time.Time) (int, error) {
	cutoffText := cutoff.UTC().Format(time.RFC3339Nano)
	result, err := db.conn.Exec(`DELETE FROM alert_records WHERE active = 0 AND cleared_at != '' AND cleared_at < ?`, cutoffText)
	if err != nil {
		return 0, err
	}
	affected, err := result.RowsAffected()
	return int(affected), err
}

func scanReports(rows *sql.Rows) ([]Report, error) {
	reports := []Report{}
	for rows.Next() {
		var report Report
		var periodStart string
		var periodEnd string
		var createdAt string
		if err := rows.Scan(&report.ID, &report.SiteID, &report.Type, &report.Title, &periodStart, &periodEnd, &report.Format, &report.Path, &createdAt); err != nil {
			return nil, err
		}
		parsedStart, err := time.Parse(time.RFC3339Nano, periodStart)
		if err != nil {
			return nil, err
		}
		parsedEnd, err := time.Parse(time.RFC3339Nano, periodEnd)
		if err != nil {
			return nil, err
		}
		parsedCreated, err := time.Parse(time.RFC3339Nano, createdAt)
		if err != nil {
			return nil, err
		}
		report.PeriodStart = parsedStart
		report.PeriodEnd = parsedEnd
		report.CreatedAt = parsedCreated
		reports = append(reports, report)
	}
	return reports, rows.Err()
}

func (db *DB) UpsertDevices(devices []Device) (int, error) {
	newCount := 0
	for _, device := range devices {
		storageMAC := device.MAC
		if storageMAC == "" && device.IP != "" {
			storageMAC = "ip:" + device.IP
		}
		if storageMAC == "" {
			continue
		}
		var existingID int64
		err := db.conn.QueryRow(`SELECT id FROM devices WHERE site_id = ? AND mac = ?`, device.SiteID, storageMAC).Scan(&existingID)
		if errors.Is(err, sql.ErrNoRows) {
			_, err = db.conn.Exec(`
INSERT INTO devices(site_id, ip, mac, vendor, hostname, first_seen, last_seen, seen_count, source, open_ports, services, notes, known_at)
VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, '', '', '', '')`,
				device.SiteID,
				device.IP,
				storageMAC,
				device.Vendor,
				device.Hostname,
				device.FirstSeen.UTC().Format(time.RFC3339Nano),
				device.LastSeen.UTC().Format(time.RFC3339Nano),
				device.Source,
			)
			if err != nil {
				return newCount, err
			}
			newCount++
			continue
		}
		if err != nil {
			return newCount, err
		}
		_, err = db.conn.Exec(`
UPDATE devices
SET ip = ?, vendor = CASE WHEN vendor = '' THEN ? ELSE vendor END, hostname = CASE WHEN hostname = '' THEN ? ELSE hostname END,
	last_seen = ?, seen_count = seen_count + 1, source = ?
WHERE id = ?`,
			device.IP,
			device.Vendor,
			device.Hostname,
			device.LastSeen.UTC().Format(time.RFC3339Nano),
			device.Source,
			existingID,
		)
		if err != nil {
			return newCount, err
		}
	}
	return newCount, nil
}

func (db *DB) Devices(siteID string) ([]Device, error) {
	rows, err := db.conn.Query(`
SELECT id, site_id, ip, mac, vendor, hostname, first_seen, last_seen, seen_count, source, open_ports, services, notes, monitor_missing, known_at
FROM devices
WHERE site_id = ?
ORDER BY last_seen DESC`, siteID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	devices, err := scanDevices(rows)
	if err == nil {
		err = db.attachDeviceIntelligence(devices)
	}
	if err == nil {
		err = db.attachDeviceExpectations(devices)
	}
	return devices, err
}

func (db *DB) Device(siteID string, id int64) (Device, error) {
	rows, err := db.conn.Query(`
SELECT id, site_id, ip, mac, vendor, hostname, first_seen, last_seen, seen_count, source, open_ports, services, notes, monitor_missing, known_at
FROM devices
WHERE site_id = ? AND id = ?`, siteID, id)
	if err != nil {
		return Device{}, err
	}
	defer rows.Close()
	devices, err := scanDevices(rows)
	if err != nil {
		return Device{}, err
	}
	if len(devices) == 0 {
		return Device{}, sql.ErrNoRows
	}
	if err := db.attachDeviceIntelligence(devices); err != nil {
		return Device{}, err
	}
	if err := db.attachDeviceExpectations(devices); err != nil {
		return Device{}, err
	}
	return devices[0], nil
}

func (db *DB) UpdateDevice(siteID string, id int64, hostname, notes string, monitorMissing bool) (Device, error) {
	monitor := 0
	if monitorMissing {
		monitor = 1
	}
	result, err := db.conn.Exec(`
UPDATE devices
SET hostname = ?, notes = ?, monitor_missing = ?
WHERE site_id = ? AND id = ?`, hostname, notes, monitor, siteID, id)
	if err != nil {
		return Device{}, err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return Device{}, err
	}
	if affected == 0 {
		return Device{}, sql.ErrNoRows
	}
	return db.Device(siteID, id)
}

func (db *DB) MarkDeviceKnown(siteID string, id int64) (Device, error) {
	result, err := db.conn.Exec(`
UPDATE devices
SET known_at = ?
WHERE site_id = ? AND id = ?`,
		time.Now().UTC().Format(time.RFC3339Nano),
		siteID,
		id,
	)
	if err != nil {
		return Device{}, err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return Device{}, err
	}
	if affected == 0 {
		return Device{}, sql.ErrNoRows
	}
	return db.Device(siteID, id)
}

func (db *DB) MarkAllNewDevicesKnown(siteID string) (int64, error) {
	result, err := db.conn.Exec(`
UPDATE devices
SET known_at = ?
WHERE site_id = ? AND known_at = ''`,
		time.Now().UTC().Format(time.RFC3339Nano),
		siteID,
	)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

func (db *DB) UpdateDeviceIdentityByIP(siteID, ip, hostname, vendor, source string) (Device, error) {
	result, err := db.conn.Exec(`
UPDATE devices
SET hostname = CASE WHEN ? != '' THEN ? ELSE hostname END,
	vendor = CASE WHEN ? != '' THEN ? ELSE vendor END,
	source = CASE WHEN source = '' THEN ? WHEN instr(source, ?) > 0 THEN source ELSE source || ',' || ? END,
	last_seen = ?
WHERE site_id = ? AND ip = ?`,
		hostname,
		hostname,
		vendor,
		vendor,
		source,
		source,
		source,
		time.Now().UTC().Format(time.RFC3339Nano),
		siteID,
		ip,
	)
	if err != nil {
		return Device{}, err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return Device{}, err
	}
	if affected == 0 {
		return Device{}, sql.ErrNoRows
	}
	devices, err := db.Devices(siteID)
	if err != nil {
		return Device{}, err
	}
	for _, device := range devices {
		if device.IP == ip {
			return device, nil
		}
	}
	return Device{}, sql.ErrNoRows
}

func (db *DB) NewDevices(siteID string, since time.Duration) ([]Device, error) {
	rows, err := db.conn.Query(`
SELECT id, site_id, ip, mac, vendor, hostname, first_seen, last_seen, seen_count, source, open_ports, services, notes, monitor_missing, known_at
FROM devices
WHERE site_id = ? AND known_at = ''
ORDER BY first_seen DESC`, siteID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	devices, err := scanDevices(rows)
	if err == nil {
		err = db.attachDeviceIntelligence(devices)
	}
	if err == nil {
		err = db.attachDeviceExpectations(devices)
	}
	return devices, err
}

func (db *DB) MissingDevices(siteID string, since time.Duration) ([]Device, error) {
	cutoff := time.Now().UTC().Add(-since).Format(time.RFC3339Nano)
	rows, err := db.conn.Query(`
SELECT id, site_id, ip, mac, vendor, hostname, first_seen, last_seen, seen_count, source, open_ports, services, notes, monitor_missing, known_at
FROM devices
WHERE site_id = ? AND monitor_missing = 1 AND last_seen < ?
ORDER BY last_seen ASC`, siteID, cutoff)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	devices, err := scanDevices(rows)
	if err == nil {
		err = db.attachDeviceIntelligence(devices)
	}
	if err == nil {
		err = db.attachDeviceExpectations(devices)
	}
	return devices, err
}

func (db *DB) attachDeviceIntelligence(devices []Device) error {
	for i := range devices {
		var evidenceJSON, risksJSON, classifiedAt, portsAt string
		err := db.conn.QueryRow(`SELECT category, confidence, evidence, risk_flags, classifier_version, classified_at, ports_observed_at FROM device_intelligence WHERE device_id = ?`, devices[i].ID).
			Scan(&devices[i].Category, &devices[i].ClassificationConfidence, &evidenceJSON, &risksJSON, &devices[i].ClassificationVersion, &classifiedAt, &portsAt)
		if errors.Is(err, sql.ErrNoRows) {
			continue
		}
		if err != nil {
			return err
		}
		_ = json.Unmarshal([]byte(evidenceJSON), &devices[i].ClassificationEvidence)
		_ = json.Unmarshal([]byte(risksJSON), &devices[i].RiskFlags)
		devices[i].ClassifiedAt, _ = time.Parse(time.RFC3339Nano, classifiedAt)
		devices[i].PortsObservedAt, _ = time.Parse(time.RFC3339Nano, portsAt)
	}
	return nil
}

func (db *DB) attachDeviceExpectations(devices []Device) error {
	for i := range devices {
		expectation, err := db.DeviceExpectation(devices[i].SiteID, devices[i].ID)
		if errors.Is(err, sql.ErrNoRows) {
			continue
		}
		if err != nil {
			return err
		}
		devices[i].Expectation = &expectation
	}
	return nil
}

func (db *DB) DeviceExpectation(siteID string, deviceID int64) (DeviceExpectation, error) {
	var result DeviceExpectation
	var portsJSON, servicesJSON, maintenance, updated string
	err := db.conn.QueryRow(`SELECT device_id, site_id, authorization, expected_category, expected_ip, expected_ports, expected_services, expected_vlan, expected_ap, expected_switch, expected_port, maintenance_until, updated_at FROM device_expectations WHERE site_id = ? AND device_id = ?`, siteID, deviceID).
		Scan(&result.DeviceID, &result.SiteID, &result.Authorization, &result.ExpectedCategory, &result.ExpectedIP, &portsJSON, &servicesJSON, &result.ExpectedVLAN, &result.ExpectedAP, &result.ExpectedSwitch, &result.ExpectedPort, &maintenance, &updated)
	if err != nil {
		return DeviceExpectation{}, err
	}
	_ = json.Unmarshal([]byte(portsJSON), &result.ExpectedPorts)
	_ = json.Unmarshal([]byte(servicesJSON), &result.ExpectedServices)
	result.MaintenanceUntil, _ = time.Parse(time.RFC3339Nano, maintenance)
	result.UpdatedAt, _ = time.Parse(time.RFC3339Nano, updated)
	return result, nil
}

func (db *DB) DeviceExpectations(siteID string) ([]DeviceExpectation, error) {
	rows, err := db.conn.Query(`SELECT device_id FROM device_expectations WHERE site_id = ? ORDER BY device_id`, siteID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var results []DeviceExpectation
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		item, err := db.DeviceExpectation(siteID, id)
		if err != nil {
			return nil, err
		}
		results = append(results, item)
	}
	return results, rows.Err()
}

func (db *DB) UpsertDeviceExpectation(expectation DeviceExpectation) (DeviceExpectation, error) {
	portsJSON, _ := json.Marshal(expectation.ExpectedPorts)
	servicesJSON, _ := json.Marshal(expectation.ExpectedServices)
	now := time.Now().UTC()
	maintenance := ""
	if !expectation.MaintenanceUntil.IsZero() {
		maintenance = expectation.MaintenanceUntil.UTC().Format(time.RFC3339Nano)
	}
	_, err := db.conn.Exec(`INSERT INTO device_expectations(device_id, site_id, authorization, expected_category, expected_ip, expected_ports, expected_services, expected_vlan, expected_ap, expected_switch, expected_port, maintenance_until, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(device_id) DO UPDATE SET site_id=excluded.site_id, authorization=excluded.authorization, expected_category=excluded.expected_category, expected_ip=excluded.expected_ip, expected_ports=excluded.expected_ports, expected_services=excluded.expected_services, expected_vlan=excluded.expected_vlan, expected_ap=excluded.expected_ap, expected_switch=excluded.expected_switch, expected_port=excluded.expected_port, maintenance_until=excluded.maintenance_until, updated_at=excluded.updated_at`,
		expectation.DeviceID, expectation.SiteID, expectation.Authorization, expectation.ExpectedCategory, expectation.ExpectedIP, string(portsJSON), string(servicesJSON), expectation.ExpectedVLAN, expectation.ExpectedAP, expectation.ExpectedSwitch, expectation.ExpectedPort, maintenance, now.Format(time.RFC3339Nano))
	if err != nil {
		return DeviceExpectation{}, err
	}
	return db.DeviceExpectation(expectation.SiteID, expectation.DeviceID)
}

func (db *DB) UpdateDeviceIntelligence(siteID string, deviceID int64, openPorts, services, category, confidence string, evidence, risks []string, version string, observedAt time.Time) (Device, error) {
	device, err := db.Device(siteID, deviceID)
	if err != nil {
		return Device{}, err
	}
	evidenceJSON, _ := json.Marshal(evidence)
	risksJSON, _ := json.Marshal(risks)
	now := time.Now().UTC()
	observedAtText := ""
	if !observedAt.IsZero() {
		observedAtText = observedAt.UTC().Format(time.RFC3339Nano)
	}
	_, err = db.conn.Exec(`UPDATE devices SET open_ports = ?, services = ? WHERE site_id = ? AND id = ?`, openPorts, services, siteID, deviceID)
	if err != nil {
		return Device{}, err
	}
	_, err = db.conn.Exec(`INSERT INTO device_intelligence(device_id, category, confidence, evidence, risk_flags, classifier_version, classified_at, ports_observed_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(device_id) DO UPDATE SET category=excluded.category, confidence=excluded.confidence, evidence=excluded.evidence, risk_flags=excluded.risk_flags, classifier_version=excluded.classifier_version, classified_at=excluded.classified_at, ports_observed_at=excluded.ports_observed_at`,
		deviceID, category, confidence, string(evidenceJSON), string(risksJSON), version, now.Format(time.RFC3339Nano), observedAtText)
	if err != nil {
		return Device{}, err
	}
	updated, err := db.Device(siteID, deviceID)
	if err != nil {
		return Device{}, err
	}
	if device.OpenPorts != updated.OpenPorts {
		_ = db.SaveDeviceEvent(DeviceEvent{Timestamp: now, SiteID: siteID, DeviceID: deviceID, Type: "ports_changed", Severity: "warning", Summary: "Observed TCP ports changed", Before: device.OpenPorts, After: updated.OpenPorts})
	}
	if device.Category != "" && device.Category != updated.Category {
		_ = db.SaveDeviceEvent(DeviceEvent{Timestamp: now, SiteID: siteID, DeviceID: deviceID, Type: "category_changed", Severity: "info", Summary: "Device category changed from " + device.Category + " to " + updated.Category, Before: device.Category, After: updated.Category})
	}
	return updated, nil
}

func (db *DB) SaveDeviceEvent(event DeviceEvent) error {
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}
	_, err := db.conn.Exec(`INSERT INTO device_events(timestamp, site_id, device_id, type, severity, summary, before_value, after_value) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, event.Timestamp.UTC().Format(time.RFC3339Nano), event.SiteID, event.DeviceID, event.Type, event.Severity, event.Summary, event.Before, event.After)
	return err
}

func (db *DB) DeviceEvents(siteID string, limit int) ([]DeviceEvent, error) {
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	rows, err := db.conn.Query(`SELECT id, timestamp, site_id, device_id, type, severity, summary, before_value, after_value FROM device_events WHERE site_id = ? ORDER BY timestamp DESC LIMIT ?`, siteID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []DeviceEvent{}
	for rows.Next() {
		var item DeviceEvent
		var timestamp string
		if err := rows.Scan(&item.ID, &timestamp, &item.SiteID, &item.DeviceID, &item.Type, &item.Severity, &item.Summary, &item.Before, &item.After); err != nil {
			return nil, err
		}
		item.Timestamp, _ = time.Parse(time.RFC3339Nano, timestamp)
		out = append(out, item)
	}
	return out, rows.Err()
}

func (db *DB) UpsertWiFiObservations(siteID, source string, observations []WiFiObservation) (int, error) {
	now := time.Now().UTC()
	count := 0
	for _, item := range observations {
		item.BSSID = strings.ToLower(strings.TrimSpace(item.BSSID))
		if item.BSSID == "" {
			continue
		}
		if item.FirstSeen.IsZero() {
			item.FirstSeen = now
		}
		if item.LastSeen.IsZero() {
			item.LastSeen = now
		}
		connected, local := 0, 0
		if item.Connected {
			connected = 1
		}
		if item.LocallyAdministered {
			local = 1
		}
		_, err := db.conn.Exec(`INSERT INTO wifi_observations(site_id,bssid,ssid,oui,security,capabilities,band,channel,frequency_mhz,rssi_dbm,connected,locally_administered,source,first_seen,last_seen)
VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(site_id,bssid) DO UPDATE SET ssid=excluded.ssid,oui=excluded.oui,security=excluded.security,capabilities=excluded.capabilities,band=excluded.band,channel=excluded.channel,frequency_mhz=excluded.frequency_mhz,rssi_dbm=excluded.rssi_dbm,connected=excluded.connected,locally_administered=excluded.locally_administered,source=excluded.source,last_seen=excluded.last_seen`,
			siteID, item.BSSID, item.SSID, item.OUI, item.Security, item.Capabilities, item.Band, item.Channel, item.FrequencyMHz, item.RSSIDBm, connected, local, source, item.FirstSeen.UTC().Format(time.RFC3339Nano), item.LastSeen.UTC().Format(time.RFC3339Nano))
		if err != nil {
			return count, err
		}
		count++
	}
	return count, nil
}

func (db *DB) WiFiObservations(siteID string, limit int) ([]WiFiObservation, error) {
	if limit <= 0 || limit > 2000 {
		limit = 500
	}
	rows, err := db.conn.Query(`SELECT site_id,bssid,ssid,oui,security,capabilities,band,channel,frequency_mhz,rssi_dbm,connected,locally_administered,source,first_seen,last_seen FROM wifi_observations WHERE site_id=? ORDER BY last_seen DESC LIMIT ?`, siteID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []WiFiObservation{}
	for rows.Next() {
		var item WiFiObservation
		var connected, local int
		var first, last string
		if err := rows.Scan(&item.SiteID, &item.BSSID, &item.SSID, &item.OUI, &item.Security, &item.Capabilities, &item.Band, &item.Channel, &item.FrequencyMHz, &item.RSSIDBm, &connected, &local, &item.Source, &first, &last); err != nil {
			return nil, err
		}
		item.Connected = connected == 1
		item.LocallyAdministered = local == 1
		item.FirstSeen, _ = time.Parse(time.RFC3339Nano, first)
		item.LastSeen, _ = time.Parse(time.RFC3339Nano, last)
		out = append(out, item)
	}
	return out, rows.Err()
}

func scanDevices(rows *sql.Rows) ([]Device, error) {
	devices := []Device{}
	for rows.Next() {
		var device Device
		var firstSeen string
		var lastSeen string
		var knownAt string
		var monitorMissing int
		if err := rows.Scan(&device.ID, &device.SiteID, &device.IP, &device.MAC, &device.Vendor, &device.Hostname, &firstSeen, &lastSeen, &device.SeenCount, &device.Source, &device.OpenPorts, &device.Services, &device.Notes, &monitorMissing, &knownAt); err != nil {
			return nil, err
		}
		parsedFirst, err := time.Parse(time.RFC3339Nano, firstSeen)
		if err != nil {
			return nil, err
		}
		parsedLast, err := time.Parse(time.RFC3339Nano, lastSeen)
		if err != nil {
			return nil, err
		}
		device.FirstSeen = parsedFirst
		device.LastSeen = parsedLast
		if knownAt != "" {
			if parsedKnown, err := time.Parse(time.RFC3339Nano, knownAt); err == nil {
				device.KnownAt = parsedKnown
			}
		}
		device.MonitorMissing = monitorMissing == 1
		if strings.HasPrefix(device.MAC, "ip:") {
			device.MAC = ""
		}
		devices = append(devices, device)
	}
	return devices, rows.Err()
}

func (db *DB) SaveSpeedtest(result SpeedtestResult) error {
	success := 0
	if result.Success {
		success = 1
	}
	_, err := db.conn.Exec(`
INSERT INTO speedtest_results(timestamp, site_id, target_name, download_url, upload_url, success, download_mbps, upload_mbps, download_bytes, upload_bytes, download_duration_ms, upload_duration_ms, download_error, upload_error)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		result.Timestamp.UTC().Format(time.RFC3339Nano),
		result.SiteID,
		result.TargetName,
		result.DownloadURL,
		result.UploadURL,
		success,
		result.DownloadMbps,
		result.UploadMbps,
		result.DownloadBytes,
		result.UploadBytes,
		result.DownloadDurationMS,
		result.UploadDurationMS,
		result.DownloadError,
		result.UploadError,
	)
	return err
}

func (db *DB) LatestSpeedtest(limit int) ([]SpeedtestResult, error) {
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	rows, err := db.conn.Query(`
SELECT id, timestamp, site_id, target_name, download_url, upload_url, success, download_mbps, upload_mbps, download_bytes, upload_bytes, download_duration_ms, upload_duration_ms, download_error, upload_error
FROM speedtest_results
ORDER BY timestamp DESC
LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanSpeedtest(rows)
}

func (db *DB) SpeedtestSince(siteID string, since time.Time, limit int) ([]SpeedtestResult, error) {
	if limit <= 0 || limit > 5000 {
		limit = 500
	}
	rows, err := db.conn.Query(`
SELECT id, timestamp, site_id, target_name, download_url, upload_url, success, download_mbps, upload_mbps, download_bytes, upload_bytes, download_duration_ms, upload_duration_ms, download_error, upload_error
FROM speedtest_results
WHERE site_id = ? AND timestamp >= ?
ORDER BY timestamp DESC
LIMIT ?`, siteID, since.UTC().Format(time.RFC3339Nano), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanSpeedtest(rows)
}

func scanSpeedtest(rows *sql.Rows) ([]SpeedtestResult, error) {
	results := []SpeedtestResult{}
	for rows.Next() {
		var result SpeedtestResult
		var timestamp string
		var success int
		if err := rows.Scan(&result.ID, &timestamp, &result.SiteID, &result.TargetName, &result.DownloadURL, &result.UploadURL, &success, &result.DownloadMbps, &result.UploadMbps, &result.DownloadBytes, &result.UploadBytes, &result.DownloadDurationMS, &result.UploadDurationMS, &result.DownloadError, &result.UploadError); err != nil {
			return nil, err
		}
		parsed, err := time.Parse(time.RFC3339Nano, timestamp)
		if err != nil {
			return nil, err
		}
		result.Timestamp = parsed
		result.Success = success == 1
		results = append(results, result)
	}
	return results, rows.Err()
}

func (db *DB) SaveAdvanced(result AdvancedResult) error {
	success := 0
	if result.Success {
		success = 1
	}
	_, err := db.conn.Exec(`
INSERT INTO advanced_results(timestamp, site_id, check_type, target_name, target, success, duration_ms, severity, summary, details, error)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		result.Timestamp.UTC().Format(time.RFC3339Nano),
		result.SiteID,
		result.CheckType,
		result.TargetName,
		result.Target,
		success,
		result.DurationMS,
		result.Severity,
		result.Summary,
		result.Details,
		result.Error,
	)
	return err
}

func (db *DB) LatestAdvanced(checkType string, limit int) ([]AdvancedResult, error) {
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	query := `SELECT id, timestamp, site_id, check_type, target_name, target, success, duration_ms, severity, summary, details, error FROM advanced_results`
	args := []any{}
	if checkType != "" {
		query += ` WHERE check_type = ?`
		args = append(args, checkType)
	}
	query += ` ORDER BY timestamp DESC LIMIT ?`
	args = append(args, limit)
	rows, err := db.conn.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var results []AdvancedResult
	for rows.Next() {
		var result AdvancedResult
		var timestamp string
		var success int
		if err := rows.Scan(&result.ID, &timestamp, &result.SiteID, &result.CheckType, &result.TargetName, &result.Target, &success, &result.DurationMS, &result.Severity, &result.Summary, &result.Details, &result.Error); err != nil {
			return nil, err
		}
		parsed, err := time.Parse(time.RFC3339Nano, timestamp)
		if err != nil {
			return nil, err
		}
		result.Timestamp = parsed
		result.Success = success == 1
		results = append(results, result)
	}
	return results, rows.Err()
}

func (db *DB) AdvancedSince(siteID string, since time.Time, limit int) ([]AdvancedResult, error) {
	if limit <= 0 || limit > 5000 {
		limit = 500
	}
	rows, err := db.conn.Query(`
SELECT id, timestamp, site_id, check_type, target_name, target, success, duration_ms, severity, summary, details, error
FROM advanced_results
WHERE site_id = ? AND timestamp >= ?
ORDER BY timestamp DESC
LIMIT ?`, siteID, since.UTC().Format(time.RFC3339Nano), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var results []AdvancedResult
	for rows.Next() {
		var result AdvancedResult
		var timestamp string
		var success int
		if err := rows.Scan(&result.ID, &timestamp, &result.SiteID, &result.CheckType, &result.TargetName, &result.Target, &success, &result.DurationMS, &result.Severity, &result.Summary, &result.Details, &result.Error); err != nil {
			return nil, err
		}
		parsed, err := time.Parse(time.RFC3339Nano, timestamp)
		if err != nil {
			return nil, err
		}
		result.Timestamp = parsed
		result.Success = success == 1
		results = append(results, result)
	}
	return results, rows.Err()
}

func (db *DB) UpsertAlertRecords(records []AlertRecord) error {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	seen := map[string]struct{}{}
	for _, record := range records {
		seen[record.Fingerprint] = struct{}{}
		evidenceRaw, _ := json.Marshal(record.Evidence)
		_, err := db.conn.Exec(`
INSERT INTO alert_records(fingerprint, source, severity, state, category, title, summary, recommendation, evidence, labels, annotations, active, acknowledged, acknowledged_at, first_seen, last_seen, cleared_at, suppressed_until)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, 0, '', ?, ?, '', '')
ON CONFLICT(fingerprint) DO UPDATE SET
	source = excluded.source,
	severity = excluded.severity,
	state = excluded.state,
	category = excluded.category,
	title = excluded.title,
	summary = excluded.summary,
	recommendation = excluded.recommendation,
	evidence = excluded.evidence,
	labels = excluded.labels,
	annotations = excluded.annotations,
	acknowledged = CASE WHEN alert_records.active = 1 THEN alert_records.acknowledged ELSE 0 END,
	acknowledged_at = CASE WHEN alert_records.active = 1 THEN alert_records.acknowledged_at ELSE '' END,
	active = CASE WHEN alert_records.suppressed_until != '' AND alert_records.suppressed_until > excluded.last_seen THEN alert_records.active ELSE 1 END,
	last_seen = excluded.last_seen,
	cleared_at = CASE WHEN alert_records.suppressed_until != '' AND alert_records.suppressed_until > excluded.last_seen THEN alert_records.cleared_at ELSE '' END`,
			record.Fingerprint, record.Source, record.Severity, record.State, record.Category, record.Title, record.Summary, record.Recommendation, string(evidenceRaw), record.Labels, record.Annotations, now, now)
		if err != nil {
			return err
		}
	}
	if len(seen) == 0 {
		_, err := db.conn.Exec(`UPDATE alert_records SET active = 0, last_seen = ?, cleared_at = CASE WHEN cleared_at = '' THEN ? ELSE cleared_at END WHERE active = 1`, now, now)
		return err
	}
	active, err := db.AlertRecords(true, true, 1000)
	if err != nil {
		return err
	}
	for _, record := range active {
		if _, ok := seen[record.Fingerprint]; !ok {
			if _, err := db.conn.Exec(`UPDATE alert_records SET active = 0, last_seen = ?, cleared_at = CASE WHEN cleared_at = '' THEN ? ELSE cleared_at END WHERE fingerprint = ?`, now, now, record.Fingerprint); err != nil {
				return err
			}
		}
	}
	return nil
}

func (db *DB) AcknowledgeAlert(fingerprint string) error {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	result, err := db.conn.Exec(`UPDATE alert_records SET acknowledged = 1, acknowledged_at = CASE WHEN acknowledged_at = '' THEN ? ELSE acknowledged_at END WHERE fingerprint = ?`, now, fingerprint)
	if err != nil {
		return err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (db *DB) SuppressAlert(fingerprint string, until time.Time) error {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	result, err := db.conn.Exec(`UPDATE alert_records SET acknowledged = 1, acknowledged_at = CASE WHEN acknowledged_at = '' THEN ? ELSE acknowledged_at END, suppressed_until = ? WHERE fingerprint = ?`, now, until.UTC().Format(time.RFC3339Nano), fingerprint)
	if err != nil {
		return err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (db *DB) CloseAlert(fingerprint string) error {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	until := time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC).Format(time.RFC3339Nano)
	result, err := db.conn.Exec(`UPDATE alert_records SET active = 0, state = 'closed', acknowledged = 1, acknowledged_at = CASE WHEN acknowledged_at = '' THEN ? ELSE acknowledged_at END, cleared_at = CASE WHEN cleared_at = '' THEN ? ELSE cleared_at END, suppressed_until = ? WHERE fingerprint = ?`, now, now, until, fingerprint)
	if err != nil {
		return err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (db *DB) AlertRecords(activeOnly, includeAcknowledged bool, limit int) ([]AlertRecord, error) {
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	query := `SELECT fingerprint, source, severity, state, category, title, summary, recommendation, evidence, labels, annotations, active, acknowledged, first_seen, last_seen, acknowledged_at, cleared_at, suppressed_until FROM alert_records`
	where := []string{}
	if activeOnly {
		where = append(where, `active = 1`)
		where = append(where, `(suppressed_until = '' OR suppressed_until <= ?)`)
	}
	if !includeAcknowledged {
		where = append(where, `acknowledged = 0`)
	}
	if len(where) > 0 {
		query += ` WHERE ` + strings.Join(where, ` AND `)
	}
	query += ` ORDER BY acknowledged ASC, first_seen DESC LIMIT ?`
	args := []any{}
	if activeOnly {
		args = append(args, time.Now().UTC().Format(time.RFC3339Nano))
	}
	args = append(args, limit)
	rows, err := db.conn.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanAlertRecords(rows)
}

func (db *DB) AlertRecordsSince(since time.Time, limit int) ([]AlertRecord, error) {
	if limit <= 0 || limit > 5000 {
		limit = 500
	}
	rows, err := db.conn.Query(`
SELECT fingerprint, source, severity, state, category, title, summary, recommendation, evidence, labels, annotations, active, acknowledged, first_seen, last_seen, acknowledged_at, cleared_at, suppressed_until
FROM alert_records
WHERE active = 1 OR first_seen >= ? OR last_seen >= ? OR cleared_at >= ?
ORDER BY active DESC, last_seen DESC
LIMIT ?`, since.UTC().Format(time.RFC3339Nano), since.UTC().Format(time.RFC3339Nano), since.UTC().Format(time.RFC3339Nano), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanAlertRecords(rows)
}

func (db *DB) SaveHTTP(result HTTPResult) error {
	up := 0
	if result.Up {
		up = 1
	}
	tlsValid := 0
	if result.TLSValid {
		tlsValid = 1
	}
	_, err := db.conn.Exec(`
INSERT INTO http_results(timestamp, site_id, name, url, up, status_code, duration_ms, tls_valid, tls_days_until_expiry, error)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		result.Timestamp.UTC().Format(time.RFC3339Nano),
		result.SiteID,
		result.Name,
		result.URL,
		up,
		result.StatusCode,
		result.DurationMS,
		tlsValid,
		result.TLSDaysUntilExpiry,
		result.Error,
	)
	return err
}

func (db *DB) LatestHTTP(target string, limit int) ([]HTTPResult, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	query := `SELECT id, timestamp, site_id, name, url, up, status_code, duration_ms, tls_valid, tls_days_until_expiry, error FROM http_results`
	args := []any{}
	if target != "" {
		query += ` WHERE name = ? OR url = ?`
		args = append(args, target, target)
	}
	query += ` ORDER BY timestamp DESC LIMIT ?`
	args = append(args, limit)

	rows, err := db.conn.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return scanHTTP(rows)
}

func (db *DB) HTTPSince(siteID string, since time.Time, limit int) ([]HTTPResult, error) {
	if limit <= 0 || limit > 5000 {
		limit = 500
	}
	rows, err := db.conn.Query(`
SELECT id, timestamp, site_id, name, url, up, status_code, duration_ms, tls_valid, tls_days_until_expiry, error
FROM http_results
WHERE site_id = ? AND timestamp >= ?
ORDER BY timestamp DESC
LIMIT ?`, siteID, since.UTC().Format(time.RFC3339Nano), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanHTTP(rows)
}

func (db *DB) RecentHTTP(limit int) ([]HTTPResult, error) {
	return db.LatestHTTP("", limit)
}

func (db *DB) SaveDNS(result DNSResult) error {
	success := 0
	if result.Success {
		success = 1
	}
	_, err := db.conn.Exec(`
INSERT INTO dns_results(timestamp, site_id, resolver_name, resolver_address, domain, record_type, success, duration_ms, answer_count, error)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		result.Timestamp.UTC().Format(time.RFC3339Nano),
		result.SiteID,
		result.ResolverName,
		result.ResolverAddress,
		result.Domain,
		result.RecordType,
		success,
		result.DurationMS,
		result.AnswerCount,
		result.Error,
	)
	return err
}

func (db *DB) LatestDNS(resolver, domain string, limit int) ([]DNSResult, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	query := `SELECT id, timestamp, site_id, resolver_name, resolver_address, domain, record_type, success, duration_ms, answer_count, error FROM dns_results`
	args := []any{}
	where := []string{}
	if resolver != "" {
		where = append(where, `(resolver_name = ? OR resolver_address = ?)`)
		args = append(args, resolver, resolver)
	}
	if domain != "" {
		where = append(where, `domain = ?`)
		args = append(args, domain)
	}
	if len(where) > 0 {
		query += ` WHERE ` + strings.Join(where, ` AND `)
	}
	query += ` ORDER BY timestamp DESC LIMIT ?`
	args = append(args, limit)

	rows, err := db.conn.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return scanDNS(rows)
}

func (db *DB) DNSSince(siteID string, since time.Time, limit int) ([]DNSResult, error) {
	if limit <= 0 || limit > 5000 {
		limit = 500
	}
	rows, err := db.conn.Query(`
SELECT id, timestamp, site_id, resolver_name, resolver_address, domain, record_type, success, duration_ms, answer_count, error
FROM dns_results
WHERE site_id = ? AND timestamp >= ?
ORDER BY timestamp DESC
LIMIT ?`, siteID, since.UTC().Format(time.RFC3339Nano), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanDNS(rows)
}

func (db *DB) LatestPingByTargetType(targetType string, limit int) ([]PingResult, error) {
	if targetType == "" {
		return db.LatestPing("", limit)
	}
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	rows, err := db.conn.Query(`
SELECT id, timestamp, site_id, target_name, target_host, target_type, up, latency_ms, loss_percent, jitter_ms, error
FROM ping_results
WHERE target_type = ?
ORDER BY timestamp DESC
LIMIT ?`, targetType, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return scanPing(rows)
}

func (db *DB) RecentDNS(limit int) ([]DNSResult, error) {
	return db.LatestDNS("", "", limit)
}

func (db *DB) SavePing(result PingResult) error {
	up := 0
	if result.Up {
		up = 1
	}
	_, err := db.conn.Exec(`
INSERT INTO ping_results(timestamp, site_id, target_name, target_host, target_type, up, latency_ms, loss_percent, jitter_ms, error)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		result.Timestamp.UTC().Format(time.RFC3339Nano),
		result.SiteID,
		result.TargetName,
		result.TargetHost,
		result.TargetType,
		up,
		result.LatencyMS,
		result.LossPercent,
		result.JitterMS,
		result.Error,
	)
	return err
}

func (db *DB) LatestPing(target string, limit int) ([]PingResult, error) {
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	query := `SELECT id, timestamp, site_id, target_name, target_host, target_type, up, latency_ms, loss_percent, jitter_ms, error FROM ping_results`
	args := []any{}
	if target != "" {
		query += ` WHERE target_name = ? OR target_host = ?`
		args = append(args, target, target)
	}
	query += ` ORDER BY timestamp DESC LIMIT ?`
	args = append(args, limit)

	rows, err := db.conn.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return scanPing(rows)
}

func scanAlertRecords(rows *sql.Rows) ([]AlertRecord, error) {
	var records []AlertRecord
	for rows.Next() {
		var record AlertRecord
		var evidenceRaw string
		var active int
		var acknowledged int
		var firstSeen string
		var lastSeen string
		var acknowledgedAt string
		var clearedAt string
		var suppressedUntil string
		if err := rows.Scan(&record.Fingerprint, &record.Source, &record.Severity, &record.State, &record.Category, &record.Title, &record.Summary, &record.Recommendation, &evidenceRaw, &record.Labels, &record.Annotations, &active, &acknowledged, &firstSeen, &lastSeen, &acknowledgedAt, &clearedAt, &suppressedUntil); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(evidenceRaw), &record.Evidence)
		record.Active = active == 1
		record.Acknowledged = acknowledged == 1
		record.FirstSeen, _ = time.Parse(time.RFC3339Nano, firstSeen)
		record.LastSeen, _ = time.Parse(time.RFC3339Nano, lastSeen)
		if parsed, err := time.Parse(time.RFC3339Nano, acknowledgedAt); err == nil {
			record.AcknowledgedAt = &parsed
		}
		if parsed, err := time.Parse(time.RFC3339Nano, clearedAt); err == nil {
			record.ClearedAt = &parsed
		}
		if parsed, err := time.Parse(time.RFC3339Nano, suppressedUntil); err == nil {
			record.SuppressedUntil = &parsed
		}
		records = append(records, record)
	}
	return records, rows.Err()
}

func scanHTTP(rows *sql.Rows) ([]HTTPResult, error) {
	var results []HTTPResult
	for rows.Next() {
		var result HTTPResult
		var timestamp string
		var up int
		var tlsValid int
		if err := rows.Scan(&result.ID, &timestamp, &result.SiteID, &result.Name, &result.URL, &up, &result.StatusCode, &result.DurationMS, &tlsValid, &result.TLSDaysUntilExpiry, &result.Error); err != nil {
			return nil, err
		}
		parsed, err := time.Parse(time.RFC3339Nano, timestamp)
		if err != nil {
			return nil, err
		}
		result.Timestamp = parsed
		result.Up = up == 1
		result.TLSValid = tlsValid == 1
		results = append(results, result)
	}
	return results, rows.Err()
}

func scanDNS(rows *sql.Rows) ([]DNSResult, error) {
	var results []DNSResult
	for rows.Next() {
		var result DNSResult
		var timestamp string
		var success int
		if err := rows.Scan(&result.ID, &timestamp, &result.SiteID, &result.ResolverName, &result.ResolverAddress, &result.Domain, &result.RecordType, &success, &result.DurationMS, &result.AnswerCount, &result.Error); err != nil {
			return nil, err
		}
		parsed, err := time.Parse(time.RFC3339Nano, timestamp)
		if err != nil {
			return nil, err
		}
		result.Timestamp = parsed
		result.Success = success == 1
		results = append(results, result)
	}
	return results, rows.Err()
}

func scanPing(rows *sql.Rows) ([]PingResult, error) {
	var results []PingResult
	for rows.Next() {
		var result PingResult
		var timestamp string
		var up int
		if err := rows.Scan(&result.ID, &timestamp, &result.SiteID, &result.TargetName, &result.TargetHost, &result.TargetType, &up, &result.LatencyMS, &result.LossPercent, &result.JitterMS, &result.Error); err != nil {
			return nil, err
		}
		parsed, err := time.Parse(time.RFC3339Nano, timestamp)
		if err != nil {
			return nil, err
		}
		result.Timestamp = parsed
		result.Up = up == 1
		results = append(results, result)
	}
	return results, rows.Err()
}

func (db *DB) PingSince(siteID string, since time.Time, limit int) ([]PingResult, error) {
	if limit <= 0 || limit > 5000 {
		limit = 500
	}
	rows, err := db.conn.Query(`
SELECT id, timestamp, site_id, target_name, target_host, target_type, up, latency_ms, loss_percent, jitter_ms, error
FROM ping_results
WHERE site_id = ? AND timestamp >= ?
ORDER BY timestamp DESC
LIMIT ?`, siteID, since.UTC().Format(time.RFC3339Nano), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanPing(rows)
}

func (db *DB) SaveEvent(category, message, details string) error {
	if category == "" || message == "" {
		return errors.New("event category and message are required")
	}
	_, err := db.conn.Exec(`INSERT INTO events(timestamp, category, message, details) VALUES (?, ?, ?, ?)`,
		time.Now().UTC().Format(time.RFC3339Nano), category, message, details)
	return err
}
