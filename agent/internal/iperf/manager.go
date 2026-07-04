package iperf

import (
	"context"
	"errors"
	"os/exec"
	"strconv"
	"sync"
	"time"
)

const DefaultPort = 5201

type Status struct {
	Available bool      `json:"available"`
	Running   bool      `json:"running"`
	Port      int       `json:"port"`
	PID       int       `json:"pid,omitempty"`
	StartedAt time.Time `json:"started_at,omitempty"`
	Error     string    `json:"error,omitempty"`
}

type Manager struct {
	mu        sync.Mutex
	port      int
	cmd       *exec.Cmd
	startedAt time.Time
	lastError string
}

func NewManager(port int) *Manager {
	if port <= 0 {
		port = DefaultPort
	}
	return &Manager{port: port}
}

func (m *Manager) Available() bool {
	_, err := exec.LookPath("iperf3")
	return err == nil
}

func (m *Manager) Status() Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.refreshLocked()
	status := Status{
		Available: m.Available(),
		Port:      m.port,
		Error:     m.lastError,
	}
	if m.cmd != nil && m.cmd.Process != nil {
		status.Running = true
		status.PID = m.cmd.Process.Pid
		status.StartedAt = m.startedAt
	}
	return status
}

func (m *Manager) Start(ctx context.Context) (Status, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.refreshLocked()
	if !m.Available() {
		m.lastError = "iperf3 executable not found"
		return m.statusLocked(), errors.New(m.lastError)
	}
	if m.cmd != nil && m.cmd.Process != nil {
		return m.statusLocked(), nil
	}
	select {
	case <-ctx.Done():
		m.lastError = ctx.Err().Error()
		return m.statusLocked(), ctx.Err()
	default:
	}
	cmd := exec.Command("iperf3", "-s", "-p", strconv.Itoa(m.port))
	if err := cmd.Start(); err != nil {
		m.lastError = err.Error()
		return m.statusLocked(), err
	}
	m.cmd = cmd
	m.startedAt = time.Now().UTC()
	m.lastError = ""
	go func() {
		err := cmd.Wait()
		m.mu.Lock()
		defer m.mu.Unlock()
		if m.cmd == cmd {
			if err != nil {
				m.lastError = err.Error()
			}
			m.cmd = nil
			m.startedAt = time.Time{}
		}
	}()
	return m.statusLocked(), nil
}

func (m *Manager) Stop(ctx context.Context) (Status, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.refreshLocked()
	if m.cmd == nil || m.cmd.Process == nil {
		return m.statusLocked(), nil
	}
	proc := m.cmd.Process
	select {
	case <-ctx.Done():
		m.lastError = ctx.Err().Error()
		return m.statusLocked(), ctx.Err()
	default:
		if err := proc.Kill(); err != nil {
			m.lastError = err.Error()
			return m.statusLocked(), err
		}
		m.cmd = nil
		m.startedAt = time.Time{}
		m.refreshLocked()
		return m.statusLocked(), nil
	}
}

func (m *Manager) refreshLocked() {
}

func (m *Manager) statusLocked() Status {
	status := Status{
		Available: m.Available(),
		Port:      m.port,
		Error:     m.lastError,
	}
	if m.cmd != nil && m.cmd.Process != nil {
		status.Running = true
		status.PID = m.cmd.Process.Pid
		status.StartedAt = m.startedAt
	}
	return status
}
