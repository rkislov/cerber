// SPDX-License-Identifier: Apache-2.0
package domain

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"
)

var (
	ErrNotFound = errors.New("not found")
	ErrConflict = errors.New("conflict")
)

type Asset struct {
	ID        string    `json:"id"`
	IP        string    `json:"ip"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
}
type Target struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	AssetIDs  []string  `json:"asset_ids"`
	CreatedAt time.Time `json:"created_at"`
}
type Host struct {
	AssetID string `json:"asset_id"`
	IP      string `json:"ip"`
}
type ScanConfig struct {
	Ports       []uint16 `json:"ports"`
	Concurrency int      `json:"concurrency"`
	TimeoutMS   int      `json:"timeout_ms"`
}

// Normalize validates resource limits before a task can reach a scanner.
func (c ScanConfig) Normalize(hosts int) (ScanConfig, error) {
	if hosts < 1 || hosts > 256 {
		return c, fmt.Errorf("hosts must be between 1 and 256")
	}
	if len(c.Ports) == 0 || len(c.Ports) > 1024 {
		return c, fmt.Errorf("specify 1–1024 ports")
	}
	seen := map[uint16]bool{}
	ports := make([]uint16, 0, len(c.Ports))
	for _, p := range c.Ports {
		if p == 0 {
			return c, fmt.Errorf("port 0 is invalid")
		}
		if !seen[p] {
			seen[p] = true
			ports = append(ports, p)
		}
	}
	sort.Slice(ports, func(i, j int) bool { return ports[i] < ports[j] })
	c.Ports = ports
	if hosts*len(ports) > 65536 {
		return c, fmt.Errorf("task exceeds 65536 connection attempts")
	}
	if c.Concurrency < 1 || c.Concurrency > 64 {
		return c, fmt.Errorf("concurrency must be between 1 and 64")
	}
	if c.TimeoutMS < 10 || c.TimeoutMS > 30000 {
		return c, fmt.Errorf("timeout must be between 10 and 30000 ms")
	}
	return c, nil
}

type TaskStatus string

const (
	Queued      TaskStatus = "queued"
	Running     TaskStatus = "running"
	Completed   TaskStatus = "completed"
	Failed      TaskStatus = "failed"
	Interrupted TaskStatus = "interrupted"
)

type Task struct {
	ID         string     `json:"id"`
	TargetID   string     `json:"target_id"`
	Hosts      []Host     `json:"hosts"`
	Config     ScanConfig `json:"config"`
	Status     TaskStatus `json:"status"`
	CreatedAt  time.Time  `json:"created_at"`
	StartedAt  *time.Time `json:"started_at,omitempty"`
	FinishedAt *time.Time `json:"finished_at,omitempty"`
	Error      string     `json:"error,omitempty"`
}

type PortState string

const (
	Open       PortState = "open"
	Closed     PortState = "closed"
	Timeout    PortState = "timeout"
	ProbeError PortState = "error"
)

type Observation struct {
	TaskID     string    `json:"task_id"`
	AssetID    string    `json:"asset_id"`
	IP         string    `json:"ip"`
	Port       uint16    `json:"port"`
	Protocol   string    `json:"protocol"`
	State      PortState `json:"state"`
	Detail     string    `json:"detail,omitempty"`
	ObservedAt time.Time `json:"observed_at"`
}

func NewID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}
func CanonicalIP(value string) (string, error) {
	ip, err := netip.ParseAddr(value)
	if err != nil || ip.Zone() != "" {
		return "", fmt.Errorf("invalid IP address %q", value)
	}
	ip = ip.Unmap()
	if ip.IsUnspecified() || ip.IsMulticast() {
		return "", fmt.Errorf("IP must be a unicast address")
	}
	return ip.String(), nil
}
func ValidateName(name string) error {
	if strings.TrimSpace(name) == "" || len(name) > 256 {
		return fmt.Errorf("name must contain 1–256 bytes")
	}
	return nil
}
