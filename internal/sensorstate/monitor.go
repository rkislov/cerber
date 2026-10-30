// SPDX-License-Identifier: Apache-2.0
package sensorstate

import (
	"github.com/rkislov/cerber/internal/telemetry"
	"net/netip"
	"time"
)

type Watch struct {
	Input          string `json:"input"`
	Peer           string `json:"peer,omitempty"`
	SilenceSeconds int    `json:"silence_seconds"`
}
type WatchStatus struct {
	Input    string     `json:"input"`
	Peer     string     `json:"peer,omitempty"`
	Since    time.Time  `json:"since"`
	LastSeen *time.Time `json:"last_seen,omitempty"`
}
type MonitorConfig struct {
	Enabled        bool    `json:"enabled"`
	OfflineSeconds int     `json:"offline_seconds"`
	PendingSeconds int     `json:"pending_seconds"`
	WindowSeconds  int     `json:"window_seconds"`
	MinMessages    int     `json:"min_messages"`
	ErrorPercent   int     `json:"error_percent"`
	UnknownSets    int     `json:"unknown_sets"`
	QueueBatches   int64   `json:"queue_batches"`
	QueueBytes     int64   `json:"queue_bytes"`
	Watches        []Watch `json:"watches"`
}
type MonitorPolicy struct {
	Revision  int64         `json:"revision"`
	UpdatedAt time.Time     `json:"updated_at"`
	UpdatedBy string        `json:"updated_by"`
	Config    MonitorConfig `json:"config"`
}

func DefaultMonitor() MonitorConfig {
	return MonitorConfig{Enabled: true, OfflineSeconds: 300, PendingSeconds: 300, WindowSeconds: 300, MinMessages: 20, ErrorPercent: 20, UnknownSets: 10, QueueBatches: 500, QueueBytes: 128 << 20, Watches: []Watch{}}
}
func (c MonitorConfig) Validate() error {
	if c.OfflineSeconds < 180 || c.OfflineSeconds > 86400 || c.PendingSeconds < 180 || c.PendingSeconds > 86400 || c.WindowSeconds < 180 || c.WindowSeconds > 3600 || c.WindowSeconds%60 != 0 || c.MinMessages < 1 || c.MinMessages > 1000000000 || c.ErrorPercent < 1 || c.ErrorPercent > 100 || c.UnknownSets < 1 || c.UnknownSets > 1000000000 || c.QueueBatches < 1 || c.QueueBatches > 1000 || c.QueueBytes < 1<<20 || c.QueueBytes > 256<<20 || len(c.Watches) > 32 {
		return ErrInvalid
	}
	seen := map[string]bool{}
	for _, w := range c.Watches {
		if !telemetry.AgentIdentifier(w.Input) || w.SilenceSeconds < 180 || w.SilenceSeconds > 604800 {
			return ErrInvalid
		}
		if w.Peer != "" {
			a, e := netip.ParseAddr(w.Peer)
			if e != nil || a.Is4In6() || a.Zone() != "" || a.IsUnspecified() || a.IsMulticast() || a.String() != w.Peer {
				return ErrInvalid
			}
		}
		key := WatchKey(w.Input, w.Peer)
		if seen[key] {
			return ErrInvalid
		}
		seen[key] = true
	}
	return nil
}
func WatchKey(input, peer string) string { return input + "/" + peer }
func (p Policy) MonitorConfig() MonitorConfig {
	if p.Monitor != nil {
		return p.Monitor.Config
	}
	return DefaultMonitor()
}

type Sample struct {
	QueueReports int64     `json:"queue_reports"`
	At           time.Time `json:"at"`
	Messages     int64     `json:"messages"`
	Bytes        int64     `json:"bytes"`
	Stored       int64     `json:"stored"`
	Rejected     int64     `json:"rejected"`
	UnknownSets  int64     `json:"unknown_sets"`
	Seconds      float64   `json:"seconds"`
	Reports      int64     `json:"reports"`
	QueueBatches int64     `json:"queue_batches"`
	QueueBytes   int64     `json:"queue_bytes"`
}
type History struct {
	Inputs      []string  `json:"inputs"`
	StepSeconds int       `json:"step_seconds"`
	Points      []Sample  `json:"points"`
	AsOf        time.Time `json:"as_of"`
	RowLimit    int       `json:"row_limit"`
}
