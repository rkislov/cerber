// SPDX-License-Identifier: Apache-2.0
package health

import (
	"context"
	"database/sql"
	"os"
	"runtime"
	"sync"
	"time"
)

type Database struct {
	Name      string `json:"name"`
	Status    string `json:"status"`
	LatencyMS int64  `json:"latency_ms"`
	Schema    int    `json:"schema"`
	Bytes     int64  `json:"bytes"`
	WALBytes  int64  `json:"wal_bytes"`
}

func CheckDB(ctx context.Context, db *sql.DB, name, path string) Database {
	r := Database{Name: name, Status: "unavailable"}
	start := time.Now()
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	if db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&r.Schema) == nil {
		r.Status = "ok"
	}
	r.LatencyMS = time.Since(start).Milliseconds()
	if path != ":memory:" {
		if s, e := os.Stat(path); e == nil {
			r.Bytes = s.Size()
		}
		if s, e := os.Stat(path + "-wal"); e == nil {
			r.WALBytes = s.Size()
		}
	}
	return r
}

type Resources struct {
	Scope         string    `json:"scope"`
	Load          []float64 `json:"load,omitempty"`
	MemoryUsed    uint64    `json:"memory_used"`
	MemoryTotal   uint64    `json:"memory_total"`
	DiskAvailable uint64    `json:"disk_available"`
	DiskTotal     uint64    `json:"disk_total"`
	CPUPercent    *float64  `json:"cpu_percent,omitempty"`
}
type Report struct {
	At            time.Time  `json:"at"`
	UptimeSeconds int64      `json:"uptime_seconds"`
	HeapBytes     uint64     `json:"heap_bytes"`
	Goroutines    int        `json:"goroutines"`
	Resources     Resources  `json:"resources"`
	Databases     []Database `json:"databases"`
}
type Probe func(context.Context) Database

// New returns a bounded, cached snapshot. Each DB check is independent of overview queries.
func New(path string, probes ...Probe) func(context.Context) Report {
	var mu sync.Mutex
	start := time.Now()
	var cached Report
	var lastCPU float64
	var lastTime time.Time
	return func(ctx context.Context) Report {
		mu.Lock()
		defer mu.Unlock()
		if !cached.At.IsZero() && time.Since(cached.At) < 5*time.Second {
			return cached
		}
		now := time.Now()
		var mem runtime.MemStats
		runtime.ReadMemStats(&mem)
		r := Report{At: now.UTC(), UptimeSeconds: int64(now.Sub(start).Seconds()), HeapBytes: mem.HeapAlloc, Goroutines: runtime.NumGoroutine(), Resources: resources(path), Databases: []Database{}}
		cpu, ok := cpuSeconds()
		if ok && !lastTime.IsZero() {
			value := (cpu - lastCPU) / now.Sub(lastTime).Seconds() * 100
			if value < 0 {
				value = 0
			}
			r.Resources.CPUPercent = &value
		}
		lastCPU = cpu
		lastTime = now
		for _, probe := range probes {
			r.Databases = append(r.Databases, probe(ctx))
		}
		cached = r
		return r
	}
}
