//go:build linux

// SPDX-License-Identifier: Apache-2.0
//
package health

import (
	"os"
	"strconv"
	"strings"
	"syscall"
)

func cpuSeconds() (float64, bool) {
	var u syscall.Rusage
	if syscall.Getrusage(syscall.RUSAGE_SELF, &u) != nil {
		return 0, false
	}
	return float64(u.Utime.Sec+u.Stime.Sec) + float64(u.Utime.Usec+u.Stime.Usec)/1e6, true
}
func resources(path string) Resources {
	r := Resources{Scope: "host"}
	if b, e := os.ReadFile("/proc/loadavg"); e == nil {
		f := strings.Fields(string(b))
		if len(f) >= 3 {
			for _, v := range f[:3] {
				x, _ := strconv.ParseFloat(v, 64)
				r.Load = append(r.Load, x)
			}
		}
	}
	if b, e := os.ReadFile("/proc/meminfo"); e == nil {
		var available uint64
		for _, line := range strings.Split(string(b), "\n") {
			f := strings.Fields(line)
			if len(f) < 2 {
				continue
			}
			v, _ := strconv.ParseUint(f[1], 10, 64)
			if f[0] == "MemTotal:" {
				r.MemoryTotal = v * 1024
			}
			if f[0] == "MemAvailable:" {
				available = v * 1024
			}
		}
		if available <= r.MemoryTotal {
			r.MemoryUsed = r.MemoryTotal - available
		}
	}
	for _, pair := range [][2]string{{"/sys/fs/cgroup/memory.current", "/sys/fs/cgroup/memory.max"}, {"/sys/fs/cgroup/memory/memory.usage_in_bytes", "/sys/fs/cgroup/memory/memory.limit_in_bytes"}} {
		a, e := os.ReadFile(pair[0])
		b, f := os.ReadFile(pair[1])
		if e != nil || f != nil {
			continue
		}
		used, e := strconv.ParseUint(strings.TrimSpace(string(a)), 10, 64)
		limit, f := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
		if e == nil && f == nil && limit > 0 && (r.MemoryTotal == 0 || limit < r.MemoryTotal) {
			r.MemoryUsed = used
			r.MemoryTotal = limit
			r.Scope = "container"
			break
		}
	}
	var st syscall.Statfs_t
	if syscall.Statfs(path, &st) == nil {
		r.DiskAvailable = st.Bavail * uint64(st.Bsize)
		r.DiskTotal = st.Blocks * uint64(st.Bsize)
	}
	return r
}
