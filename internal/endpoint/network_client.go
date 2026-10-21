// SPDX-License-Identifier: Apache-2.0
package endpoint

import (
	"context"
	"encoding/json"
	"github.com/rkislov/cerber/internal/netscan"
	"os"
	"sync"
	"time"
)

type networkWorker struct {
	mu     sync.Mutex
	task   string
	cancel context.CancelFunc
	result *netscan.Result
}

func (l *Local) networkReport() *netscan.Result {
	l.network.mu.Lock()
	defer l.network.mu.Unlock()
	if l.network.task != "" {
		return nil
	}
	if l.network.result == nil {
		data, e := os.ReadFile(l.path + ".network")
		if e == nil && len(data) <= 1<<20 {
			var r netscan.Result
			if json.Unmarshal(data, &r) == nil {
				if r.State == "running" {
					r.State = "interrupted"
					r.Finished = time.Now().UTC()
					r.Error = "Agent restarted during scan; result is incomplete"
				}
				l.network.result = &r
			}
		}
	}
	return l.network.result
}
func (l *Local) networkStep(ctx context.Context, t *netscan.Task) error {
	w := &l.network
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.task != "" {
		if t == nil || t.ID != w.task {
			w.cancel()
		}
		return nil
	}
	if w.result != nil {
		if t != nil && t.ID == w.result.ID {
			return nil
		}
		if e := os.Remove(l.path + ".network"); e != nil && !os.IsNotExist(e) {
			return e
		}
		w.result = nil
	}
	if t == nil || !time.Now().Before(t.Expires) || t.Validate() != nil {
		return nil
	}
	running := netscan.Result{ID: t.ID, State: "running", Started: time.Now().UTC()}
	b, _ := json.Marshal(running)
	if e := writeBlob(l.path+".network", b); e != nil {
		return e
	}
	runCtx, cancel := context.WithDeadline(ctx, t.Expires)
	w.task = t.ID
	w.cancel = cancel
	task := *t
	go func() {
		r := netscan.Execute(runCtx, task)
		cancel()
		w.mu.Lock()
		defer w.mu.Unlock()
		b, _ := json.Marshal(r)
		if len(b) > 512<<10 {
			r.State = "failed"
			r.Hosts = nil
			r.Error = "Result exceeded 512 KiB; use a smaller scan window"
			b, _ = json.Marshal(r)
		}
		if e := writeBlob(l.path+".network", b); e != nil {
			r.State = "failed"
			r.Error = "Could not persist network result"
		}
		w.result = &r
		w.task = ""
	}()
	return nil
}
