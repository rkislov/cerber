// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/rkislov/cerber/internal/admin"
	"github.com/rkislov/cerber/internal/agent"
	"github.com/rkislov/cerber/internal/alerts"
	"github.com/rkislov/cerber/internal/app"
	linuxcollector "github.com/rkislov/cerber/internal/collector/linux"
	"github.com/rkislov/cerber/internal/collector/windows"
	"github.com/rkislov/cerber/internal/domain"
	"github.com/rkislov/cerber/internal/endpoint"
	"github.com/rkislov/cerber/internal/eventcollector"
	"github.com/rkislov/cerber/internal/eventstore"
	"github.com/rkislov/cerber/internal/health"
	"github.com/rkislov/cerber/internal/ingest"
	"github.com/rkislov/cerber/internal/integrations"
	"github.com/rkislov/cerber/internal/inventory"
	"github.com/rkislov/cerber/internal/jobs"
	"github.com/rkislov/cerber/internal/patch"
	"github.com/rkislov/cerber/internal/storage/sqlite"
	"github.com/rkislov/cerber/internal/telemetry"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

func readCredentials(path string) (ingest.Credentials, error) { return agent.LoadCredentials(path) }

type lockedWriter struct {
	mu     sync.Mutex
	writer io.Writer
}

func (w *lockedWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.writer.Write(p)
}
func centralCommand(ctx context.Context, store *sqlite.Store, args []string, out, errOut io.Writer) error {
	errOut = &lockedWriter{writer: errOut}
	command := args[0] + " " + args[1]
	f := flags(command, errOut)
	switch command {
	case "siem agents":
		asset := f.String("asset", "", "optional server asset ID")
		after := f.String("after", "", "exclusive agent ID cursor")
		limit := f.Int("limit", 100, "page size (1–1000)")
		offline := f.Duration("offline-after", 15*time.Minute, "contact/health stale threshold (1m–24h)")
		maxAge := f.Duration("inventory-max-age", 24*time.Hour, "inventory stale threshold (1m–365d)")
		if err := parse(f, args[2:]); err != nil {
			return err
		}
		if *limit < 1 || *limit > 1000 || *offline < time.Minute || *offline > 24*time.Hour || *maxAge < time.Minute || *maxAge > 365*24*time.Hour {
			return fmt.Errorf("invalid agent status limits or freshness policy")
		}
		now := time.Now().UTC()
		agents, err := store.AgentStatuses(ctx, *asset, *after, *limit+1)
		if err != nil {
			return err
		}
		next := ""
		if len(agents) > *limit {
			agents = agents[:*limit]
			next = agents[len(agents)-1].AgentID
		}
		for i := range agents {
			agents[i].Evaluate(now, *offline, *maxAge)
		}
		return json.NewEncoder(out).Encode(struct {
			AsOf            time.Time            `json:"as_of"`
			OfflineAfter    string               `json:"offline_after"`
			InventoryMaxAge string               `json:"inventory_max_age"`
			Agents          []ingest.AgentStatus `json:"agents"`
			Next            string               `json:"next_cursor,omitempty"`
		}{now, offline.String(), maxAge.String(), agents, next})
	case "siem alerts":
		state := f.String("state", "active", "active, resolved or all")
		before := f.Int64("before", 0, "exclusive sequence cursor")
		limit := f.Int("limit", 100, "page size (1–1000)")
		if err := parse(f, args[2:]); err != nil {
			return err
		}
		if *limit < 1 || *limit > 1000 {
			return fmt.Errorf("invalid page limit")
		}
		items, err := store.Alerts(ctx, *state, *before, *limit+1)
		if err != nil {
			return err
		}
		var next int64
		if len(items) > *limit {
			items = items[:*limit]
			next = items[len(items)-1].Sequence
		}
		return json.NewEncoder(out).Encode(map[string]any{"items": items, "next_before": next})
	case "siem acknowledge":
		id := f.String("id", "", "alert ID")
		if err := parse(f, args[2:]); err != nil {
			return err
		}
		v, err := store.AcknowledgeAlert(ctx, *id, "cli")
		if err != nil {
			return err
		}
		return json.NewEncoder(out).Encode(v)
	case "siem evaluate-alerts":
		offline := f.Duration("offline-after", 15*time.Minute, "offline grace/threshold")
		maxAge := f.Duration("inventory-max-age", 24*time.Hour, "inventory grace/threshold")
		if err := parse(f, args[2:]); err != nil {
			return err
		}
		v, err := store.EvaluateAlerts(ctx, time.Now().UTC(), alerts.Policy{OfflineAfter: *offline, InventoryMaxAge: *maxAge})
		if err != nil {
			return err
		}
		return json.NewEncoder(out).Encode(v)
	case "siem user-add":
		return adminUserAdd(ctx, store, args[2:], out, errOut)
	case "siem serve":
		settingsFile := f.String("settings-file", "", "absolute encrypted integration settings file")
		settingsKey := f.String("settings-key", "", "private 32-byte integration settings key file")
		patchKey := f.String("patch-key", "", "Ed25519 private signing key for managed updates (opt-in)")
		eventArchiveDir := f.String("event-archive-dir", "", "absolute private directory for event archives; opt-in retention")
		eventsDB := f.String("events-db", "", "separate security event journal database; disabled if omitted")
		oidcConfig := f.String("oidc-config", "", "optional OpenID Connect configuration JSON")
		directoryConfig := f.String("directory-config", "", "optional LDAPS configuration JSON")
		listen := f.String("listen", "127.0.0.1:8790", "receiver address")
		cert := f.String("tls-cert", "", "TLS certificate")
		key := f.String("tls-key", "", "TLS private key")
		secureCookies := f.Bool("admin-secure-cookies", false, "HTTPS-only console behind a trusted local TLS proxy")
		adminEnabled := f.Bool("admin", false, "enable named-account administration console")
		adminKey := f.String("admin-key", "", "legacy bootstrap key JSON file; login allowed only before named users exist")
		offline := f.Duration("offline-after", 15*time.Minute, "automatic offline alert threshold/grace")
		maxAge := f.Duration("inventory-max-age", 24*time.Hour, "automatic inventory alert threshold/grace")
		checkEvery := f.Duration("monitor-interval", 30*time.Second, "alert evaluation interval (5s–1h)")
		if err := parse(f, args[2:]); err != nil {
			return err
		}
		var integrationStore *integrations.Store
		if (*settingsFile == "") != (*settingsKey == "") {
			return fmt.Errorf("both settings-file and settings-key are required")
		}
		if *settingsFile != "" {
			var e error
			integrationStore, e = integrations.Open(*settingsFile, *settingsKey)
			if e != nil {
				return e
			}
		}
		policy := alerts.Policy{OfflineAfter: *offline, InventoryMaxAge: *maxAge}
		if err := policy.Validate(); err != nil {
			return err
		}
		if *checkEvery < 5*time.Second || *checkEvery > time.Hour {
			return fmt.Errorf("monitor interval must be 5s–1h")
		}
		jobMonitor := &jobs.Monitor{}
		monitor := &alerts.Monitor{Policy: policy, Interval: *checkEvery}
		mux := http.NewServeMux()
		mux.Handle("/v1/agent/", ingest.NewHandler(store))
		if *patchKey != "" {
			k, e := patch.Private(*patchKey)
			if e != nil {
				return e
			}
			mux.Handle("/v1/agent/patches/", ingest.NewPatchHandler(store, k))
		}
		if *eventArchiveDir != "" && *eventsDB == "" {
			return fmt.Errorf("event archive directory requires -events-db")
		}
		var eventDB *eventstore.Store
		var eventReader admin.EventStore
		if *eventsDB != "" {
			if err := separateEventDatabase(*eventsDB, store.Path()); err != nil {
				return err
			}
			var err error
			eventDB, err = eventstore.Open(ctx, *eventsDB)
			if err != nil {
				return err
			}
			defer eventDB.Close()
			if *eventArchiveDir != "" {
				if err = eventDB.ConfigureArchive(*eventArchiveDir); err != nil {
					return err
				}
			}
			eventReader = eventDB
			mux.Handle("/v1/agent/events", ingest.NewEventHandler(store, eventDB))
		}
		var integrationWorker *integrations.Worker
		if integrationStore != nil {
			var engine integrations.EventEngine
			if eventDB != nil {
				engine = eventDB
			}
			var err error
			integrationWorker, err = integrations.OpenWorker(integrationStore, *settingsFile+".runtime.db", engine, store)
			if err != nil {
				return err
			}
			defer integrationWorker.Close()
		}
		var responseServer *endpoint.Server
		if *patchKey != "" {
			k, e := patch.Private(*patchKey)
			if e != nil {
				return e
			}
			var feed endpoint.Feed
			if integrationWorker != nil {
				feed = integrationWorker
			}
			var sink endpoint.EventSink
			if eventDB != nil {
				sink = eventDB
			}
			responseServer, e = endpoint.Open(store.Path()+".endpoint.db", k, feed, sink)
			if e != nil {
				return e
			}
			defer responseServer.Close()
			mux.Handle("/v1/agent/endpoint", responseServer.Handler(store))
		}
		var directory admin.Directory
		if *directoryConfig != "" {
			var err error
			directory, err = admin.LoadDirectory(*directoryConfig)
			if err != nil {
				return err
			}
			if !*adminEnabled && *adminKey == "" {
				return fmt.Errorf("directory config requires admin console")
			}
		}

		var identityProvider *admin.OIDC
		if *oidcConfig != "" {
			if !*adminEnabled && *adminKey == "" {
				return fmt.Errorf("OIDC config requires admin console")
			}
			var err error
			identityProvider, err = admin.LoadOIDC(ctx, *oidcConfig)
			if err != nil {
				return err
			}
			defer identityProvider.Close()
		}
		if *adminKey != "" || *adminEnabled {
			token := ""
			var err error
			if *adminKey != "" {
				token, err = admin.ReadKey(*adminKey)
			}
			if err != nil {
				return err
			}
			probes := []health.Probe{store.Health}
			if integrationWorker != nil {
				probes = append(probes, integrationWorker.Health)
			}
			if eventDB != nil {
				probes = append(probes, eventDB.Health)
			}
			handler, err := admin.NewHandler(store, token, admin.Options{Endpoint: responseServer, Integrations: integrationWorker, System: health.New(filepath.Dir(store.Path()), probes...), Settings: integrationStore, PatchEnabled: *patchKey != "", SecureCookies: *cert != "" || *secureCookies, Policy: policy, Monitor: monitor.Snapshot, JobMonitor: jobMonitor.Snapshot, Events: eventReader, Directory: directory, OIDC: identityProvider})
			if err != nil {
				return err
			}
			mux.Handle("/admin", handler)
			mux.Handle("/admin/", handler)
		}
		monitorCtx, stop := context.WithCancel(ctx)
		done := make(chan struct{})
		go func() {
			defer close(done)
			schedulerDone := make(chan struct{})
			go func() {
				defer close(schedulerDone)
				jobMonitor.Run(monitorCtx, store, func(err error) { fmt.Fprintf(errOut, "job scheduler: %v\n", err) })
			}()
			monitor.Run(monitorCtx, store, func(err error) { fmt.Fprintf(errOut, "alert monitor: %v\n", err) })
			<-schedulerDone
		}()
		responseDone := make(chan struct{})
		go func() {
			defer close(responseDone)
			if responseServer == nil || eventDB == nil {
				return
			}
			t := time.NewTicker(30 * time.Second)
			defer t.Stop()
			for {
				detections, e := eventDB.ReadDetections(monitorCtx, 0, 100)
				if e == nil {
					e = responseServer.Observe(monitorCtx, detections)
				}
				if e != nil && monitorCtx.Err() == nil {
					fmt.Fprintln(errOut, "response learning: operation failed")
				}
				select {
				case <-monitorCtx.Done():
					return
				case <-t.C:
				}
			}
		}()
		integrationDone := make(chan struct{})
		go func() {
			defer close(integrationDone)
			if integrationWorker != nil {
				integrationWorker.Run(monitorCtx)
			}
		}()
		eventDone := make(chan struct{})
		go func() {
			defer close(eventDone)
			if eventDB != nil {
				eventDB.Run(monitorCtx, func(err error) { fmt.Fprintf(errOut, "event pipeline: %v\n", err) })
			}
		}()
		defer func() { stop(); <-done; <-eventDone; <-integrationDone; <-responseDone }()
		return serveHTTP(ctx, mux, *listen, *cert, *key, "SIEM receiver", 2*time.Minute, 2*time.Minute, errOut)
	case "siem enroll":
		asset := f.String("asset", "", "server asset ID")
		file := f.String("out", "", "new credentials file; copy securely to agent")
		if err := parse(f, args[2:]); err != nil {
			return err
		}
		id, err := domain.NewID()
		if err != nil {
			return err
		}
		var secret [32]byte
		if _, err = rand.Read(secret[:]); err != nil {
			return err
		}
		c := ingest.Credentials{AgentID: id, Token: hex.EncodeToString(secret[:])}
		data, _ := json.MarshalIndent(c, "", "  ")
		dest, err := os.OpenFile(*file, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return err
		}
		_, err = dest.Write(data)
		if err == nil {
			err = dest.Sync()
		}
		closeErr := dest.Close()
		if err == nil {
			err = closeErr
		}
		if err == nil {
			err = store.RegisterAgent(ctx, id, *asset, ingest.Hash([]byte(c.Token)))
		}
		if err != nil {
			os.Remove(*file)
			return err
		}
		return json.NewEncoder(out).Encode(map[string]string{"agent_id": id, "asset_id": *asset, "credentials_file": *file})
	case "siem revoke":
		id := f.String("agent", "", "agent ID")
		if err := parse(f, args[2:]); err != nil {
			return err
		}
		if err := store.RevokeAgent(ctx, *id); err != nil {
			return err
		}
		return json.NewEncoder(out).Encode(map[string]string{"revoked": *id})
	}
	endpointState := f.String("endpoint-state", "", "opt-in private endpoint state file")
	endpointKey := f.String("endpoint-key", "", "trusted endpoint signing public key")
	patchInbox := f.String("patch-inbox", "", "opt-in signed patch request directory")
	patchOutbox := f.String("patch-outbox", "", "read-only executor results directory")
	credentials := f.String("credentials", "", "agent credentials JSON file")
	server := f.String("server", "", "SIEM HTTPS origin (required for flush/run)")
	ca := f.String("ca-cert", "", "additional trusted CA PEM")
	asset := f.String("asset", "", "local asset ID")
	snapshot := f.String("inventory", "", "inventory snapshot ID for enqueue")
	windowsOnline := f.Bool("check-windows-updates", false, "query configured Windows update service")
	packages := f.Bool("check-package-updates", false, "query native Linux package update candidates")
	refresh := f.Bool("refresh-package-metadata", false, "refresh configured Linux repository metadata")
	manager := f.String("package-manager", "auto", "Linux package manager")
	eventSources := f.String("event-sources", "", "opt-in sources: journald or windows:Security,windows:System,windows:Application")
	heartbeat := f.Duration("heartbeat-interval", time.Minute, "heartbeat interval for run (1m–1h)")
	interval := f.Duration("interval", time.Hour, "collection interval for run (1m–24h)")
	if err := parse(f, args[2:]); err != nil {
		return err
	}
	allowed := map[string]bool{"credentials": true}
	switch command {
	case "agent enqueue":
		allowed["inventory"] = true
	case "agent flush":
		allowed["server"] = true
		allowed["ca-cert"] = true
	case "agent collect", "agent run":
		for _, name := range []string{"asset", "check-windows-updates", "check-package-updates", "refresh-package-metadata", "package-manager"} {
			allowed[name] = true
		}
		if command == "agent run" {
			allowed["server"] = true
			allowed["ca-cert"] = true
			allowed["event-sources"] = true
			allowed["interval"] = true
			allowed["heartbeat-interval"] = true
			allowed["patch-inbox"] = true
			allowed["endpoint-state"] = true
			allowed["endpoint-key"] = true
			allowed["patch-outbox"] = true
		}
	}
	var invalid string
	f.Visit(func(flag *flag.Flag) {
		if !allowed[flag.Name] {
			invalid = flag.Name
		}
	})
	if invalid != "" {
		return fmt.Errorf("flag -%s does not apply to %s", invalid, command)
	}
	c, err := readCredentials(*credentials)
	if err != nil {
		return err
	}
	if *refresh && !*packages {
		return fmt.Errorf("metadata refresh requires package update checking")
	}
	if command == "agent collect" || command == "agent run" {
		if *asset == "" {
			return fmt.Errorf("local asset ID is required")
		}
		switch runtime.GOOS {
		case "windows":
			if *packages || *refresh || *manager != "auto" {
				return fmt.Errorf("Linux flags require Linux")
			}
		case "linux":
			if *windowsOnline {
				return fmt.Errorf("Windows update flag requires Windows")
			}
		default:
			return fmt.Errorf("native agent collection requires Windows or Linux")
		}
		switch *manager {
		case "auto", "apt", "apt-rpm", "dnf", "yum":
		default:
			return fmt.Errorf("unknown package manager")
		}
	}
	sources, err := parseEventSources(*eventSources)
	if err != nil {
		return err
	}
	health := &agent.Health{}
	initialEvents := telemetry.CollectorHealth{Enabled: len(sources) > 0, ObservedAt: time.Now().UTC(), Delivery: "not_attempted", Sources: []telemetry.SourceHealth{}}
	for _, s := range sources {
		initialEvents.Sources = append(initialEvents.Sources, telemetry.SourceHealth{Source: s.Name(), State: "not_attempted"})
	}
	health.EventsObserved(initialEvents)
	collect := func() (inventory.Snapshot, error) {
		svc := app.InventoryService{Store: store, Assets: store}
		switch runtime.GOOS {
		case "windows":
			if *packages || *refresh || *manager != "auto" {
				return inventory.Snapshot{}, fmt.Errorf("Linux flags require Linux")
			}
			return svc.CollectLocal(ctx, *asset, windows.Collector{CheckAvailable: *windowsOnline})
		case "linux":
			if *windowsOnline {
				return inventory.Snapshot{}, fmt.Errorf("Windows update flag requires Windows")
			}
			return svc.CollectLocal(ctx, *asset, linuxcollector.Collector{CheckAvailable: *packages, RefreshMetadata: *refresh, Manager: *manager})
		default:
			return inventory.Snapshot{}, fmt.Errorf("native agent collection requires Windows or Linux")
		}
	}
	queue := func() (ingest.Report, error) {
		count, size, err := store.QueueUsage(ctx)
		if err != nil {
			return ingest.Report{}, err
		}
		if count >= 100 || size >= 256<<20 {
			return ingest.Report{}, fmt.Errorf("agent queue full; flush before collecting")
		}
		s, err := collect()
		health.Collected(s, err)
		if err != nil {
			return ingest.Report{}, err
		}
		return store.QueueInventory(ctx, c.AgentID, s.ID)
	}
	switch command {
	case "agent enqueue":
		r, err := store.QueueInventory(ctx, c.AgentID, *snapshot)
		if err != nil {
			return err
		}
		return json.NewEncoder(out).Encode(map[string]string{"queued_report_id": r.ID, "inventory_id": r.Snapshot.ID})
	case "agent collect":
		r, err := queue()
		if err != nil {
			return err
		}
		return json.NewEncoder(out).Encode(map[string]string{"queued_report_id": r.ID, "inventory_id": r.Snapshot.ID})
	}
	if command != "agent flush" && command != "agent run" {
		return fmt.Errorf("unknown agent command")
	}
	var caPEM []byte
	if *ca != "" {
		caPEM, err = os.ReadFile(*ca)
		if err != nil {
			return err
		}
	}
	client, err := ingest.NewClient(*server, c, caPEM)
	if err != nil {
		return err
	}
	defer client.Close()
	if command == "agent flush" {
		n, err := agent.Flush(ctx, store, client, c.AgentID)
		if err != nil {
			return err
		}
		return json.NewEncoder(out).Encode(map[string]int{"delivered": n})
	}
	if *interval < time.Minute || *interval > 24*time.Hour {
		return fmt.Errorf("collection interval must be 1m–24h")
	}
	if *heartbeat < time.Minute || *heartbeat > time.Hour {
		return fmt.Errorf("heartbeat interval must be 1m–1h")
	}
	heartbeatCtx, stopHeartbeat := context.WithCancel(ctx)
	heartbeatDone := make(chan struct{})
	go func() {
		defer close(heartbeatDone)
		agent.RunHeartbeats(heartbeatCtx, store, client, c.AgentID, health, *heartbeat, func(err error) { fmt.Fprintf(errOut, "agent heartbeat: %v\n", err) })
	}()
	defer func() { stopHeartbeat(); <-heartbeatDone }()
	var endpointAgent *endpoint.Local
	if *endpointState != "" {
		var e error
		endpointAgent, e = endpoint.OpenLocal(*endpointState, *endpointKey, c.AgentID)
		if e != nil {
			return e
		}
	}
	if endpointAgent != nil {
		for i, source := range sources {
			sources[i] = eventcollector.ObservedSource{Source: source, Observe: endpointAgent.ObserveEvents}
		}
	}
	var eventSpool *eventstore.Store
	if len(sources) > 0 {
		if store.Path() == ":memory:" || strings.HasPrefix(store.Path(), "file:") {
			return fmt.Errorf("event collection requires a durable filesystem database")
		}
		eventSpool, err = eventstore.Open(ctx, store.Path()+".events")
		if err != nil {
			return err
		}
		defer eventSpool.Close()
	}
	eventCtx, stopEvents := context.WithCancel(ctx)
	eventDone := make(chan struct{})
	go func() {
		defer close(eventDone)
		if eventSpool == nil {
			return
		}
		for {
			eventHealth := eventcollector.Cycle(eventCtx, eventSpool, client, c.AgentID, sources, func(e error) {
				if eventCtx.Err() == nil {
					fmt.Fprintf(errOut, "agent events: %v\n", e)
				}
			})
			health.EventsObserved(eventHealth)
			t := time.NewTimer(10 * time.Second)
			select {
			case <-eventCtx.Done():
				t.Stop()
				return
			case <-t.C:
			}
		}
	}()
	defer func() { stopEvents(); <-eventDone }()
	if (*patchInbox == "") != (*patchOutbox == "") {
		return fmt.Errorf("both patch spool paths required")
	}
	if *patchInbox != "" {
		if !filepath.IsAbs(*patchInbox) || !filepath.IsAbs(*patchOutbox) || *patchInbox == *patchOutbox {
			return fmt.Errorf("separate absolute patch spool paths required")
		}
	}
	worker := agent.Worker{Store: store, Client: client, AgentID: c.AgentID, Execute: func(jobCtx context.Context, job jobs.Job) jobs.Result {
		fail := func(code string) jobs.Result { return jobs.Result{JobID: job.ID, Status: "failed", Code: code} }
		count, size, e := store.QueueUsage(jobCtx)
		if e != nil {
			return fail("collection_failed")
		}
		if count >= 100 || size >= 256<<20 {
			return fail("queue_full")
		}
		svc := app.InventoryService{Store: store, Assets: store}
		var snapshot inventory.Snapshot
		switch runtime.GOOS {
		case "windows":
			snapshot, e = svc.CollectLocal(jobCtx, *asset, windows.Collector{CheckAvailable: job.Kind == "updates"})
		case "linux":
			snapshot, e = svc.CollectLocal(jobCtx, *asset, linuxcollector.Collector{CheckAvailable: job.Kind == "updates", RefreshMetadata: job.RefreshMetadata, Manager: *manager})
		default:
			return fail("unsupported_platform")
		}
		health.Collected(snapshot, e)
		if e != nil {
			return fail("collection_failed")
		}
		report, e := store.QueueInventory(jobCtx, c.AgentID, snapshot.ID)
		if e != nil {
			return fail("collection_failed")
		}
		return agent.JobResult(job, snapshot, report.ID)
	}}

	nextCollection := time.Time{}
	retry := 30 * time.Second
	for {
		if ctx.Err() != nil {
			return nil
		}
		n, deliveryErr := agent.Flush(ctx, store, client, c.AgentID)
		health.Delivered(n, deliveryErr)
		if deliveryErr != nil {
			fmt.Fprintf(errOut, "agent delivery: %v\n", deliveryErr)
		} else if n > 0 {
			fmt.Fprintf(errOut, "agent delivered %d report(s)\n", n)
		}
		if endpointAgent != nil {
			if e := endpointAgent.Step(ctx, client); e != nil && ctx.Err() == nil {
				fmt.Fprintf(errOut, "endpoint: %v\n", e)
			}
		}
		if *patchInbox != "" {
			if e := agent.PatchStep(ctx, client, *patchInbox, *patchOutbox); e != nil && ctx.Err() == nil {
				fmt.Fprintf(errOut, "agent patches: %v\n", e)
			}
		}
		if err := worker.Step(ctx); err != nil && ctx.Err() == nil {
			fmt.Fprintf(errOut, "agent job: %v\n", err)
		}
		if !time.Now().Before(nextCollection) {
			r, err := queue()
			nextCollection = time.Now().Add(*interval)
			if err != nil {
				fmt.Fprintf(errOut, "agent collection: %v\n", err)
			} else {
				fmt.Fprintf(errOut, "agent queued report %s\n", r.ID)
				delivered, flushErr := agent.Flush(ctx, store, client, c.AgentID)
				deliveryErr = flushErr
				health.Delivered(delivered, deliveryErr)
				if deliveryErr != nil {
					fmt.Fprintf(errOut, "agent delivery: %v\n", deliveryErr)
				}
			}
		}
		if deliveryErr == nil {
			retry = 30 * time.Second
		} else if retry < 5*time.Minute {
			retry *= 2
			if retry > 5*time.Minute {
				retry = 5 * time.Minute
			}
		}
		delay := retry
		until := time.Until(nextCollection)
		if until < delay {
			delay = until
		}
		if delay < time.Second {
			delay = time.Second
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-timer.C:
		}
	}
}
