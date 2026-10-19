package app_test

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rkislov/cerber/internal/app"
	"github.com/rkislov/cerber/internal/domain"
	"github.com/rkislov/cerber/internal/event"
	"github.com/rkislov/cerber/internal/scanner/tcp"
	"github.com/rkislov/cerber/internal/storage/sqlite"
)

func fixture(t *testing.T) (*sqlite.Store, app.Service, domain.Task) {
	t.Helper()
	ctx := context.Background()
	db, err := sqlite.Open(ctx, filepath.Join(t.TempDir(), "cerber.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	svc := app.Service{Repo: db, Scanner: tcp.Scanner{}}
	a, err := svc.AddAsset(ctx, "127.0.0.1", "loopback")
	if err != nil {
		t.Fatal(err)
	}
	target, err := svc.AddTarget(ctx, "test", []string{a.ID})
	if err != nil {
		t.Fatal(err)
	}
	task, err := svc.CreateTask(ctx, target.ID, domain.ScanConfig{Ports: []uint16{12345}, Concurrency: 2, TimeoutMS: 100})
	if err != nil {
		t.Fatal(err)
	}
	return db, svc, task
}
func TestEndToEndPersistsAcrossReopen(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "cerber.db")
	db, err := sqlite.Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	svc := app.Service{Repo: db, Scanner: tcp.Scanner{}}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	a, err := svc.AddAsset(ctx, "::ffff:127.0.0.1", "local")
	if err != nil {
		t.Fatal(err)
	}
	if a.IP != "127.0.0.1" {
		t.Fatal("IP was not canonicalized")
	}
	target, err := svc.AddTarget(ctx, "local", []string{a.ID})
	if err != nil {
		t.Fatal(err)
	}
	task, err := svc.CreateTask(ctx, target.ID, domain.ScanConfig{Ports: []uint16{uint16(ln.Addr().(*net.TCPAddr).Port)}, Concurrency: 1, TimeoutMS: 1000})
	if err != nil {
		t.Fatal(err)
	}
	if err = svc.Run(ctx, task.ID); err != nil {
		t.Fatal(err)
	}
	if err = svc.Run(ctx, task.ID); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("second run: %v", err)
	}
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err = sqlite.Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	stored, err := db.Task(ctx, task.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Status != domain.Completed || stored.StartedAt == nil || stored.FinishedAt == nil {
		t.Fatalf("%+v", stored)
	}
	results, err := db.Observations(ctx, task.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 || results[0].State != domain.Open {
		t.Fatalf("%+v", results)
	}
	all, err := db.Events(ctx, 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"asset.created", "target.created", "task.created", "task.started", "scan.port_observed", "task.finished"}
	if len(all) != len(want) {
		t.Fatalf("events: %+v", all)
	}
	for i, e := range all {
		if e.Kind != want[i] || e.SchemaVersion != 1 || !json.Valid(e.Payload) {
			t.Fatalf("event %d: %+v", i, e)
		}
	}
	page, err := db.Events(ctx, all[3].Sequence, 1)
	if err != nil || len(page) != 1 || page[0].ID != all[4].ID {
		t.Fatal("cursor", page, err)
	}
}
func TestMutationAndEventAreAtomic(t *testing.T) {
	db, svc, _ := fixture(t)
	ctx := context.Background()
	before, err := db.Events(ctx, 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	e, err := event.New("asset.created", "rollback", nil)
	if err != nil {
		t.Fatal(err)
	}
	e.Payload = json.RawMessage(`not json`)
	a := domain.Asset{ID: "rollback", IP: "127.0.0.2", Name: "rollback", CreatedAt: time.Now().UTC()}
	if err = db.CreateAsset(ctx, a, e); err == nil {
		t.Fatal("invalid event should roll back asset")
	}
	assets, err := db.Assets(ctx)
	if err != nil || len(assets) != 1 {
		t.Fatal(assets, err)
	}
	if _, err = svc.AddTarget(ctx, "bad", []string{"missing"}); err == nil {
		t.Fatal("missing foreign key accepted")
	}
	targets, err := db.Targets(ctx)
	if err != nil || len(targets) != 1 {
		t.Fatal(targets, err)
	}
	after, err := db.Events(ctx, 0, 100)
	if err != nil || len(after) != len(before) {
		t.Fatal("failed transaction published event", after, err)
	}
}

type scannerFunc func(context.Context, domain.Task, func(domain.Observation) error) error

func (f scannerFunc) Scan(ctx context.Context, t domain.Task, emit func(domain.Observation) error) error {
	return f(ctx, t, emit)
}
func TestCancellationPersistsPartialResults(t *testing.T) {
	db, svc, task := fixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	svc.Scanner = scannerFunc(func(ctx context.Context, t domain.Task, emit func(domain.Observation) error) error {
		if err := emit(domain.Observation{TaskID: t.ID, AssetID: t.Hosts[0].AssetID, IP: t.Hosts[0].IP, Port: t.Config.Ports[0], Protocol: "tcp", State: domain.Open, ObservedAt: time.Now().UTC()}); err != nil {
			return err
		}
		cancel()
		return ctx.Err()
	})
	if err := svc.Run(ctx, task.ID); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	stored, err := db.Task(context.Background(), task.ID)
	if err != nil || stored.Status != domain.Interrupted {
		t.Fatal(stored, err)
	}
	results, err := db.Observations(context.Background(), task.ID)
	if err != nil || len(results) != 1 {
		t.Fatal(results, err)
	}
}
func TestConcurrentRunClaimsOnlyOnce(t *testing.T) {
	db, svc, task := fixture(t)
	var calls atomic.Int32
	entered, release := make(chan struct{}), make(chan struct{})
	svc.Scanner = scannerFunc(func(context.Context, domain.Task, func(domain.Observation) error) error {
		calls.Add(1)
		close(entered)
		<-release
		return errors.New("test failure")
	})
	first := make(chan error, 1)
	go func() { first <- svc.Run(context.Background(), task.ID) }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("scanner did not start")
	}
	err := svc.Run(context.Background(), task.ID)
	close(release)
	if !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("concurrent claim %v", err)
	}
	if err = <-first; err == nil {
		t.Fatal("expected scanner failure")
	}
	stored, err := db.Task(context.Background(), task.ID)
	if err != nil || stored.Status != domain.Failed || calls.Load() != 1 {
		t.Fatal(stored, err, calls.Load())
	}
}

type knowledgeFunc func(context.Context) (domain.KnowledgeSnapshot, error)

func (f knowledgeFunc) Acquire(ctx context.Context) (domain.KnowledgeSnapshot, error) { return f(ctx) }

func TestKnowledgeSnapshotAcquiredAndPinnedBeforeScan(t *testing.T) {
	db, svc, task := fixture(t)
	snapshot := domain.KnowledgeSnapshot{ID: "bdu-bundle", Version: "2026-10-19.1", SHA256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}
	called := false
	svc.Knowledge = knowledgeFunc(func(context.Context) (domain.KnowledgeSnapshot, error) { called = true; return snapshot, nil })
	svc.Scanner = scannerFunc(func(ctx context.Context, input domain.Task, _ func(domain.Observation) error) error {
		if !called || input.Knowledge == nil || *input.Knowledge != snapshot || input.Status != domain.Running || input.StartedAt == nil {
			t.Fatal("snapshot not passed to scanner")
		}
		persisted, err := db.Task(ctx, input.ID)
		if err != nil || persisted.Knowledge == nil || *persisted.Knowledge != snapshot || persisted.Status != domain.Running {
			t.Fatal(persisted, err)
		}
		return errors.New("stop after snapshot check")
	})
	if err := svc.Run(context.Background(), task.ID); err == nil {
		t.Fatal("expected scanner error")
	}
	stored, err := db.Task(context.Background(), task.ID)
	if err != nil || stored.Knowledge == nil || *stored.Knowledge != snapshot {
		t.Fatal(stored, err)
	}
	events, err := db.Events(context.Background(), 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	var start map[string]json.RawMessage
	if err = json.Unmarshal(events[3].Payload, &start); err != nil {
		t.Fatal(err)
	}
	var recorded domain.KnowledgeSnapshot
	if err = json.Unmarshal(start["knowledge_snapshot"], &recorded); err != nil || recorded != snapshot {
		t.Fatal(recorded, err)
	}
}
func TestKnowledgeFailureLeavesTaskQueued(t *testing.T) {
	for _, invalid := range []bool{false, true} {
		t.Run(map[bool]string{false: "offline", true: "invalid manifest"}[invalid], func(t *testing.T) {
			db, svc, task := fixture(t)
			svc.Knowledge = knowledgeFunc(func(context.Context) (domain.KnowledgeSnapshot, error) {
				if invalid {
					return domain.KnowledgeSnapshot{}, nil
				}
				return domain.KnowledgeSnapshot{}, errors.New("server unavailable")
			})
			svc.Scanner = scannerFunc(func(context.Context, domain.Task, func(domain.Observation) error) error {
				t.Fatal("scan started without knowledge")
				return nil
			})
			if err := svc.Run(context.Background(), task.ID); err == nil {
				t.Fatal("expected knowledge error")
			}
			stored, err := db.Task(context.Background(), task.ID)
			if err != nil || stored.Status != domain.Queued || stored.Knowledge != nil {
				t.Fatal(stored, err)
			}
			events, err := db.Events(context.Background(), 0, 100)
			if err != nil || len(events) != 3 {
				t.Fatal(events, err)
			}
		})
	}
}
