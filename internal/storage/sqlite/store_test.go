package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rkislov/cerber/internal/domain"
	"github.com/rkislov/cerber/internal/event"
)

func seed(t *testing.T, s *Store) domain.Task {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC()
	a := domain.Asset{ID: "asset", IP: "127.0.0.1", Name: "test", CreatedAt: now}
	e, _ := event.New("asset.created", a.ID, a)
	if err := s.CreateAsset(ctx, a, e); err != nil {
		t.Fatal(err)
	}
	target := domain.Target{ID: "target", Name: "test", AssetIDs: []string{a.ID}, CreatedAt: now}
	e, _ = event.New("target.created", target.ID, target)
	if err := s.CreateTarget(ctx, target, e); err != nil {
		t.Fatal(err)
	}
	task := domain.Task{ID: "task", TargetID: target.ID, Status: domain.Queued, Hosts: []domain.Host{{AssetID: a.ID, IP: a.IP}}, Config: domain.ScanConfig{Ports: []uint16{22}, Concurrency: 1, TimeoutMS: 100}, CreatedAt: now}
	e, _ = event.New("task.created", task.ID, task)
	if err := s.CreateTask(ctx, task, e); err != nil {
		t.Fatal(err)
	}
	return task
}
func TestConcurrentClaimsAcrossConnections(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "db")
	a, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	task := seed(t, a)
	b, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	start := make(chan struct{})
	results := make(chan error, 2)
	var wg sync.WaitGroup
	for _, s := range []*Store{a, b} {
		wg.Add(1)
		go func(s *Store) {
			defer wg.Done()
			<-start
			e, _ := event.New("task.started", task.ID, nil)
			results <- s.ClaimTask(ctx, task.ID, nil, e)
		}(s)
	}
	close(start)
	wg.Wait()
	close(results)
	wins, conflicts := 0, 0
	for err := range results {
		if err == nil {
			wins++
		} else if errors.Is(err, domain.ErrConflict) {
			conflicts++
		} else {
			t.Fatal(err)
		}
	}
	if wins != 1 || conflicts != 1 {
		t.Fatal(wins, conflicts)
	}
	events, err := a.Events(ctx, 0, 100)
	if err != nil || len(events) != 4 {
		t.Fatal(events, err)
	}
}
func TestObservationRollsBackWhenOutboxFails(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx, filepath.Join(t.TempDir(), "db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	task := seed(t, s)
	e, _ := event.New("task.started", task.ID, nil)
	if err = s.ClaimTask(ctx, task.ID, nil, e); err != nil {
		t.Fatal(err)
	}
	o := domain.Observation{TaskID: task.ID, AssetID: "asset", IP: "127.0.0.1", Port: 22, Protocol: "tcp", State: domain.Open, ObservedAt: time.Now().UTC()}
	// Reusing an existing event ID forces the outbox INSERT to fail after the observation INSERT.
	if err = s.RecordObservation(ctx, o, e); err == nil {
		t.Fatal("expected duplicate event failure")
	}
	obs, err := s.Observations(ctx, task.ID)
	if err != nil || len(obs) != 0 {
		t.Fatal(obs, err)
	}
	good, _ := event.New("scan.port_observed", task.ID, o)
	if err = s.RecordObservation(ctx, o, good); err != nil {
		t.Fatal(err)
	}
	if err = s.RecordObservation(ctx, o, good); err == nil {
		t.Fatal("duplicate observation accepted")
	}
}
func TestRejectsFutureSchema(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "db")
	s, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.db.Exec("PRAGMA user_version=999"); err != nil {
		t.Fatal(err)
	}
	s.Close()
	if reopened, err := Open(ctx, path); err == nil {
		reopened.Close()
		t.Fatal("future schema accepted")
	}
}

func TestTimestampSortPreservesChronology(t *testing.T) {
	base := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)
	later := base.Add(time.Nanosecond)
	if stamp(base) >= stamp(later) {
		t.Fatal("SQL text ordering must preserve timestamp order")
	}
	parsed, err := parse(stamp(later))
	if err != nil || !parsed.Equal(later) {
		t.Fatal(parsed, err)
	}
}

func TestMigratesVersionOneDatabase(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	oldSchema := strings.Replace(schema, ",\n knowledge_snapshot TEXT CHECK(knowledge_snapshot IS NULL OR json_valid(knowledge_snapshot))", "", 1)
	if strings.Contains(oldSchema, "knowledge_snapshot") {
		t.Fatal("fixture did not remove new column")
	}
	if _, err = db.Exec(oldSchema); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec("PRAGMA user_version=1"); err != nil {
		t.Fatal(err)
	}
	task := seed(t, &Store{db: db})
	db.Close()
	s, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	var version int
	if err = s.db.QueryRow("PRAGMA user_version").Scan(&version); err != nil || version != 2 {
		t.Fatal(version, err)
	}
	assets, err := s.Assets(ctx)
	if err != nil || len(assets) != 1 || assets[0].ID != "asset" {
		t.Fatal(assets, err)
	}
	e, _ := event.New("task.started", task.ID, nil)
	if err = s.ClaimTask(ctx, task.ID, nil, e); err != nil {
		t.Fatal(err)
	}
	stored, err := s.Task(ctx, task.ID)
	if err != nil || stored.Knowledge != nil {
		t.Fatal(stored, err)
	}
}
