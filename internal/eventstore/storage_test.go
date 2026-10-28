// SPDX-License-Identifier: Apache-2.0
package eventstore

import (
	"context"
	"database/sql"
	"errors"
	"github.com/rkislov/cerber/internal/telemetry"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func storageFixture(t *testing.T) *Store {
	t.Helper()
	s, e := Open(context.Background(), filepath.Join(t.TempDir(), "events.db"))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { s.Close() })
	s.spaceProbe = func(string) (uint64, uint64, string, error) { return 1 << 40, 2 << 40, "fixture", nil }
	return s
}
func TestStorageBackpressureAtomicAndAcknowledgedRetry(t *testing.T) {
	ctx := context.Background()
	s := storageFixture(t)
	b := journalBatch("agent", 0, 2, time.Now())
	first, e := s.Accept(ctx, "agent", "asset", b)
	if e != nil {
		t.Fatal(e)
	}
	s.spaceProbe = func(string) (uint64, uint64, string, error) { return 0, 40 << 30, "full", nil }
	again, e := s.Accept(ctx, "agent", "asset", b)
	if e != nil || again != first {
		t.Fatal("acknowledged retry lost", again, e)
	}
	next := journalBatch("agent", 2, 2, time.Now())
	if _, e = s.Accept(ctx, "agent", "asset", next); !errors.Is(e, telemetry.ErrStorageProtected) {
		t.Fatal(e)
	}
	v, e := s.Status(ctx)
	if e != nil || v.Raw != 2 {
		t.Fatal("partial write", v, e)
	}
	var receipts int
	s.db.QueryRow("SELECT count(*) FROM batch_receipts").Scan(&receipts)
	if receipts != 1 {
		t.Fatal(receipts)
	}
	s.spaceProbe = func(string) (uint64, uint64, string, error) { return 1 << 40, 2 << 40, "ok", nil }
	if _, e = s.Accept(ctx, "agent", "asset", next); e != nil {
		t.Fatal("did not recover", e)
	}
}
func TestPhysicalAndSeparateArchiveBudgets(t *testing.T) {
	p := telemetry.RetentionPolicy{DatabaseMaxBytes: 12 << 30, ArchiveMaxBytes: 4 << 30, MinFreeBytes: 3 << 30}
	v := telemetry.StorageStatus{HotBytes: 11 << 30, ArchiveBytes: 1 << 30, DiskAvailable: 6 << 30, ArchiveAvailable: 5 << 30}
	if storageReason(v, p, 32<<20, false, true) != "" {
		t.Fatal("healthy storage blocked")
	}
	v.WALBytes = 2 << 30
	v.HotBytes += v.WALBytes
	if !strings.Contains(storageReason(v, p, 32<<20, false, true), "SQLite") {
		t.Fatal("WAL excluded")
	}
	v.HotBytes = 11 << 30
	v.ArchiveAvailable = 512 << 20
	if storageReason(v, p, 32<<20, false, true) == "" {
		t.Fatal("archive volume ignored")
	}
	v.ArchiveAvailable = 5 << 30
	v.ArchiveBytes = 4 << 30
	if storageReason(v, p, 32<<20, false, true) == "" {
		t.Fatal("archive budget ignored")
	}
	v.DiskAvailable = 2 << 30
	if storageReason(v, p, 32<<20, true, true) != "" {
		t.Fatal("maintenance cannot recover below ingestion reserve")
	}
	v.DiskAvailable = 256 << 20
	if storageReason(v, p, 32<<20, true, true) == "" {
		t.Fatal("maintenance exhausted emergency reserve")
	}
}
func TestArchiveBudgetFailurePreservesHotEvidence(t *testing.T) {
	s, root, _ := oldJournal(t)
	ctx := context.Background()
	s.spaceProbe = func(string) (uint64, uint64, string, error) { return 1 << 40, 2 << 40, "fixture", nil }
	status, _ := s.RetentionStatus(ctx)
	p := status.Policy
	p.ArchiveMaxBytes = 256 << 20
	if e := s.SetRetention(ctx, p, "admin", time.Now()); e != nil {
		t.Fatal(e)
	}
	f, e := os.Create(filepath.Join(root, "unindexed-file"))
	if e != nil {
		t.Fatal(e)
	}
	if e = f.Truncate(256 << 20); e != nil {
		t.Fatal(e)
	}
	f.Close()
	s.archiveUsageAt = time.Time{}
	if _, e = s.Maintain(ctx, time.Now()); !errors.Is(e, telemetry.ErrStorageProtected) {
		t.Fatal(e)
	}
	v, _ := s.Status(ctx)
	if v.Raw != 2 || v.Normalized != 2 {
		t.Fatal("hot originals deleted", v)
	}
	list, _ := s.Archives(ctx, 0)
	if len(list) != 0 {
		t.Fatal(list)
	}
	os.Remove(filepath.Join(root, "unindexed-file"))
	s.archiveUsageAt = time.Time{}
	if n, e := s.Maintain(ctx, time.Now()); e != nil || n != 2 {
		t.Fatal(n, e)
	}
	status, e = s.RetentionStatus(ctx)
	if e != nil || status.Storage.ArchiveFiles != 1 || status.Storage.ArchiveBytes <= 0 {
		t.Fatal(status, e)
	}
}
func TestCheckpointKeepsBusyReaderSnapshot(t *testing.T) {
	s := storageFixture(t)
	ctx := context.Background()
	b := journalBatch("agent", 0, 2, time.Now())
	if _, e := s.Accept(ctx, "agent", "asset", b); e != nil {
		t.Fatal(e)
	}
	other, e := sql.Open("sqlite", s.path)
	if e != nil {
		t.Fatal(e)
	}
	defer other.Close()
	tx, e := other.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if e != nil {
		t.Fatal(e)
	}
	var count int
	if e = tx.QueryRow("SELECT count(*) FROM raw_events").Scan(&count); e != nil {
		t.Fatal(e)
	}
	if _, e = s.Accept(ctx, "agent", "asset", journalBatch("agent", 2, 2, time.Now())); e != nil {
		t.Fatal(e)
	}
	if e = s.CheckpointStorage(ctx); e != nil {
		t.Fatal(e)
	}
	if !s.checkpointBusy {
		t.Fatal("reader pin not reported")
	}
	if e = tx.QueryRow("SELECT count(*) FROM raw_events").Scan(&count); e != nil || count != 2 {
		t.Fatal("reader snapshot changed", count, e)
	}
	tx.Rollback()
	if e = s.CheckpointStorage(ctx); e != nil {
		t.Fatal(e)
	}
	n, e := fileBytes(s.path + "-wal")
	if e != nil || n != 0 || s.checkpointBusy {
		t.Fatal(n, e)
	}
	v, _ := s.Status(ctx)
	if v.Raw != 4 {
		t.Fatal(v)
	}
}
func TestCapacityProbeFailureClosesAdmission(t *testing.T) {
	s := storageFixture(t)
	s.spaceProbe = func(string) (uint64, uint64, string, error) { return 0, 0, "", errors.New("probe unavailable") }
	ctx := context.Background()
	if _, e := s.Accept(ctx, "agent", "asset", journalBatch("agent", 0, 1, time.Now())); !errors.Is(e, telemetry.ErrStorageProtected) {
		t.Fatal(e)
	}
	v, e := s.RetentionStatus(ctx)
	if e != nil || v.Storage.AdmissionAllowed || v.Storage.MeasurementError == "" {
		t.Fatal(v, e)
	}
	if e = s.SamplePipelineHealth(ctx, time.Now()); e != nil {
		t.Fatal(e)
	}
	h, _ := s.PipelineHealth(ctx)
	found := false
	for _, a := range h.Alerts {
		if a.Kind == "storage_guard" {
			found = true
		}
	}
	if !found {
		t.Fatal(h)
	}
}
func TestMaintenanceDrainsBacklogWithoutMinuteThrottle(t *testing.T) {
	s, _, _ := oldJournal(t)
	ctx := context.Background()
	delay, e := s.maintenanceStep(ctx)
	if e != nil || delay != time.Second {
		t.Fatal(delay, e)
	}
	delay, e = s.maintenanceStep(ctx)
	if e != nil || delay != time.Minute {
		t.Fatal(delay, e)
	}
}
func TestLegacyStoragePolicyMigrationAndOldClient(t *testing.T) {
	s := storageFixture(t)
	ctx := context.Background()
	p, _ := retentionPolicy(ctx, s.db)
	if p.MinFreeBytes != 2<<30 || p.DatabaseMaxBytes != 16<<30 || p.ArchiveMaxBytes != 8<<30 {
		t.Fatal(p)
	}
	old := p
	old.DatabaseMaxBytes, old.ArchiveMaxBytes, old.MinFreeBytes = 0, 0, 0
	if e := s.SetRetention(ctx, old, "old-client", time.Now()); e != nil {
		t.Fatal(e)
	}
	v, _ := retentionPolicy(ctx, s.db)
	if v.DatabaseMaxBytes != p.DatabaseMaxBytes || v.MinFreeBytes != p.MinFreeBytes {
		t.Fatal(v)
	}
	var pages, size int64
	s.db.QueryRow("PRAGMA max_page_count").Scan(&pages)
	s.db.QueryRow("PRAGMA page_size").Scan(&size)
	if pages*size > (v.DatabaseMaxBytes - (64 << 20)) {
		t.Fatal("SQLite allocation ceiling missing", pages, size)
	}
}

func TestVersionFourUpgradeAndAdditiveRollback(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "events.db")
	s, e := Open(ctx, path)
	if e != nil {
		t.Fatal(e)
	}
	b := journalBatch("migration-agent", 0, 2, time.Now())
	receipt, e := s.Accept(ctx, "migration-agent", "asset", b)
	if e != nil {
		t.Fatal(e)
	}
	s.Close()
	downgrade := func() {
		db, e := sql.Open("sqlite", path)
		if e != nil {
			t.Fatal(e)
		}
		defer db.Close()
		_, e = db.Exec(`BEGIN;ALTER TABLE event_retention DROP COLUMN database_max_bytes;ALTER TABLE event_retention DROP COLUMN archive_max_bytes;ALTER TABLE event_retention DROP COLUMN min_free_bytes;PRAGMA user_version=4;COMMIT;`)
		if e != nil {
			t.Fatal(e)
		}
	}
	downgrade()
	for cycle := 0; cycle < 2; cycle++ {
		s, e = Open(ctx, path)
		if e != nil {
			t.Fatal(e)
		}
		p, e := retentionPolicy(ctx, s.db)
		if e != nil || p.DatabaseMaxBytes != 16<<30 {
			t.Fatal(p, e)
		}
		actual, e := s.Accept(ctx, "migration-agent", "asset", b)
		if e != nil || actual != receipt {
			t.Fatal("receipt changed by migration", actual, e)
		}
		v, e := s.Status(ctx)
		if e != nil || v.Raw != 2 {
			t.Fatal("events changed by migration", v, e)
		}
		s.Close()
		downgrade()
	}
}
