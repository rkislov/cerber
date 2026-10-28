// SPDX-License-Identifier: Apache-2.0
package eventstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"github.com/rkislov/cerber/internal/telemetry"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const admissionHeadroom int64 = 256 << 20
const maintenanceReserve int64 = 512 << 20
const archivePayloadBytes = 8 << 20

type storageQuerier interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func fileBytes(path string) (int64, error) {
	v, e := os.Stat(path)
	if errors.Is(e, os.ErrNotExist) {
		return 0, nil
	}
	if e != nil {
		return 0, e
	}
	return v.Size(), nil
}
func (s *Store) archiveUsage(ctx context.Context, root string) (int64, int64, error) {
	s.archiveUsageMu.Lock()
	defer s.archiveUsageMu.Unlock()
	if root == "" {
		return 0, 0, nil
	}
	if !s.archiveUsageAt.IsZero() && time.Since(s.archiveUsageAt) < time.Minute {
		return s.archiveUsageBytes, s.archiveUsageFiles, s.archiveUsageError
	}
	var bytes, files int64
	e := filepath.WalkDir(root, func(path string, d fs.DirEntry, e error) error {
		if e != nil {
			return e
		}
		if e = ctx.Err(); e != nil {
			return e
		}
		if path == root {
			return nil
		}
		if strings.Count(strings.TrimPrefix(path, root), string(os.PathSeparator)) > 8 {
			return fmt.Errorf("archive directory nesting exceeds limit")
		}
		if d.IsDir() {
			return nil
		}
		files++
		if files > 1000000 {
			return fmt.Errorf("archive file count exceeds supported bound")
		}
		info, e := d.Info()
		if e != nil {
			return e
		}
		bytes += info.Size()
		return nil
	})
	if ctx.Err() != nil {
		return 0, 0, ctx.Err()
	}
	s.archiveUsageBytes, s.archiveUsageFiles, s.archiveUsageError, s.archiveUsageAt = bytes, files, e, time.Now()
	return bytes, files, e
}
func (s *Store) publishCountedArchive(tmp, final string, size int64) error {
	s.archiveUsageMu.Lock()
	defer s.archiveUsageMu.Unlock()
	if e := publishArchive(tmp, final); e != nil {
		return e
	}
	if !s.archiveUsageAt.IsZero() {
		s.archiveUsageBytes += size
		s.archiveUsageFiles++
	}
	return nil
}
func (s *Store) removeCountedArchive(path string) error {
	s.archiveUsageMu.Lock()
	defer s.archiveUsageMu.Unlock()
	info, e := os.Lstat(path)
	if e != nil {
		return e
	}
	if e = os.Remove(path); e != nil {
		return e
	}
	if !s.archiveUsageAt.IsZero() {
		s.archiveUsageBytes -= info.Size()
		s.archiveUsageFiles--
		if s.archiveUsageBytes < 0 || s.archiveUsageFiles < 0 {
			s.archiveUsageAt = time.Time{}
		}
	}
	return nil
}
func (s *Store) storageStatus(ctx context.Context, q storageQuerier, p telemetry.RetentionPolicy) (telemetry.StorageStatus, error) {
	v := telemetry.StorageStatus{AdmissionAllowed: true}
	if s.path == ":memory:" {
		return v, nil
	}
	var e error
	v.DatabaseBytes, e = fileBytes(s.path)
	if e == nil {
		v.WALBytes, e = fileBytes(s.path + "-wal")
	}
	if e == nil {
		v.SHMBytes, e = fileBytes(s.path + "-shm")
	}
	if e != nil {
		return v, e
	}
	if v.DatabaseBytes == 0 {
		return v, fmt.Errorf("event database path unavailable")
	}
	v.HotBytes = v.DatabaseBytes + v.WALBytes + v.SHMBytes
	var pages, size int64
	if e = q.QueryRowContext(ctx, "PRAGMA freelist_count").Scan(&pages); e == nil {
		e = q.QueryRowContext(ctx, "PRAGMA page_size").Scan(&size)
	}
	if e != nil {
		return v, e
	}
	v.ReusableBytes = pages * size
	var dbID, archiveID string
	v.DiskAvailable, _, dbID, e = s.spaceProbe(filepath.Dir(s.path))
	if e != nil {
		return v, e
	}
	root := s.archiveRoot()
	if root != "" {
		v.ArchiveBytes, v.ArchiveFiles, e = s.archiveUsage(ctx, root)
		if e == nil {
			v.ArchiveAvailable, _, archiveID, e = s.spaceProbe(root)
		}
		if e != nil {
			return v, e
		}
		v.SharedVolume = dbID != "" && dbID == archiveID
	}
	s.checkpointMu.Lock()
	if !s.checkpointAt.IsZero() {
		at := s.checkpointAt
		v.CheckpointAt = &at
	}
	v.CheckpointBusy = s.checkpointBusy
	s.checkpointMu.Unlock()
	v.Reason = storageReason(v, p, 16*telemetry.MaxBatchBytes+(4<<20), false, root != "")
	v.AdmissionAllowed = v.Reason == ""
	return v, nil
}
func storageReason(v telemetry.StorageStatus, p telemetry.RetentionPolicy, work int64, maintenance, archiveConfigured bool) string {
	reserve := p.MinFreeBytes
	if maintenance {
		reserve = maintenanceReserve
	} else {
		reserve += admissionHeadroom
	}
	if v.DiskAvailable < uint64(reserve+work) {
		return "Недостаточно свободного места на разделе БД: приём приостановлен для сохранения резерва"
	}
	if !maintenance && v.HotBytes+work > p.DatabaseMaxBytes {
		return "Достигнут физический лимит SQLite + WAL + SHM"
	}
	if !maintenance && archiveConfigured {
		if v.ArchiveAvailable < uint64(reserve+work) {
			return "Недостаточно свободного места на разделе архивов"
		}
		if v.ArchiveBytes+work > p.ArchiveMaxBytes {
			return "Достигнут лимит архивного каталога; бессрочные архивы сохранены"
		}
	}
	return ""
}

// checkWrite runs after duplicate receipt lookup, before any new rows are inserted.
// A retry of an already committed batch remains acknowledgeable under pressure.
func (s *Store) checkWrite(ctx context.Context, q storageQuerier, p telemetry.RetentionPolicy, work int64, maintenance bool) error {
	if s.path == ":memory:" {
		return nil
	}
	v, e := s.storageStatus(ctx, q, p)
	if e != nil {
		return fmt.Errorf("%w: capacity measurement unavailable: %v", telemetry.ErrStorageProtected, e)
	}
	if reason := storageReason(v, p, work, maintenance, s.archiveRoot() != ""); reason != "" {
		return fmt.Errorf("%w: %s", telemetry.ErrStorageProtected, reason)
	}
	return nil
}
func (s *Store) checkArchiveWrite(ctx context.Context, q storageQuerier, p telemetry.RetentionPolicy, estimate int64) (int64, error) {
	v, e := s.storageStatus(ctx, q, p)
	if e != nil {
		return 0, e
	}
	if s.path == ":memory:" {
		root := s.archiveRoot()
		v.ArchiveBytes, v.ArchiveFiles, e = s.archiveUsage(ctx, root)
		if e != nil {
			return 0, e
		}
		v.ArchiveAvailable, _, _, e = s.spaceProbe(root)
		if e != nil {
			return 0, e
		}
	}
	if v.ArchiveAvailable < uint64(maintenanceReserve+estimate) {
		return 0, fmt.Errorf("%w: insufficient archive work reserve", telemetry.ErrStorageProtected)
	}
	remaining := p.ArchiveMaxBytes - v.ArchiveBytes
	if remaining < estimate {
		return 0, fmt.Errorf("%w: archive budget reached", telemetry.ErrStorageProtected)
	}
	if remaining > maxArchiveBytes {
		remaining = maxArchiveBytes
	}
	return remaining, nil
}
func (s *Store) applyPageLimit(ctx context.Context, p telemetry.RetentionPolicy) error {
	if s.path == ":memory:" {
		return nil
	}
	var size int64
	if e := s.db.QueryRowContext(ctx, "PRAGMA page_size").Scan(&size); e != nil {
		return e
	}
	if size <= 0 {
		return fmt.Errorf("invalid SQLite page size")
	}
	var actual int64
	return s.db.QueryRowContext(ctx, fmt.Sprintf("PRAGMA max_page_count=%d", (p.DatabaseMaxBytes-(64<<20))/size)).Scan(&actual)
}

// CheckpointStorage bounds retained WAL without deleting WAL files manually.
// Busy readers keep their snapshots; the next maintenance cycle retries.
func (s *Store) CheckpointStorage(ctx context.Context) error {
	if s.path == ":memory:" {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	conn, e := s.db.Conn(ctx)
	if e != nil {
		return e
	}
	defer conn.Close()
	if _, e = conn.ExecContext(ctx, "PRAGMA busy_timeout=0"); e != nil {
		return e
	}
	defer conn.ExecContext(context.Background(), "PRAGMA busy_timeout=5000")
	var pages, pageSize int64
	if e = conn.QueryRowContext(ctx, "PRAGMA page_count").Scan(&pages); e != nil {
		return e
	}
	if e = conn.QueryRowContext(ctx, "PRAGMA page_size").Scan(&pageSize); e != nil {
		return e
	}
	mainBytes, e := fileBytes(s.path)
	if e != nil {
		return e
	}
	growth := pages*pageSize - mainBytes
	if growth < 0 {
		growth = 0
	}
	available, _, _, e := s.spaceProbe(filepath.Dir(s.path))
	if e != nil {
		return e
	}
	if available < uint64(growth+(64<<20)) {
		return fmt.Errorf("%w: checkpoint work reserve unavailable", telemetry.ErrStorageProtected)
	}
	var busy, log, checkpointed int
	e = conn.QueryRowContext(ctx, "PRAGMA wal_checkpoint(TRUNCATE)").Scan(&busy, &log, &checkpointed)
	s.checkpointMu.Lock()
	s.checkpointBusy = busy != 0 || log > checkpointed
	if e == nil {
		s.checkpointAt = time.Now().UTC()
	}
	s.checkpointMu.Unlock()
	return e
}
func (s *Store) maintenanceStep(ctx context.Context) (time.Duration, error) {
	n, e := s.Maintain(ctx, time.Now().UTC())
	if checkpointErr := s.CheckpointStorage(ctx); e == nil && checkpointErr != nil {
		e = checkpointErr
	}
	if e != nil {
		return time.Minute, e
	}
	if n > 0 {
		return time.Second, nil
	}
	return time.Minute, nil
}

type archiveBudgetWriter struct {
	file      *os.File
	remaining int64
}

func (w *archiveBudgetWriter) Write(p []byte) (int, error) {
	if int64(len(p)) > w.remaining {
		return 0, fmt.Errorf("%w: archive file budget exceeded", telemetry.ErrStorageProtected)
	}
	n, e := w.file.Write(p)
	w.remaining -= int64(n)
	return n, e
}
