// SPDX-License-Identifier: Apache-2.0
package eventstore

import (
	"context"
	"database/sql"
	"fmt"
	"github.com/rkislov/cerber/internal/health"
	"github.com/rkislov/cerber/internal/integrations"
	"github.com/rkislov/cerber/internal/telemetry"
	"path/filepath"
	"time"
)

func (s *Store) PipelineHealth(ctx context.Context) (telemetry.PipelineHealth, error) {
	s.healthMu.Lock()
	defer s.healthMu.Unlock()
	if s.lastHealth.At.IsZero() {
		return telemetry.PipelineHealth{}, fmt.Errorf("pipeline monitor warming up")
	}
	v := s.lastHealth
	v.Alerts = append([]telemetry.PipelineAlert{}, v.Alerts...)
	return v, nil
}
func (s *Store) SamplePipelineHealth(ctx context.Context, now time.Time) error {
	s.healthMu.Lock()
	defer s.healthMu.Unlock()
	var v telemetry.PipelineHealth
	v.At = now
	v.Alerts = []telemetry.PipelineAlert{}
	if s.path != ":memory:" {
		r := health.New(filepath.Dir(s.path))(ctx)
		v.DiskAvailable = r.Resources.DiskAvailable
		v.DiskTotal = r.Resources.DiskTotal
	}
	var ordinal, processed int64
	var oldest sql.NullString
	e := s.db.QueryRowContext(ctx, `SELECT coalesce((SELECT max(sequence) FROM raw_events),0),(SELECT position FROM consumer_cursors WHERE name='normalizer/1'),(SELECT count(*) FROM raw_events WHERE sequence>(SELECT position FROM consumer_cursors WHERE name='normalizer/1')),(SELECT count(*) FROM normalized_events WHERE sequence>(SELECT position FROM consumer_cursors WHERE name='correlator/1')),(SELECT min(received_at) FROM raw_events WHERE sequence>min((SELECT position FROM consumer_cursors WHERE name='normalizer/1'),(SELECT position FROM consumer_cursors WHERE name='correlator/1')))`).Scan(&ordinal, &processed, &v.PendingNormalization, &v.PendingCorrelation, &oldest)
	if e != nil {
		return e
	}
	v.Retention, e = s.RetentionStatus(ctx)
	if e != nil {
		return e
	}
	v.JournalBytes = v.Retention.QuotaBytes
	v.JournalMaxBytes = v.Retention.Policy.MaxBytes
	if v.JournalMaxBytes > 0 {
		v.JournalPercent = 100 * float64(v.JournalBytes) / float64(v.JournalMaxBytes)
	}
	if oldest.Valid {
		if at, e := parseTime(oldest.String); e == nil && now.After(at) {
			v.OldestPendingSeconds = now.Sub(at).Seconds()
		}
	}
	if !s.lastHealth.At.IsZero() {
		v.SampleSeconds = now.Sub(s.lastHealth.At).Seconds()
		if v.SampleSeconds > 0 {
			if ordinal >= s.lastHealthOrdinal {
				v.ReceivedPerSecond = float64(ordinal-s.lastHealthOrdinal) / v.SampleSeconds
			}
			if processed >= s.lastHealthProcessed {
				v.ProcessedPerSecond = float64(processed-s.lastHealthProcessed) / v.SampleSeconds
			}
		}
	}
	conditions := map[string]struct{ severity, detail string }{}
	if v.DiskTotal > 0 && float64(v.DiskAvailable)/float64(v.DiskTotal) < 0.1 {
		level := "warning"
		if float64(v.DiskAvailable)/float64(v.DiskTotal) < 0.05 || v.DiskAvailable < 1<<30 {
			level = "critical"
		}
		conditions["storage_capacity"] = struct{ severity, detail string }{level, fmt.Sprintf("На разделе хранилища осталось %.1f%% свободного места (%d байт). Проверьте архивы и резервные копии.", 100*float64(v.DiskAvailable)/float64(v.DiskTotal), v.DiskAvailable)}
	}
	storage := v.Retention.Storage
	if !storage.AdmissionAllowed {
		conditions["storage_guard"] = struct{ severity, detail string }{"critical", "Защитная приостановка приёма: " + storage.Reason}
	}
	level, detail := "", ""
	for _, part := range []struct {
		name        string
		used, limit int64
	}{{"SQLite + WAL + SHM", storage.HotBytes, v.Retention.Policy.DatabaseMaxBytes}, {"Архивный каталог", storage.ArchiveBytes, v.Retention.Policy.ArchiveMaxBytes}} {
		if part.limit > 0 && float64(part.used)/float64(part.limit) >= 0.8 {
			next := "warning"
			if float64(part.used)/float64(part.limit) >= 0.95 {
				next = "critical"
			}
			if level != "critical" {
				level = next
			}
			detail += fmt.Sprintf("%s: %d из %d байт. ", part.name, part.used, part.limit)
		}
	}
	if level != "" {
		conditions["physical_capacity"] = struct{ severity, detail string }{level, detail}
	}
	if v.JournalPercent >= 80 {
		level := "warning"
		if v.JournalPercent >= 95 {
			level = "critical"
		}
		conditions["journal_capacity"] = struct{ severity, detail string }{level, fmt.Sprintf("Заполнение оперативного журнала %.1f%% (%d из %d байт). Проверьте архивирование и свободное место.", v.JournalPercent, v.JournalBytes, v.JournalMaxBytes)}
	}
	if v.OldestPendingSeconds >= 300 && (v.PendingNormalization > 0 || v.PendingCorrelation > 0) {
		conditions["pipeline_lag"] = struct{ severity, detail string }{"warning", fmt.Sprintf("События ожидают обработки %.0f секунд; нормализация: %d, корреляции: %d", v.OldestPendingSeconds, v.PendingNormalization, v.PendingCorrelation)}
	}
	if v.Retention.LastError != "" {
		conditions["archive_error"] = struct{ severity, detail string }{"critical", "Ошибка обслуживания архива: " + v.Retention.LastError}
	}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	for _, kind := range []string{"journal_capacity", "pipeline_lag", "archive_error", "storage_capacity", "storage_guard", "physical_capacity"} {
		var id, severity, raised string
		e = tx.QueryRowContext(ctx, "SELECT id,severity,raised_at FROM pipeline_health_alerts WHERE kind=? AND resolved_at IS NULL", kind).Scan(&id, &severity, &raised)
		if e != nil && e != sql.ErrNoRows {
			return e
		}
		c, active := conditions[kind]
		if active {
			if id == "" {
				id = telemetry.ID(kind, now.String())
				raised = stamp(now)
				_, e = tx.ExecContext(ctx, "INSERT INTO pipeline_health_alerts(id,kind,severity,detail,raised_at) VALUES(?,?,?,?,?)", id, kind, c.severity, c.detail, raised)
			} else {
				_, e = tx.ExecContext(ctx, "UPDATE pipeline_health_alerts SET severity=?,detail=? WHERE id=?", c.severity, c.detail, id)
			}
			if e != nil {
				return e
			}
			if severity != c.severity {
				if _, e = tx.ExecContext(ctx, "INSERT INTO pipeline_health_notifications(id,subject,body) VALUES(?,?,?)", id+":"+c.severity, "Предупреждение SIEM: "+pipelineAlertTitle(kind), c.detail+"\nID: "+id); e != nil {
					return e
				}
			}
			at, _ := parseTime(raised)
			v.Alerts = append(v.Alerts, telemetry.PipelineAlert{ID: id, Kind: kind, Severity: c.severity, Detail: c.detail, RaisedAt: at})
		} else if id != "" {
			if _, e = tx.ExecContext(ctx, "UPDATE pipeline_health_alerts SET resolved_at=? WHERE id=?", stamp(now), id); e != nil {
				return e
			}
			if _, e = tx.ExecContext(ctx, "INSERT INTO pipeline_health_notifications(id,subject,body) VALUES(?,?,?)", id+":resolved", "Восстановление SIEM: "+pipelineAlertTitle(kind), "Условие предупреждения устранено. ID: "+id); e != nil {
				return e
			}
		}
	}
	if e = tx.Commit(); e != nil {
		return e
	}
	s.lastHealth = v
	s.lastHealthOrdinal = ordinal
	s.lastHealthProcessed = processed
	return nil
}
func (s *Store) HealthNotificationBatch(ctx context.Context, after int64) ([]integrations.Notification, error) {
	rows, e := s.db.QueryContext(ctx, "SELECT sequence,id,subject,body FROM pipeline_health_notifications WHERE sequence>? ORDER BY sequence LIMIT 100", after)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []integrations.Notification{}
	for rows.Next() {
		var n integrations.Notification
		if e = rows.Scan(&n.Sequence, &n.ID, &n.Subject, &n.Body); e != nil {
			return nil, e
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

func pipelineAlertTitle(kind string) string {
	return map[string]string{"journal_capacity": "заполнение журнала событий", "pipeline_lag": "задержка обработки событий", "archive_error": "ошибка архивирования", "storage_capacity": "недостаточно свободного места", "storage_guard": "защитная приостановка приёма", "physical_capacity": "физическое заполнение хранилища"}[kind]
}
