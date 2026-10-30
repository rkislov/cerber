// SPDX-License-Identifier: Apache-2.0
package sqlite

import (
	"context"
	"database/sql"
	"github.com/rkislov/cerber/internal/ingest"
	"github.com/rkislov/cerber/internal/sensorstate"
	"time"
)

const sensorHistoryRows = 200000

func pruneSensorHistory(ctx context.Context, tx *sql.Tx, now time.Time) error {
	for step, days := range map[int]int{60: 1, 300: 7, 3600: 30} {
		if _, e := tx.ExecContext(ctx, "DELETE FROM sensor_samples WHERE step=? AND bucket<?", step, now.Add(-time.Duration(days)*24*time.Hour).Unix()); e != nil {
			return e
		}
	}
	_, e := tx.ExecContext(ctx, `DELETE FROM sensor_samples WHERE id IN (SELECT id FROM sensor_samples ORDER BY bucket,id LIMIT MAX(0,(SELECT COUNT(*) FROM sensor_samples)-?))`, sensorHistoryRows)
	return e
}
func counterDelta(a, b sensorstate.Counters) (sensorstate.Sample, bool) {
	av := []uint64{a.Messages, a.Bytes, a.Stored, a.Rejected, a.UnknownSets}
	bv := []uint64{b.Messages, b.Bytes, b.Stored, b.Rejected, b.UnknownSets}
	v := make([]int64, 5)
	for k := range av {
		if av[k] < bv[k] || av[k]-bv[k] > 1<<40 {
			return sensorstate.Sample{}, false
		}
		v[k] = int64(av[k] - bv[k])
	}
	return sensorstate.Sample{Messages: v[0], Bytes: v[1], Stored: v[2], Rejected: v[3], UnknownSets: v[4]}, true
}
func recordSensorHistory(ctx context.Context, tx *sql.Tx, id string, h, old ingest.Heartbeat, now time.Time) error {
	if h.Sensor == nil {
		return nil
	}
	current := h.Sensor
	prior := old.Sensor
	seconds := float64(0)
	if prior != nil && current.StartedAt.Equal(prior.StartedAt) {
		seconds = current.ObservedAt.Sub(prior.ObservedAt).Seconds()
		if seconds <= 0 || seconds > 300 {
			seconds = 0
		}
	}
	// Stale or clock-skewed reports are visible in health but cannot create a rate spike.
	if now.Sub(current.ObservedAt) > 5*time.Minute || current.ObservedAt.After(now.Add(5*time.Minute)) {
		seconds = 0
	}
	samples := map[string]sensorstate.Sample{}
	total := sensorstate.Sample{Reports: 1}
	valid := 0
	for _, i := range current.Inputs {
		sample := sensorstate.Sample{Reports: 1}
		if prior != nil && seconds > 0 {
			for _, p := range prior.Inputs {
				if p.ID == i.ID && p.Format == i.Format && p.Listen == i.Listen {
					if d, ok := counterDelta(i.Counters, p.Counters); ok {
						sample = d
						sample.Reports = 1
						sample.Seconds = seconds
						valid++
					}
					break
				}
			}
		}
		samples[i.ID] = sample
		total.Messages += sample.Messages
		total.Bytes += sample.Bytes
		total.Stored += sample.Stored
		total.Rejected += sample.Rejected
		total.UnknownSets += sample.UnknownSets
	}
	if valid > 0 {
		total.Seconds = seconds
	}
	if h.Events != nil && h.Events.QueueKnown && now.Sub(h.Events.ObservedAt) <= 5*time.Minute && !h.Events.ObservedAt.After(now.Add(5*time.Minute)) {
		total.QueueReports = 1
		total.QueueBatches = h.Events.QueueBatches
		total.QueueBytes = h.Events.QueueBytes
	}
	samples[""] = total
	for input, v := range samples {
		for _, step := range []int64{60, 300, 3600} {
			_, e := tx.ExecContext(ctx, `INSERT INTO sensor_samples(agent_id,input_id,step,bucket,messages,bytes,stored,rejected,unknown_sets,seconds,reports,queue_reports,queue_batches,queue_bytes) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(agent_id,input_id,step,bucket) DO UPDATE SET messages=MIN(messages+excluded.messages,1000000000000000),bytes=MIN(bytes+excluded.bytes,1000000000000000),stored=MIN(stored+excluded.stored,1000000000000000),rejected=MIN(rejected+excluded.rejected,1000000000000000),unknown_sets=MIN(unknown_sets+excluded.unknown_sets,1000000000000000),seconds=seconds+excluded.seconds,reports=reports+excluded.reports,queue_reports=queue_reports+excluded.queue_reports,queue_batches=MAX(queue_batches,excluded.queue_batches),queue_bytes=MAX(queue_bytes,excluded.queue_bytes)`, id, input, step, now.Unix()/step*step, v.Messages, v.Bytes, v.Stored, v.Rejected, v.UnknownSets, v.Seconds, v.Reports, v.QueueReports, v.QueueBatches, v.QueueBytes)
			if e != nil {
				return e
			}
		}
	}
	return pruneSensorHistory(ctx, tx, now)
}
func (s *Store) SensorHistory(ctx context.Context, id, input, period string, now time.Time) (sensorstate.History, error) {
	result := sensorstate.History{Points: []sensorstate.Sample{}, AsOf: now, RowLimit: sensorHistoryRows}
	if !ingest.Identifier(id) || (input != "" && !ingest.Identifier(input)) {
		return result, sensorstate.ErrInvalid
	}
	hours := 24
	step := 60
	switch period {
	case "24h", "":
	case "7d":
		hours = 168
		step = 300
	case "30d":
		hours = 720
		step = 3600
	default:
		return result, sensorstate.ErrInvalid
	}
	result.StepSeconds = step
	var exists int
	if e := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM agent_heartbeats WHERE agent_id=? AND json_type(payload,'$.sensor')='object'`, id).Scan(&exists); e != nil {
		return result, e
	}
	if exists == 0 {
		return result, sensorstate.ErrNotFound
	}
	rows, e := s.db.QueryContext(ctx, `SELECT bucket,messages,bytes,stored,rejected,unknown_sets,seconds,reports,queue_reports,queue_batches,queue_bytes FROM sensor_samples WHERE agent_id=? AND input_id=? AND step=? AND bucket>=? ORDER BY bucket LIMIT 2048`, id, input, step, now.Add(-time.Duration(hours)*time.Hour).Unix()/int64(step)*int64(step))
	if e != nil {
		return result, e
	}
	defer rows.Close()
	for rows.Next() {
		var v sensorstate.Sample
		var at int64
		if e = rows.Scan(&at, &v.Messages, &v.Bytes, &v.Stored, &v.Rejected, &v.UnknownSets, &v.Seconds, &v.Reports, &v.QueueReports, &v.QueueBatches, &v.QueueBytes); e != nil {
			return result, e
		}
		v.At = time.Unix(at, 0).UTC()
		result.Points = append(result.Points, v)
	}
	if e = rows.Err(); e != nil {
		return result, e
	}
	rows.Close()
	streams, e := s.db.QueryContext(ctx, "SELECT DISTINCT input_id FROM sensor_samples WHERE agent_id=? AND input_id!='' ORDER BY input_id LIMIT 256", id)
	if e != nil {
		return result, e
	}
	defer streams.Close()
	result.Inputs = []string{}
	for streams.Next() {
		var input string
		if e = streams.Scan(&input); e != nil {
			return result, e
		}
		result.Inputs = append(result.Inputs, input)
	}
	return result, streams.Err()
}
