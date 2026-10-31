// SPDX-License-Identifier: Apache-2.0
package sqlite

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/rkislov/cerber/internal/ingest"
	rules "github.com/rkislov/cerber/internal/suricatarules"
)

func readSuricataRollout(ctx context.Context, q rowQuerier, id string) (*rules.Rollout, error) {
	var data string
	e := q.QueryRowContext(ctx, "SELECT payload FROM suricata_rollouts WHERE group_id=?", id).Scan(&data)
	if errors.Is(e, sql.ErrNoRows) {
		return nil, nil
	}
	if e != nil {
		return nil, e
	}
	var r rules.Rollout
	e = json.Unmarshal([]byte(data), &r)
	return &r, e
}
func saveSuricataRollout(ctx context.Context, tx *sql.Tx, r *rules.Rollout) error {
	data, e := json.Marshal(r)
	if e != nil {
		return e
	}
	_, e = tx.ExecContext(ctx, "INSERT INTO suricata_rollouts VALUES(?,?) ON CONFLICT(group_id) DO UPDATE SET payload=excluded.payload", r.GroupID, string(data))
	return e
}
func rolloutHistory(ctx context.Context, tx *sql.Tx, r *rules.Rollout, actor string) error {
	return automationHistory(ctx, tx, r.GroupID, "suricata.rollout_"+r.State, actor, map[string]any{"id": r.ID, "state": r.State, "candidate_id": r.CandidateID, "error": r.Error, "members": len(r.Members), "updated_by": actor})
}
func rolloutAgentHeld(ctx context.Context, tx *sql.Tx, id string) (bool, error) {
	var n int
	e := tx.QueryRowContext(ctx, `SELECT count(*) FROM suricata_rollouts r,json_each(r.payload,'$.members') m WHERE json_extract(r.payload,'$.state') IN ('canary','fleet','rolling_back','rollback_failed') AND json_extract(m.value,'$.agent_id')=?`, id).Scan(&n)
	return n > 0, e
}
func validateRolloutConfig(ctx context.Context, tx *sql.Tx, p rules.GroupPolicy) error {
	c := p.Rollout
	if c == nil {
		return nil
	}
	if !ingest.Identifier(c.CanaryGroupID) || c.CanaryGroupID == p.GroupID || c.ObservationSeconds < 60 || c.ObservationSeconds > 3600 || c.TimeoutSeconds < c.ObservationSeconds+180 || c.TimeoutSeconds > 7200 || c.MaxDropPercent < 0 || c.MaxDropPercent > 100 || c.MaxQueueMiB < 1 || c.MaxQueueMiB > 256 {
		return rules.ErrInvalid
	}
	g, e := groupInfo(ctx, tx, c.CanaryGroupID)
	if e != nil || g.Archived {
		return rules.ErrInvalid
	}
	var count, outside int
	e = tx.QueryRowContext(ctx, `SELECT count(*),coalesce(sum(NOT EXISTS(SELECT 1 FROM agent_group_members t WHERE t.group_id=? AND t.agent_id=c.agent_id)),0) FROM agent_group_members c WHERE c.group_id=?`, p.GroupID, c.CanaryGroupID).Scan(&count, &outside)
	if e != nil {
		return e
	}
	if count == 0 || outside > 0 {
		return rules.ErrInvalid
	}
	return nil
}

type rolloutHeartbeat struct {
	h        ingest.Heartbeat
	received time.Time
	revoked  bool
}

func readRolloutHeartbeat(ctx context.Context, tx *sql.Tx, id string) (rolloutHeartbeat, error) {
	var v rolloutHeartbeat
	var data, at string
	e := tx.QueryRowContext(ctx, `SELECT a.revoked,coalesce(h.received_at,''),coalesce(h.payload,'') FROM agents a LEFT JOIN agent_heartbeats h ON h.agent_id=a.id WHERE a.id=?`, id).Scan(&v.revoked, &at, &data)
	if e != nil {
		return v, e
	}
	v.received, _ = parse(at)
	if data != "" {
		e = json.Unmarshal([]byte(data), &v.h)
	}
	return v, e
}

// Freshness uses server receipt time. Relative agent timestamps additionally
// reject frozen/cached capture observations without requiring synchronized clocks.
func rolloutHealth(v rolloutHeartbeat, c rules.RolloutConfig, now time.Time) string {
	h := v.h
	if v.revoked {
		return "Агент отозван"
	}
	if v.received.IsZero() || now.Sub(v.received) > 180*time.Second {
		return "Нет свежего heartbeat более 180 секунд"
	}
	if h.Sensor == nil || h.Sensor.Rules == nil || h.Sensor.Capture == nil {
		return "Нет диагностики Suricata и захвата"
	}
	s := h.Sensor
	cap := s.Capture
	if cap.ObservedAt.Before(h.ObservedAt.Add(-30*time.Second)) || cap.ObservedAt.After(h.ObservedAt.Add(30*time.Second)) {
		return "Устаревшая диагностика захвата"
	}
	if cap.State == "unavailable" || cap.Error != "" {
		return "Движок или интерфейс захвата недоступен"
	}
	if cap.EVEState != "ready" {
		return "EVE: " + cap.EVEState
	}
	if s.ConfigError != "" {
		return "Ошибка конфигурации сенсора: " + s.ConfigError
	}
	if h.Events == nil || !h.Events.Enabled || !h.Events.QueueKnown {
		return "Нет диагностики очереди событий"
	}
	if h.Events.QueueBytes > int64(c.MaxQueueMiB)<<20 {
		return "Превышен лимит очереди событий"
	}
	if h.Events.Delivery == "error" {
		return "Ошибка доставки событий"
	}
	sourceReady := false
	for _, src := range h.Events.Sources {
		if src.Source != "network:suricata" {
			continue
		}
		sourceReady = src.State == "ok"
		if !sourceReady {
			return "Источник событий не готов: " + src.Source
		}
	}
	if !sourceReady {
		return "Нет диагностики чтения EVE"
	}
	found := false
	for _, i := range s.Inputs {
		if i.Enabled && i.Format == "suricata" {
			found = true
			if i.State != "receiving" && i.State != "listening" {
				return "Вход EVE не готов"
			}
		}
	}
	if !found {
		return "Не подключён вход событий Suricata"
	}
	return ""
}

func prepareSuricataRollout(ctx context.Context, tx *sql.Tx, p *rules.GroupPolicy, candidate string, now time.Time) error {
	if candidate == p.ActiveID {
		p.State = "ready"
		p.Error = ""
		return nil
	}
	// Structural configuration errors reject the change. A missing baseline or
	// unhealthy sensor is persisted as blocked, without distributing any package.
	if e := validateRolloutConfig(ctx, tx, *p); e != nil {
		return e
	}
	rows, e := tx.QueryContext(ctx, `SELECT a.id,s.name,EXISTS(SELECT 1 FROM agent_group_members c WHERE c.group_id=? AND c.agent_id=a.id) FROM agent_group_members m JOIN agents a ON a.id=m.agent_id JOIN assets s ON s.id=a.asset_id WHERE m.group_id=? ORDER BY a.id LIMIT 501`, p.Rollout.CanaryGroupID, p.GroupID)
	if e != nil {
		return e
	}
	type member struct {
		id, name string
		canary   bool
	}
	var members []member
	for rows.Next() {
		var m member
		if e = rows.Scan(&m.id, &m.name, &m.canary); e != nil {
			rows.Close()
			return e
		}
		members = append(members, m)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return e
	}
	if len(members) > 500 {
		return rules.ErrLimit
	}
	token := make([]byte, 16)
	if _, e = rand.Read(token); e != nil {
		return e
	}
	r := &rules.Rollout{ID: hex.EncodeToString(token), GroupID: p.GroupID, PolicyRevision: p.Revision, CandidateID: candidate, PreviousID: p.ActiveID, State: "canary", Config: *p.Rollout, StartedAt: now, StageStartedAt: now, UpdatedAt: now, Members: []rules.RolloutMember{}}
	blocked := ""
	canaries := 0
	for _, m := range members {
		v, e := readRolloutHeartbeat(ctx, tx, m.id)
		if e != nil {
			return e
		}
		if v.h.Sensor == nil || v.h.Sensor.Rules == nil || v.h.Sensor.Rules.EngineMajor != p.EngineMajor {
			if m.canary {
				blocked = "В пробной группе есть агент без совместимого Suricata: " + m.name
			}
			continue
		}
		a, e := suricataAssignment(ctx, tx, m.id)
		if e != nil {
			return e
		}
		owners, e := matchingSuricataGroups(ctx, tx, m.id, p.EngineMajor)
		if e != nil {
			return e
		}
		for _, owner := range owners {
			if owner.GroupID != p.GroupID {
				blocked = "Пересечение групп: " + m.name
			}
		}
		held, e := rolloutAgentHeld(ctx, tx, m.id)
		if e != nil {
			return e
		}
		if held {
			blocked = "Сенсор участвует в другом незавершённом обновлении: " + m.name
		}
		reason := rolloutHealth(v, *p.Rollout, now)
		st := v.h.Sensor.Rules
		if st.State != "applied" || st.AppliedID == "" || st.AppliedID != a.Bundle.ID || st.Revision != a.Revision {
			reason = "Нет подтверждённого рабочего пакета для отката"
		}
		if st.AppliedID != "" {
			if _, e = suricataBundle(ctx, tx, st.AppliedID); errors.Is(e, rules.ErrNotFound) {
				reason = "Рабочий пакет отсутствует в каталоге"
			} else if e != nil {
				return e
			}
		}
		if reason != "" {
			blocked = m.name + ": " + reason
		}
		phase := "fleet"
		if m.canary {
			phase = "canary"
			canaries++
		}
		rm := rules.RolloutMember{AgentID: m.id, Name: m.name, Phase: phase, PreviousID: st.AppliedID, OriginalRevision: a.Revision, State: "waiting", LastHeartbeat: v.received, SensorStarted: v.h.Sensor.StartedAt}
		if cap := v.h.Sensor.Capture; cap != nil {
			rm.Packets = cap.Packets
			rm.Dropped = cap.Dropped
			rm.Uptime = cap.Uptime
			rm.Interface = cap.Interface
			rm.CaptureMode = cap.Mode
		}
		r.Members = append(r.Members, rm)
	}
	if canaries == 0 {
		blocked = "В пробной группе нет готовых сенсоров"
	}
	if blocked != "" {
		r.State = "blocked"
		r.Error = blocked
	}
	p.State = r.State
	p.Error = r.Error
	if e = saveSuricataRollout(ctx, tx, r); e != nil {
		return e
	}
	return rolloutHistory(ctx, tx, r, p.UpdatedBy)
}

func beginSuricataRollback(ctx context.Context, tx *sql.Tx, p *rules.GroupPolicy, r *rules.Rollout, reason, actor string, now time.Time) error {
	r.State = "rolling_back"
	r.Error = reason
	r.StageStartedAt = now
	r.UpdatedAt = now
	p.State = r.State
	p.Error = reason
	// Halt automatic following until an administrator explicitly saves the recipe.
	if p.ActiveID != "" {
		p.Mode = "pinned"
		p.BundleID = p.ActiveID
		p.CustomID = ""
	}
	for i := range r.Members {
		m := &r.Members[i]
		if m.State == "rolled_back" || m.State == "unchanged" {
			continue
		}
		m.HealthySince = time.Time{}
		m.Samples = 0
		if m.AssignmentRevision == 0 || m.PreviousID == r.CandidateID {
			m.State = "unchanged"
			m.Error = ""
		} else {
			// A manual retry is fenced against the last rollback assignment,
			// not the original (already superseded) candidate revision.
			if m.RollbackRevision > 0 {
				m.AssignmentRevision = m.RollbackRevision
			}
			m.State = "rollback_pending"
			m.RollbackRevision = 0
		}
	}
	if e := rolloutHistory(ctx, tx, r, actor); e != nil {
		return e
	}
	return advanceSuricataRollback(ctx, tx, p, r, now)
}

func (s *Store) AdvanceSuricataRollouts(ctx context.Context, now time.Time) error {
	// Each group is an independent bounded transaction; the same DB transaction
	// fences concurrent controllers and assignment revisions.
	rows, e := s.db.QueryContext(ctx, `SELECT group_id FROM suricata_rollouts WHERE json_extract(payload,'$.state') IN ('canary','fleet','rolling_back') ORDER BY group_id LIMIT 32`)
	if e != nil {
		return e
	}
	var ids []string
	for rows.Next() {
		var id string
		if e = rows.Scan(&id); e != nil {
			rows.Close()
			return e
		}
		ids = append(ids, id)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return e
	}
	for _, id := range ids {
		if e = s.advanceSuricataRollout(ctx, id, now); e != nil {
			return e
		}
	}
	return nil
}
func (s *Store) advanceSuricataRollout(ctx context.Context, id string, now time.Time) error {
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	r, e := readSuricataRollout(ctx, tx, id)
	if e != nil {
		return e
	}
	if r == nil || !rules.RolloutHolds(r.State) || r.State == "rollback_failed" {
		return nil
	}
	original, _ := json.Marshal(r)
	p, e := readSuricataGroup(ctx, tx, id)
	if e != nil {
		return e
	}
	if p.Revision != r.PolicyRevision {
		return rules.ErrConflict
	}
	g, e := groupInfo(ctx, tx, id)
	if e != nil {
		return e
	}
	if r.State != "rolling_back" && (!p.Enabled || g.Archived) {
		if e = beginSuricataRollback(ctx, tx, &p, r, "Групповое назначение отключено или группа архивирована", "system:suricata-rollout", now); e != nil {
			return e
		}
	}
	if r.State == "rolling_back" {
		e = advanceSuricataRollback(ctx, tx, &p, r, now)
	} else if r.State == "canary" || r.State == "fleet" {
		e = advanceSuricataCandidate(ctx, tx, &p, r, now)
	}
	if e != nil {
		return e
	}
	data, _ := json.Marshal(r)
	if string(original) == string(data) {
		return nil
	}
	r.UpdatedAt = now
	p.UpdatedAt = now
	if e = saveSuricataRollout(ctx, tx, r); e != nil {
		return e
	}
	if e = saveSuricataGroup(ctx, tx, p); e != nil {
		return e
	}
	return tx.Commit()
}

func advanceSuricataCandidate(ctx context.Context, tx *sql.Tx, p *rules.GroupPolicy, r *rules.Rollout, now time.Time) error {
	fail := func(reason string) error {
		return beginSuricataRollback(ctx, tx, p, r, reason, "system:suricata-rollout", now)
	}
	if now.Sub(r.StageStartedAt) > time.Duration(r.Config.TimeoutSeconds)*time.Second {
		return fail("Истёк срок применения или наблюдения этапа")
	}
	allHealthy := true
	for i := range r.Members {
		m := &r.Members[i]
		if r.State == "canary" && m.Phase != "canary" {
			continue
		}
		v, e := readRolloutHeartbeat(ctx, tx, m.AgentID)
		if e != nil {
			return e
		}
		m.LastHeartbeat = v.received
		if v.revoked || v.received.IsZero() || now.Sub(v.received) > 180*time.Second {
			return fail(m.Name + ": нет связи или агент отозван")
		}
		if v.h.Sensor == nil || v.h.Sensor.Rules == nil {
			return fail(m.Name + ": отсутствует состояние движка")
		}
		a, e := suricataAssignment(ctx, tx, m.AgentID)
		if e != nil {
			return e
		}
		if m.AssignmentRevision == 0 {
			if reason := rolloutHealth(v, r.Config, now); reason != "" {
				return fail(m.Name + ": " + reason)
			}
			if a.Revision != m.OriginalRevision || v.h.Sensor.Rules.State != "applied" || v.h.Sensor.Rules.AppliedID != m.PreviousID || v.h.Sensor.Rules.Revision != a.Revision {
				return fail(m.Name + ": рабочее назначение изменилось")
			}
			if a.Bundle.ID != r.CandidateID {
				a, e = assignSuricata(ctx, tx, rules.Change{AgentID: m.AgentID, ExpectedRevision: a.Revision, BundleID: r.CandidateID}, "system:suricata-rollout", r.GroupID, r.PolicyRevision)
				if e != nil {
					return e
				}
				m.AssignmentRevision = a.Revision
				m.State = "applying"
				allHealthy = false
				continue
			}
			m.AssignmentRevision = a.Revision
		}
		if a.Revision != m.AssignmentRevision || a.Bundle.ID != r.CandidateID {
			return fail(m.Name + ": назначение изменилось во время обновления")
		}
		st := v.h.Sensor.Rules
		if st.Revision == m.AssignmentRevision && (st.State == "error" || st.State == "rollback_failed") {
			return fail(m.Name + ": " + st.State + " " + st.Error)
		}
		if st.Revision != m.AssignmentRevision || st.State != "applied" || st.AppliedID != r.CandidateID {
			allHealthy = false
			continue
		}
		if reason := rolloutHealth(v, r.Config, now); reason != "" {
			return fail(m.Name + ": " + reason)
		}
		cap := v.h.Sensor.Capture
		if !v.h.Sensor.StartedAt.Equal(m.SensorStarted) || cap.Uptime < m.Uptime || cap.Packets < m.Packets || cap.Dropped < m.Dropped || cap.Interface != m.Interface || cap.Mode != m.CaptureMode {
			return fail(m.Name + ": перезапуск движка/сенсора или изменение источника захвата")
		}
		if !v.received.After(m.LastObserved) || !cap.ObservedAt.After(m.LastCapture) {
			if m.State != "healthy" {
				allHealthy = false
			}
			continue
		}
		// A gap cannot count as a healthy observation interval, even after server downtime.
		if !m.LastObserved.IsZero() && v.received.Sub(m.LastObserved) > 180*time.Second {
			m.HealthySince = time.Time{}
			m.Samples = 0
		}
		packets, drops := cap.Packets-m.Packets, cap.Dropped-m.Dropped
		m.DropPercent = 0
		if packets > 0 {
			m.DropPercent = float64(drops) / float64(packets) * 100
		} else if drops > 0 {
			m.DropPercent = 100
		}
		if m.DropPercent > float64(r.Config.MaxDropPercent) {
			return fail(fmt.Sprintf("%s: потери пакетов %.2f%% выше порога %d%%", m.Name, m.DropPercent, r.Config.MaxDropPercent))
		}
		m.Uptime = cap.Uptime
		m.Packets = cap.Packets
		m.Dropped = cap.Dropped
		m.QueueBytes = v.h.Events.QueueBytes
		m.LastObserved = v.received
		m.LastCapture = cap.ObservedAt
		m.Samples++
		if m.HealthySince.IsZero() {
			m.HealthySince = v.received
		}
		m.State = "observing"
		if m.Samples >= 2 && v.received.Sub(m.HealthySince) >= time.Duration(r.Config.ObservationSeconds)*time.Second {
			m.State = "healthy"
		} else {
			allHealthy = false
		}
	}
	if !allHealthy {
		return nil
	}
	if r.State == "canary" {
		fleet := false
		for _, m := range r.Members {
			fleet = fleet || m.Phase == "fleet"
		}
		if fleet {
			r.State = "fleet"
			p.State = "fleet"
			r.StageStartedAt = now
			return rolloutHistory(ctx, tx, r, "system:suricata-rollout")
		}
	}
	r.State = "completed"
	p.State = "ready"
	p.Error = ""
	p.PreviousID = p.ActiveID
	p.ActiveID = r.CandidateID
	return rolloutHistory(ctx, tx, r, "system:suricata-rollout")
}

func advanceSuricataRollback(ctx context.Context, tx *sql.Tx, p *rules.GroupPolicy, r *rules.Rollout, now time.Time) error {
	complete := true
	failed := false
	for i := range r.Members {
		m := &r.Members[i]
		if m.AssignmentRevision == 0 || m.State == "rolled_back" || m.State == "unchanged" {
			continue
		}
		if m.State == "rollback_failed" {
			failed = true
			continue
		}
		v, e := readRolloutHeartbeat(ctx, tx, m.AgentID)
		if e != nil {
			return e
		}
		m.LastHeartbeat = v.received
		if now.Sub(r.StageStartedAt) > time.Duration(r.Config.TimeoutSeconds)*time.Second || v.revoked {
			m.State = "rollback_failed"
			m.Error = "Откат не подтверждён: истёк срок или агент отозван"
			failed = true
			continue
		}
		a, e := suricataAssignment(ctx, tx, m.AgentID)
		if e != nil {
			return e
		}
		expected := m.AssignmentRevision
		if m.RollbackRevision > 0 {
			expected = m.RollbackRevision
		}
		if a.Revision != expected {
			m.State = "rollback_failed"
			m.Error = "Назначение изменено, автоматическая перезапись запрещена"
			failed = true
			continue
		}
		if v.h.Sensor == nil || v.h.Sensor.Rules == nil {
			complete = false
			continue
		}
		st := v.h.Sensor.Rules
		if m.RollbackRevision == 0 {
			// Fence even a candidate that was never downloaded: a fresh signed revision
			// replaces it so a reconnecting sensor cannot pick up an aborted candidate.
			a, e = assignSuricata(ctx, tx, rules.Change{AgentID: m.AgentID, ExpectedRevision: a.Revision, BundleID: m.PreviousID}, "system:suricata-rollback", r.GroupID, r.PolicyRevision)
			if e != nil {
				if errors.Is(e, rules.ErrConflict) || errors.Is(e, rules.ErrNotFound) {
					m.State = "rollback_failed"
					m.Error = "Сенсор недоступен для назначения отката"
					failed = true
					continue
				}
				return e
			}
			m.RollbackRevision = a.Revision
			m.State = "rollback_pending"
			complete = false
			continue
		}
		if st.Revision == m.RollbackRevision && (st.State == "error" || st.State == "rollback_failed") {
			m.State = "rollback_failed"
			m.Error = st.Error
			failed = true
			continue
		}
		if st.Revision == m.RollbackRevision && st.State == "applied" && st.AppliedID == m.PreviousID && rolloutHealth(v, r.Config, now) == "" {
			m.State = "rolled_back"
			m.Error = ""
		} else {
			complete = false
		}
	}
	if !complete {
		return nil
	}
	r.State = "rolled_back"
	if failed {
		r.State = "rollback_failed"
	}
	p.State = r.State
	return rolloutHistory(ctx, tx, r, "system:suricata-rollout")
}
