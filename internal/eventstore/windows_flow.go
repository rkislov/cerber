// SPDX-License-Identifier: Apache-2.0
package eventstore

import (
	"context"
	"database/sql"
	"encoding/json"
	"github.com/rkislov/cerber/internal/correlation"
	"github.com/rkislov/cerber/internal/rulepolicy"
	"github.com/rkislov/cerber/internal/telemetry"
	"time"
)

func (r *ruleRuntime) windowsFlowHistory(ctx context.Context, tx *sql.Tx, rule string, n telemetry.Normalized) ([]telemetry.Normalized, bool, error) {
	cfg := r.policies[rule].Config
	from := n.EventTime.Add(-time.Duration(cfg.WindowSeconds) * time.Second)
	out := []telemetry.Normalized{}
	truncated := false
	size := 0
	queries := []struct {
		q     string
		value string
	}{
		{`SELECT payload FROM normalized_events INDEXED BY normalized_credential_guid WHERE json_extract(payload,'$.windows_auth.target_guid') IS NOT NULL AND json_extract(payload,'$.windows_auth.target_guid')=? AND class='credentials' AND event_time>=? AND event_time<=? AND sequence<=? AND status='parsed' ORDER BY event_time DESC,sequence DESC LIMIT 101`, n.Identity.SessionGUID},
		{`SELECT payload FROM normalized_events INDEXED BY normalized_chain_guid WHERE json_extract(payload,'$.identity.session_guid') IS NOT NULL AND json_extract(payload,'$.identity.session_guid')=? AND class='kerberos' AND event_time>=? AND event_time<=? AND sequence<=? AND status='parsed' ORDER BY event_time DESC,sequence DESC LIMIT 101`, n.Identity.SessionGUID},
	}
	for _, query := range queries {
		rows, e := tx.QueryContext(ctx, query.q, query.value, stamp(from.Add(-time.Second)), stamp(n.EventTime.Add(time.Second)), n.Sequence)
		if e != nil {
			return nil, false, e
		}
		count := 0
		for rows.Next() {
			count++
			if count > 100 {
				truncated = true
				break
			}
			var p string
			if e = rows.Scan(&p); e != nil {
				break
			}
			size += len(p)
			if size > 8<<20 {
				truncated = true
				break
			}
			var v telemetry.Normalized
			if e = json.Unmarshal([]byte(p), &v); e != nil {
				break
			}
			out = append(out, v)
		}
		if e == nil {
			e = rows.Err()
		}
		rows.Close()
		if e != nil {
			return nil, false, e
		}
		if size > 8<<20 {
			break
		}
	}
	filtered := []telemetry.Normalized{}
	var attempt *telemetry.Normalized
	for _, v := range out {
		if v.EventTime.Before(from) || v.EventTime.After(n.EventTime) {
			continue
		}
		groups, e := r.groups(ctx, rule, v)
		if e != nil {
			return nil, false, e
		}
		if _, why := rulepolicy.ScopeEvent(cfg, v.AgentID, v.User, v.SourceIP, v.DestinationIP, groups); why != "" {
			continue
		}
		filtered = append(filtered, v)
		if correlation.CredentialMatches(v, n) && (attempt == nil || v.EventTime.After(attempt.EventTime) || v.EventTime.Equal(attempt.EventTime) && v.Sequence > attempt.Sequence) {
			copy := v
			attempt = &copy
		}
	}
	if attempt != nil && attempt.Identity.AccountKey != "" && attempt.Identity.LocalSession != "" {
		var p string
		e := tx.QueryRowContext(ctx, `SELECT payload FROM normalized_events INDEXED BY normalized_actor_session WHERE agent_id=? AND json_extract(payload,'$.identity.local_session') IS NOT NULL AND json_extract(payload,'$.identity.local_session')=? AND json_extract(payload,'$.identity.account_key')=? AND json_extract(payload,'$.asset_id')=? AND class='authentication' AND outcome='success' AND json_extract(payload,'$.action')='logon' AND status='parsed' AND event_time>=? AND event_time<? AND sequence<=? ORDER BY event_time DESC,sequence DESC LIMIT 1`, attempt.AgentID, attempt.Identity.LocalSession, attempt.Identity.AccountKey, attempt.AssetID, stamp(from), stamp(attempt.EventTime), n.Sequence).Scan(&p)
		if e != nil && e != sql.ErrNoRows {
			return nil, false, e
		}
		if e == nil {
			size += len(p)
			if size > 8<<20 {
				truncated = true
			} else {
				var v telemetry.Normalized
				if e = json.Unmarshal([]byte(p), &v); e != nil {
					return nil, false, e
				}
				groups, e := r.groups(ctx, rule, v)
				if e != nil {
					return nil, false, e
				}
				if _, why := rulepolicy.ScopeEvent(cfg, v.AgentID, v.User, v.SourceIP, v.DestinationIP, groups); why == "" {
					filtered = append(filtered, v)
				}
			}
		}
	}
	return filtered, truncated, nil
}
