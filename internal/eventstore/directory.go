// SPDX-License-Identifier: Apache-2.0
package eventstore

import (
	"context"
	"encoding/json"
	"github.com/rkislov/cerber/internal/directory"
	"github.com/rkislov/cerber/internal/rulepolicy"
	"github.com/rkislov/cerber/internal/telemetry"
	"strings"
)

type DirectorySource interface {
	Enabled() bool
	Prepare(context.Context, []directory.Query)
	Attest(telemetry.Normalized) telemetry.Normalized
}

func (s *Store) SetDirectory(r DirectorySource) {
	s.policyMu.Lock()
	s.directory = r
	s.policyMu.Unlock()
}
func (s *Store) directoryResolver() DirectorySource {
	s.policyMu.RLock()
	defer s.policyMu.RUnlock()
	return s.directory
}
func (s *Store) attest(n telemetry.Normalized) telemetry.Normalized {
	if r := s.directoryResolver(); r != nil {
		return r.Attest(n)
	}
	return n
}

// Preflight runs outside any transaction, with bounded input and network budgets.
// GUID history is warmed too, allowing a configured directory to resolve older
// source names without changing saved normalized events or manufacturing SIDs.
func (s *Store) prepareDirectory(ctx context.Context, ids ...string) error {
	r := s.directoryResolver()
	if r == nil || !r.Enabled() {
		return nil
	}
	query := `SELECT payload FROM normalized_events WHERE sequence>(SELECT position FROM consumer_cursors WHERE name='correlator/1') ORDER BY sequence LIMIT 100`
	args := []any{}
	if len(ids) > 0 {
		if len(ids) > 100 {
			return rulepolicy.ErrInvalid
		}
		placeholders := []string{}
		for _, id := range ids {
			if !telemetry.Identifier(id) {
				return rulepolicy.ErrInvalid
			}
			placeholders = append(placeholders, "?")
			args = append(args, id)
		}
		query = "SELECT payload FROM normalized_events WHERE id IN (" + strings.Join(placeholders, ",") + ") ORDER BY sequence LIMIT 100"
	}
	rows, e := s.db.QueryContext(ctx, query, args...)
	if e != nil {
		return e
	}
	events := []telemetry.Normalized{}
	size := 0
	for rows.Next() {
		var p string
		if e = rows.Scan(&p); e != nil {
			break
		}
		size += len(p)
		if size > 8<<20 {
			break
		}
		var n telemetry.Normalized
		if e = json.Unmarshal([]byte(p), &n); e != nil {
			break
		}
		events = append(events, n)
	}
	if e == nil {
		e = rows.Err()
	}
	rows.Close()
	if e != nil {
		return e
	}
	guids := map[string]bool{}
	initial := append([]telemetry.Normalized{}, events...)
	for _, n := range initial {
		if n.Identity == nil || n.Identity.SessionGUID == "" || n.Class != "authentication" || guids[n.Identity.SessionGUID] || len(guids) >= 16 {
			continue
		}
		guid := n.Identity.SessionGUID
		guids[guid] = true
		for _, q := range []string{
			`SELECT payload FROM normalized_events INDEXED BY normalized_credential_guid WHERE json_extract(payload,'$.windows_auth.target_guid') IS NOT NULL AND json_extract(payload,'$.windows_auth.target_guid')=? AND sequence<=? ORDER BY event_time DESC,sequence DESC LIMIT 101`,
			`SELECT payload FROM normalized_events INDEXED BY normalized_chain_guid WHERE json_extract(payload,'$.identity.session_guid') IS NOT NULL AND json_extract(payload,'$.identity.session_guid')=? AND class='kerberos' AND sequence<=? ORDER BY event_time DESC,sequence DESC LIMIT 101`,
		} {
			rows, e = s.db.QueryContext(ctx, q, guid, n.Sequence)
			if e != nil {
				return e
			}
			for rows.Next() {
				var p string
				if e = rows.Scan(&p); e != nil {
					break
				}
				size += len(p)
				if size > 8<<20 {
					break
				}
				var v telemetry.Normalized
				if e = json.Unmarshal([]byte(p), &v); e != nil {
					break
				}
				events = append(events, v)
			}
			if e == nil {
				e = rows.Err()
			}
			rows.Close()
			if e != nil {
				return e
			}
			if size > 8<<20 {
				break
			}
		}
		if size > 8<<20 {
			break
		}
	}
	queries := []directory.Query{}
	for _, n := range events {
		queries = append(queries, directory.Queries(n)...)
	}
	r.Prepare(ctx, queries)
	return nil
}
