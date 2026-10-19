// SPDX-License-Identifier: Apache-2.0
// Package ingest defines the agent-to-server delivery contract, independent of HTTP and storage.
package ingest

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/rkislov/cerber/internal/inventory"
	"time"
)

const MaxReportBytes int64 = 40 << 20

// Report is immutable once queued. A retry must use the same ID and contents.
type Report struct {
	SchemaVersion int                `json:"schema_version"`
	ID            string             `json:"id"`
	AgentID       string             `json:"agent_id"`
	Snapshot      inventory.Snapshot `json:"snapshot"`
	Checks        []inventory.Check  `json:"checks"`
}
type Receipt struct {
	ReportID   string    `json:"report_id"`
	AgentID    string    `json:"agent_id"`
	SnapshotID string    `json:"snapshot_id"`
	ReceivedAt time.Time `json:"received_at"`
	Duplicate  bool      `json:"duplicate"`
}

func Identifier(s string) bool {
	if len(s) < 1 || len(s) > 128 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}
func (r Report) Validate() error {
	if r.SchemaVersion != 1 || !Identifier(r.ID) || !Identifier(r.AgentID) || len(r.Checks) > 100 {
		return fmt.Errorf("invalid report identity or check count")
	}
	if err := r.Snapshot.Validate(); err != nil {
		return err
	}
	ids := map[string]bool{}
	for _, c := range r.Checks {
		if err := c.Validate(); err != nil {
			return err
		}
		if c.InventoryID != r.Snapshot.ID || c.AssetID != r.Snapshot.AssetID || ids[c.ID] {
			return fmt.Errorf("check must belong to report inventory and have a unique ID")
		}
		ids[c.ID] = true
	}
	snapshotBytes, err := json.Marshal(r.Snapshot)
	if err != nil {
		return err
	}
	if int64(len(snapshotBytes)) > inventory.MaxSnapshotBytes {
		return fmt.Errorf("snapshot exceeds 32 MiB")
	}
	reportBytes, err := json.Marshal(r)
	if err != nil {
		return err
	}
	if int64(len(reportBytes)) > MaxReportBytes {
		return fmt.Errorf("report exceeds 40 MiB")
	}
	return nil
}
func Hash(data []byte) string { h := sha256.Sum256(data); return hex.EncodeToString(h[:]) }
func RemoteID(agent, kind, id string) string {
	return Hash([]byte(agent + "\x00" + kind + "\x00" + id))
}
