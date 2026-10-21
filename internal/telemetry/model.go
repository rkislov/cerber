// SPDX-License-Identifier: Apache-2.0
// Package telemetry defines source security events, separate from Cerber's product audit.
package telemetry

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"
	"unicode/utf8"
)

const MaxBatchBytes = 2 << 20
const MaxRecords = 100

var ErrInvalid = errors.New("invalid security event batch")
var ErrConflict = errors.New("immutable security event conflict")
var ErrFull = errors.New("event spool full; source cursor retained")
var ErrExpired = errors.New("event archive expired")
var ErrNotFound = errors.New("event not found")

type Raw struct {
	ID         string          `json:"id"`
	Source     string          `json:"source"`
	Cursor     string          `json:"cursor"`
	ObservedAt time.Time       `json:"observed_at"`
	Data       json.RawMessage `json:"data"`
}
type Batch struct {
	SchemaVersion int    `json:"schema_version"`
	ID            string `json:"id"`
	AgentID       string `json:"agent_id"`
	Records       []Raw  `json:"records"`
}
type Receipt struct {
	BatchID    string    `json:"batch_id"`
	AgentID    string    `json:"agent_id"`
	Count      int       `json:"count"`
	ReceivedAt time.Time `json:"received_at"`
}

func ID(parts ...string) string {
	b, _ := json.Marshal(parts)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
func Identifier(s string) bool {
	if len(s) != 64 {
		return false
	}
	_, e := hex.DecodeString(s)
	return e == nil && strings.ToLower(s) == s
}
func AgentIdentifier(s string) bool {
	if len(s) < 1 || len(s) > 128 {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
			return false
		}
	}
	return true
}
func (b Batch) Validate() error {
	if b.SchemaVersion != 1 || !Identifier(b.ID) || !AgentIdentifier(b.AgentID) || len(b.Records) < 1 || len(b.Records) > MaxRecords {
		return ErrInvalid
	}
	seen := map[string]bool{}
	for _, r := range b.Records {
		if !Identifier(r.ID) || seen[r.ID] || !ValidSource(r.Source) || len(r.Cursor) < 1 || len(r.Cursor) > 2048 || !utf8.ValidString(r.Cursor) || strings.ContainsAny(r.Cursor, "\x00\r\n") || r.ObservedAt.IsZero() || len(r.Data) == 0 || len(r.Data) > 16384 || !json.Valid(r.Data) {
			return ErrInvalid
		}
		seen[r.ID] = true
	}
	data, e := json.Marshal(b)
	if e != nil || len(data) > MaxBatchBytes {
		return ErrInvalid
	}
	return nil
}
func ValidSource(s string) bool {
	return s == "agent:ioc" || s == "network:cef" || s == "journald" || s == "windows:Security" || s == "windows:System" || s == "windows:Application"
}

type Normalized struct {
	FilePath        string    `json:"file_path,omitempty"`
	SHA256          string    `json:"sha256,omitempty"`
	MD5             string    `json:"md5,omitempty"`
	Product         string    `json:"product,omitempty"`
	Device          string    `json:"device,omitempty"`
	DestinationIP   string    `json:"destination_ip,omitempty"`
	DestinationPort int       `json:"destination_port,omitempty"`
	Request         string    `json:"request,omitempty"`
	Sequence        int64     `json:"sequence"`
	ID              string    `json:"id"`
	AgentID         string    `json:"agent_id"`
	AssetID         string    `json:"asset_id"`
	Source          string    `json:"source"`
	EventTime       time.Time `json:"event_time"`
	ReceivedAt      time.Time `json:"received_at"`
	Parser          string    `json:"parser"`
	Status          string    `json:"status"`
	Class           string    `json:"class"`
	Action          string    `json:"action"`
	Outcome         string    `json:"outcome"`
	User            string    `json:"user,omitempty"`
	SourceIP        string    `json:"source_ip,omitempty"`
	Code            string    `json:"code,omitempty"`
	Message         string    `json:"message"`
}
type RawRecord struct {
	Archived         bool
	ArchiveID        string
	Sequence         int64
	AgentID, AssetID string
	ReceivedAt       time.Time
	Raw              Raw
}
type Detection struct {
	GroupKey       string    `json:"group_key,omitempty"`
	Sequence       int64     `json:"sequence"`
	ID             string    `json:"id"`
	Rule           string    `json:"rule"`
	Version        int       `json:"version"`
	AgentID        string    `json:"agent_id"`
	AssetID        string    `json:"asset_id"`
	User           string    `json:"user"`
	SourceIP       string    `json:"source_ip"`
	Severity       string    `json:"severity"`
	Title          string    `json:"title"`
	CreatedAt      time.Time `json:"created_at"`
	FirstSeen      time.Time `json:"first_seen"`
	LastSeen       time.Time `json:"last_seen"`
	Evidence       []string  `json:"evidence"`
	State          string    `json:"state"`
	AcknowledgedBy string    `json:"acknowledged_by,omitempty"`
}
type Query struct {
	Text, Source, User, SourceIP, Code, Outcome, TimeField string
	From, Until                                            *time.Time
	Before                                                 int64
	AgentID, Class, Status                                 string
	Limit                                                  int
}
type PipelineStatus struct {
	Raw              int64 `json:"raw"`
	Normalized       int64 `json:"normalized"`
	Quarantined      int64 `json:"quarantined"`
	Detections       int64 `json:"detections"`
	ProcessorCursor  int64 `json:"processor_cursor"`
	CorrelatorCursor int64 `json:"correlator_cursor"`
}
type Reader interface {
	ReadEvents(context.Context, Query) ([]Normalized, error)
	ReadDetections(context.Context, int64, int) ([]Detection, error)
	ReadRaw(context.Context, string) (RawRecord, error)
	Status(context.Context) (PipelineStatus, error)
}
