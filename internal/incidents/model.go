// SPDX-License-Identifier: Apache-2.0
// Package incidents defines the investigation workflow independently of event storage.
package incidents

import (
	"errors"
	"time"
)

var ErrInvalid = errors.New("invalid incident command")
var ErrConflict = errors.New("incident version or state changed")
var ErrNotFound = errors.New("incident not found")

type Card struct {
	Sequence       int64     `json:"sequence"`
	ID             string    `json:"id"`
	Title          string    `json:"title"`
	Description    string    `json:"description"`
	Severity       string    `json:"severity"`
	State          string    `json:"state"`
	Assignee       string    `json:"assignee"`
	CreatedBy      string    `json:"created_by"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
	Version        int       `json:"version"`
	Resolution     string    `json:"resolution"`
	Outcome        string    `json:"outcome"`
	DetectionCount int       `json:"detection_count"`
}
type Command struct {
	DetectionIDs []string `json:"detection_ids,omitempty"`
	Action       string   `json:"action"`
	ID           string   `json:"id,omitempty"`
	Version      int      `json:"version,omitempty"`
	Title        string   `json:"title,omitempty"`
	Description  string   `json:"description,omitempty"`
	Severity     string   `json:"severity,omitempty"`
	Assignee     string   `json:"assignee,omitempty"`
	State        string   `json:"state,omitempty"`
	Outcome      string   `json:"outcome,omitempty"`
	Text         string   `json:"text,omitempty"`
	DetectionID  string   `json:"detection_id,omitempty"`
}
type Entry struct {
	Sequence int64     `json:"sequence"`
	Kind     string    `json:"kind"`
	Actor    string    `json:"actor"`
	At       time.Time `json:"at"`
	Text     string    `json:"text"`
	Version  int       `json:"version"`
}

func ValidSeverity(s string) bool {
	return s == "low" || s == "medium" || s == "high" || s == "critical"
}
func ValidState(s string) bool {
	return s == "new" || s == "in_progress" || s == "contained" || s == "resolved" || s == "closed"
}
func ValidOutcome(s string) bool {
	return s == "confirmed" || s == "false_positive" || s == "benign" || s == "inconclusive"
}
func CanTransition(from, to string) bool {
	switch from {
	case "new":
		return to == "in_progress"
	case "in_progress":
		return to == "contained" || to == "resolved"
	case "contained":
		return to == "in_progress" || to == "resolved"
	case "resolved":
		return to == "closed" || to == "in_progress"
	case "closed":
		return to == "in_progress"
	}
	return false
}
