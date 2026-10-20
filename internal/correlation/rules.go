// SPDX-License-Identifier: Apache-2.0
// Package correlation evaluates versioned rules independently of collection and storage.
package correlation

import (
	"time"

	"github.com/rkislov/cerber/internal/telemetry"
)

const Window = 5 * time.Minute
const Threshold = 5

// Evaluate uses event time and exact source identity. The store supplies immutable
// evidence in [event_time-5m,event_time], including late arrivals already processed.
func Evaluate(n telemetry.Normalized, failures []telemetry.Normalized) *telemetry.Detection {
	rule, title, severity := "", "", "medium"
	if n.Class == "audit" && n.Action == "log_cleared" {
		rule = "windows.audit_log_cleared"
		title = "Очищен журнал аудита Windows"
		severity = "high"
	} else {
		if n.Class != "authentication" || n.User == "" || n.SourceIP == "" || len(failures) < Threshold {
			return nil
		}
		if n.Outcome == "failure" {
			rule = "auth.repeated_failures"
			title = "Серия неудачных входов"
		} else if n.Outcome == "success" {
			rule = "auth.success_after_failures"
			title = "Успешный вход после серии отказов"
			severity = "high"
		} else {
			return nil
		}
	}
	evidence := []string{}
	first := n.EventTime
	for _, f := range failures {
		evidence = append(evidence, f.ID)
		if f.EventTime.Before(first) {
			first = f.EventTime
		}
	}
	present := false
	for _, id := range evidence {
		if id == n.ID {
			present = true
		}
	}
	if !present {
		evidence = append(evidence, n.ID)
	}
	return &telemetry.Detection{ID: telemetry.ID(rule, "1", n.ID), Rule: rule, Version: 1, AgentID: n.AgentID, AssetID: n.AssetID, User: n.User, SourceIP: n.SourceIP, Severity: severity, Title: title, CreatedAt: n.ReceivedAt, FirstSeen: first, LastSeen: n.EventTime, Evidence: evidence, State: "open"}
}
