// SPDX-License-Identifier: Apache-2.0
// Package admin serves the local SIEM administration UI without a hosted dependency.
package admin

import (
	"context"
	"encoding/json"
	"github.com/rkislov/cerber/internal/alerts"
	"github.com/rkislov/cerber/internal/ingest"
	"github.com/rkislov/cerber/internal/inventory"
	"github.com/rkislov/cerber/internal/jobs"
	"time"
)

type Overview struct {
	Agents           int `json:"agents"`
	Online           int `json:"online"`
	Offline          int `json:"offline"`
	NeverSeen        int `json:"never_seen"`
	Revoked          int `json:"revoked"`
	InventoryStale   int `json:"inventory_stale"`
	InventoryMissing int `json:"inventory_missing"`
	ActiveAlerts     int `json:"active_alerts"`
	Unacknowledged   int `json:"unacknowledged"`
}
type InventoryPage struct {
	Summary            inventory.Summary `json:"summary"`
	PackageManager     string            `json:"package_manager,omitempty"`
	RepositoryMetadata string            `json:"repository_metadata,omitempty"`
	Section            string            `json:"section"`
	Offset             int               `json:"offset"`
	Total              int               `json:"total"`
	Items              []json.RawMessage `json:"items"`
}
type Store interface {
	JobCommand(context.Context, jobs.Command, time.Time) (string, error)
	Jobs(context.Context, string, int64, int) ([]jobs.Job, error)
	JobSchedules(context.Context, string, string, int) ([]jobs.Schedule, error)
	AdminLogin(context.Context, User) error
	AdminUser(context.Context, string) (User, error)
	AdminUserCount(context.Context) (int, error)
	AdminUsers(context.Context, string, int) ([]User, error)
	AdminCommand(context.Context, Command) error
	AdminOverview(context.Context, time.Time, alerts.Policy) (Overview, error)
	AgentStatuses(context.Context, string, string, int) ([]ingest.AgentStatus, error)
	Alerts(context.Context, string, int64, int) ([]alerts.Alert, error)
	AcknowledgeAlert(context.Context, string, string) (alerts.Alert, error)
	AdminInventory(context.Context, string, string, int, int) (InventoryPage, error)
}
