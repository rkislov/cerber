// SPDX-License-Identifier: Apache-2.0
package patch

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/rkislov/cerber/internal/inventory"
	"reflect"
	"regexp"
	"time"
)

var ErrInvalid = errors.New("invalid patch request")
var ErrConflict = errors.New("patch state conflict")

type Request struct {
	SchemaVersion int                `json:"schema_version"`
	PreviewID     string             `json:"preview_id,omitempty"`
	ID            string             `json:"id"`
	AgentID       string             `json:"agent_id"`
	InventoryID   string             `json:"inventory_id"`
	Mode          string             `json:"mode"`
	Manager       string             `json:"manager"`
	Updates       []inventory.Update `json:"updates"`
	ExpiresAt     time.Time          `json:"expires_at"`
	NoReboot      bool               `json:"no_reboot"`
}
type Ticket struct {
	Payload   json.RawMessage `json:"payload"`
	Signature []byte          `json:"signature"`
}
type Item struct {
	ID     string `json:"id"`
	Status string `json:"status"`
	Code   string `json:"code"`
}
type Result struct {
	ID     string `json:"id"`
	Status string `json:"status"`
	Reboot string `json:"reboot_required"`
	Items  []Item `json:"items"`
	Detail string `json:"detail"`
}
type Job struct {
	Sequence  int64     `json:"sequence"`
	Request   Request   `json:"request"`
	State     string    `json:"state"`
	CreatedBy string    `json:"created_by"`
	CreatedAt time.Time `json:"created_at"`
	Result    *Result   `json:"result,omitempty"`
}
type Command struct {
	Action      string   `json:"action"`
	AgentID     string   `json:"agent_id"`
	InventoryID string   `json:"inventory_id"`
	UpdateIDs   []string `json:"update_ids"`
	PreviewID   string   `json:"preview_id"`
	ID          string   `json:"id"`
}

func (r Request) Validate() error {
	if r.SchemaVersion != 1 {
		return ErrInvalid
	}
	if r.Manager != "apt" && r.Manager != "dnf" && r.Manager != "wua" {
		return ErrInvalid
	}
	b, e := json.Marshal(r)
	if e != nil || len(b) > 96<<10 {
		return ErrInvalid
	}
	if !validID(r.ID) || !regexp.MustCompile(`^[a-zA-Z0-9_-]{1,128}$`).MatchString(r.AgentID) || r.InventoryID == "" || !r.NoReboot || (r.Mode != "preview" && r.Mode != "install") || len(r.Updates) < 1 || len(r.Updates) > 20 || r.ExpiresAt.IsZero() {
		return ErrInvalid
	}
	seen := map[string]bool{}
	for _, u := range r.Updates {
		if u.ID == "" || len(u.ID) > 2048 || u.State != "available" || seen[u.ID] {
			return ErrInvalid
		}
		seen[u.ID] = true
	}
	return nil
}
func Sign(r Request, key ed25519.PrivateKey) (Ticket, error) {
	if e := r.Validate(); e != nil {
		return Ticket{}, e
	}
	b, e := json.Marshal(r)
	if e != nil {
		return Ticket{}, e
	}
	return Ticket{b, ed25519.Sign(key, b)}, nil
}
func (t Ticket) Verify(key ed25519.PublicKey, agent string, now time.Time) (Request, error) {
	var r Request
	if len(key) != 32 || !ed25519.Verify(key, t.Payload, t.Signature) || json.Unmarshal(t.Payload, &r) != nil || r.Validate() != nil || r.AgentID != agent || !now.Before(r.ExpiresAt) || r.ExpiresAt.After(now.Add(2*time.Hour)) {
		return r, ErrInvalid
	}
	return r, nil
}
func (r Result) Validate(q Request) error {
	if r.ID != q.ID || len(r.Detail) > 4096 || len(r.Items) != len(q.Updates) || (r.Status != "succeeded" && r.Status != "partial" && r.Status != "failed" && r.Status != "unknown") || (r.Reboot != "yes" && r.Reboot != "no" && r.Reboot != "unknown") {
		return ErrInvalid
	}
	seen := map[string]bool{}
	good := 0
	for _, i := range r.Items {
		if seen[i.ID] || len(i.Code) > 256 {
			return ErrInvalid
		}
		seen[i.ID] = true
		found := false
		for _, u := range q.Updates {
			found = found || u.ID == i.ID
		}
		if !found {
			return ErrInvalid
		}
		switch i.Status {
		case "ready", "installed", "already_installed":
			good++
		case "failed", "unknown", "not_applicable":
		default:
			return ErrInvalid
		}
		if q.Mode == "install" && i.Status == "ready" || q.Mode == "preview" && (i.Status == "installed" || i.Status == "already_installed") {
			return ErrInvalid
		}
	}
	if r.Status == "succeeded" && good != len(q.Updates) || r.Status == "partial" && (good == 0 || good == len(q.Updates)) {
		return ErrInvalid
	}
	return nil
}
func Failure(q Request, code string) Result {
	r := Result{ID: q.ID, Status: "failed", Reboot: "unknown", Detail: code}
	for _, u := range q.Updates {
		r.Items = append(r.Items, Item{u.ID, "failed", code})
	}
	return r
}
func Matches(a, b inventory.Update) bool {
	a.Source = ""
	b.Source = ""
	return reflect.DeepEqual(a, b)
}

func validID(s string) bool { b, e := hex.DecodeString(s); return e == nil && len(b) == 16 }
