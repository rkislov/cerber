// SPDX-License-Identifier: Apache-2.0
package admin_test

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/rkislov/cerber/internal/admin"
	"github.com/rkislov/cerber/internal/alerts"
	"github.com/rkislov/cerber/internal/app"
	"github.com/rkislov/cerber/internal/ingest"
	"github.com/rkislov/cerber/internal/sensorstate"
	"github.com/rkislov/cerber/internal/storage/sqlite"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSensorAdminPolicyRBACHeartbeatAndRevisions(t *testing.T) {
	ctx := context.Background()
	s, e := sqlite.Open(ctx, ":memory:")
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	hash, _ := admin.HashPassword("fixture-password-long")
	for _, u := range []admin.User{{Username: "root", Role: "administrator"}, {Username: "operator", Role: "operator"}, {Username: "reader", Role: "viewer"}, {Username: "analyst", Role: "analyst"}} {
		if e = s.AdminCommand(ctx, admin.Command{Action: "user.create", Username: u.Username, Role: u.Role, PasswordHash: hash}); e != nil {
			t.Fatal(e)
		}
	}
	a, e := (app.Service{Repo: s}).AddAsset(ctx, "192.0.2.20", "sensor <script>")
	if e != nil {
		t.Fatal(e)
	}
	token := strings.Repeat("a", 64)
	creds := ingest.Credentials{AgentID: "sensor", Token: token}
	for _, id := range []string{"sensor", "endpoint"} {
		if e = s.RegisterAgent(ctx, id, a.ID, ingest.Hash([]byte(token))); e != nil {
			t.Fatal(e)
		}
	}
	at := time.Now().UTC()
	h := ingest.Heartbeat{SchemaVersion: 1, AgentID: "sensor", Platform: "linux", Architecture: "amd64", ObservedAt: at, CollectionStatus: "not_attempted", DeliveryStatus: "not_attempted", Sensor: &sensorstate.Status{StartedAt: at, ObservedAt: at, Inputs: []sensorstate.Input{{ID: "ipfix", Format: "ipfix", Protocol: "udp", Listen: "127.0.0.1:4739", Allow: []string{"127.0.0.1/32"}, Enabled: true, State: "listening"}, {ID: "v9", Format: "netflow9", Protocol: "udp", Listen: "127.0.0.1:2059", Allow: []string{"127.0.0.1/32"}, Enabled: true, State: "listening"}}}}
	receiver := httptest.NewServer(ingest.NewHandler(s))
	defer receiver.Close()
	client, e := ingest.NewClient(receiver.URL, creds, nil)
	if e != nil {
		t.Fatal(e)
	}
	defer client.Close()
	if _, e = client.Heartbeat(ctx, h); e != nil {
		t.Fatal(e)
	}
	handler, e := admin.NewHandler(s, "", admin.Options{Policy: alerts.Policy{OfflineAfter: time.Minute, InventoryMaxAge: time.Hour}})
	if e != nil {
		t.Fatal(e)
	}
	server := httptest.NewServer(handler)
	defer server.Close()
	type session struct {
		cookie *http.Cookie
		csrf   string
	}
	request := func(u session, method, path, origin string, v any) (int, []byte, *http.Response) {
		t.Helper()
		data, _ := json.Marshal(v)
		req, _ := http.NewRequest(method, server.URL+"/admin/"+path, strings.NewReader(string(data)))
		req.Header.Set("Origin", origin)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-CSRF-Token", u.csrf)
		if u.cookie != nil {
			req.AddCookie(u.cookie)
		}
		res, e := server.Client().Do(req)
		if e != nil {
			t.Fatal(e)
		}
		defer res.Body.Close()
		b, _ := io.ReadAll(res.Body)
		return res.StatusCode, b, res
	}
	login := func(name string) session {
		code, _, res := request(session{}, "POST", "login", server.URL, map[string]string{"username": name, "password": "fixture-password-long"})
		if code != 200 {
			t.Fatal(code)
		}
		u := session{cookie: res.Cookies()[0]}
		_, b, _ := request(u, "GET", "api/session", "", nil)
		var v map[string]string
		json.Unmarshal(b, &v)
		u.csrf = v["csrf"]
		return u
	}
	root := login("root")
	command := sensorstate.Change{AgentID: "sensor", Inputs: []sensorstate.Control{{ID: "ipfix", Enabled: false, Allow: []string{"127.0.0.1/32"}, TemplateTTLSeconds: 300}}}
	if code, _, _ := request(session{}, "GET", "api/sensors", "", nil); code != 401 {
		t.Fatal("unauthenticated", code)
	}
	for _, name := range []string{"operator", "reader", "analyst"} {
		u := login(name)
		code, b, _ := request(u, "GET", "api/sensors", "", nil)
		if code != 200 || strings.Contains(string(b), "<script>") {
			t.Fatal(code, string(b))
		}
		var list struct {
			Items []struct {
				Agent ingest.AgentStatus `json:"agent"`
			}
		}
		if json.Unmarshal(b, &list) != nil || len(list.Items) != 1 || list.Items[0].Agent.AgentID != "sensor" {
			t.Fatal("wrong sensor registry", string(b))
		}
		if code, _, _ := request(u, "POST", "api/sensors", server.URL, command); code != 403 {
			t.Fatal("role bypass", name, code)
		}
	}
	if code, _, _ := request(session{cookie: root.cookie}, "POST", "api/sensors", server.URL, command); code != 403 {
		t.Fatal("CSRF", code)
	}
	if code, _, _ := request(root, "POST", "api/sensors", "http://attacker.invalid", command); code != 403 {
		t.Fatal("origin", code)
	}
	// A policy larger than the old 4096-byte heartbeat receipt is delivered intact.
	for n := 0; n < 128; n++ {
		command.Inputs[0].Allow = append(command.Inputs[0].Allow, fmt.Sprintf("2001:db8:%x::/64", n))
	}
	command.Inputs[0].Allow = command.Inputs[0].Allow[1:]
	other := command.Inputs[0]
	other.ID = "v9"
	command.Inputs = append(command.Inputs, other)
	code, b, _ := request(root, "POST", "api/sensors", server.URL, command)
	if code != 200 {
		t.Fatal(code, string(b))
	}
	if code, _, _ := request(root, "POST", "api/sensors", server.URL, command); code != 409 {
		t.Fatal("lost update", code)
	}
	receipt, e := client.Heartbeat(ctx, h)
	if e != nil || receipt.SensorPolicy == nil || receipt.SensorPolicy.Revision != 1 || len(receipt.SensorPolicy.Inputs) != 2 {
		t.Fatal(receipt, e)
	}
	h.Sensor.AppliedRevision = 1
	h.Sensor.Inputs[0].Enabled = false
	if _, e = client.Heartbeat(ctx, h); e != nil {
		t.Fatal(e)
	}
	command.ExpectedRevision = 1
	command.Inputs[0].ID = "not-local"
	if code, _, _ := request(root, "POST", "api/sensors", server.URL, command); code != 400 {
		t.Fatal("unknown local input", code)
	}
	command.Inputs = nil
	if code, b, _ := request(root, "POST", "api/sensors", server.URL, command); code != 200 {
		t.Fatal("reset", code, string(b))
	}
	if e = s.AdminCommand(ctx, admin.Command{Action: "agent.revoke", AgentID: "sensor"}); e != nil {
		t.Fatal(e)
	}
	command.ExpectedRevision = 2
	if code, _, _ := request(root, "POST", "api/sensors", server.URL, command); code != 409 {
		t.Fatal("revoked sensor write", code)
	}
	if _, e = client.Heartbeat(ctx, h); e == nil {
		t.Fatal("revoked heartbeat")
	}
}

func TestSensorDoesNotRequireInventoryButStillMonitorsContact(t *testing.T) {
	now := time.Now().UTC()
	s := ingest.AgentStatus{CreatedAt: now.Add(-48 * time.Hour), LastSeenAt: &now, Health: &ingest.Heartbeat{Sensor: &sensorstate.Status{}}}
	p := alerts.Policy{OfflineAfter: time.Minute, InventoryMaxAge: time.Hour}
	s.Evaluate(now, p.OfflineAfter, p.InventoryMaxAge)
	if s.InventoryStatus != "not_applicable" {
		t.Fatal(s.InventoryStatus)
	}
	if len(alerts.Conditions(s, now, p)) != 0 {
		t.Fatal("sensor inventory false alarm")
	}
	conditions := alerts.Conditions(s, now.Add(2*time.Minute), p)
	if _, ok := conditions["agent_offline"]; !ok {
		t.Fatal("lost contact not monitored")
	}
	if _, ok := conditions["inventory_stale"]; ok {
		t.Fatal("stale sensor inventory")
	}
}
