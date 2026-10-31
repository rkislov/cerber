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
	"github.com/rkislov/cerber/internal/jobs"
	"github.com/rkislov/cerber/internal/sensorstate"
	"github.com/rkislov/cerber/internal/storage/sqlite"
	rules "github.com/rkislov/cerber/internal/suricatarules"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSuricataCatalogAssignmentRBACDeliveryAndRollback(t *testing.T) {
	ctx := context.Background()
	s, e := sqlite.Open(ctx, ":memory:")
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	pw, _ := admin.HashPassword("suricata-test-password")
	for _, u := range []admin.User{{Username: "owner", Role: "administrator"}, {Username: "viewer", Role: "viewer"}} {
		if e = s.AdminCommand(ctx, admin.Command{Action: "user.create", Username: u.Username, Role: u.Role, PasswordHash: pw}); e != nil {
			t.Fatal(e)
		}
	}
	asset, e := (app.Service{Repo: s}).AddAsset(ctx, "192.0.2.10", "sensor")
	if e != nil {
		t.Fatal(e)
	}
	creds := ingest.Credentials{AgentID: "sensor", Token: strings.Repeat("a", 64)}
	hash := ingest.Hash([]byte(creds.Token))
	if e = s.RegisterAgent(ctx, creds.AgentID, asset.ID, hash); e != nil {
		t.Fatal(e)
	}
	now := time.Now().UTC()
	h := ingest.Heartbeat{SchemaVersion: 1, AgentID: creds.AgentID, Platform: "linux", Architecture: "amd64", ObservedAt: now, CollectionStatus: "not_attempted", DeliveryStatus: "not_attempted", Sensor: &sensorstate.Status{StartedAt: now, ObservedAt: now, Rules: &rules.Status{Version: 1, EngineMajor: 7, State: "idle", UpdatedAt: now}}}
	if _, e = s.AcceptHeartbeat(ctx, creds.AgentID, hash, h); e != nil {
		t.Fatal(e)
	}
	handler, e := admin.NewHandler(s, "", admin.Options{Policy: alerts.Policy{OfflineAfter: time.Minute, InventoryMaxAge: time.Hour}})
	if e != nil {
		t.Fatal(e)
	}
	server := httptest.NewServer(handler)
	defer server.Close()
	type session struct {
		client *http.Client
		csrf   string
	}
	call := func(u session, method, path string, body any, csrf bool) (int, []byte) {
		t.Helper()
		b, _ := json.Marshal(body)
		req, _ := http.NewRequest(method, server.URL+path, strings.NewReader(string(b)))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Origin", server.URL)
		if csrf {
			req.Header.Set("X-CSRF-Token", u.csrf)
		}
		res, e := u.client.Do(req)
		if e != nil {
			t.Fatal(e)
		}
		defer res.Body.Close()
		data, _ := io.ReadAll(res.Body)
		return res.StatusCode, data
	}
	login := func(name string) session {
		t.Helper()
		jar, _ := cookiejar.New(nil)
		u := session{client: &http.Client{Jar: jar}}
		code, _ := call(u, "POST", "/admin/login", map[string]string{"username": name, "password": "suricata-test-password"}, false)
		if code != 200 {
			t.Fatal(code)
		}
		_, data := call(u, "GET", "/admin/api/session", nil, false)
		var v map[string]string
		_ = json.Unmarshal(data, &v)
		u.csrf = v["csrf"]
		return u
	}
	owner := login("owner")
	viewer := login("viewer")
	for _, body := range []any{map[string]any{"action": "feed", "feed": rules.FeedChange{EngineMajor: 7, Enabled: true, IntervalHours: 24, NextRunAt: time.Now().Add(time.Hour)}}, map[string]any{"action": "group", "group": rules.GroupChange{}}} {
		if code, _ := call(viewer, "POST", "/admin/api/suricata-automation", body, true); code != 403 {
			t.Fatal("automation viewer", code)
		}
		if code, _ := call(owner, "POST", "/admin/api/suricata-automation", body, false); code != 403 {
			t.Fatal("automation CSRF", code)
		}
	}
	if code, _ := call(owner, "POST", "/admin/api/suricata-automation", map[string]any{"action": "feed", "feed": rules.FeedChange{EngineMajor: 7, IntervalHours: 24, NextRunAt: time.Now().Add(time.Hour)}}, true); code != 200 {
		t.Fatal("schedule", code)
	}
	if code, data := call(viewer, "GET", "/admin/suricata-automation.js", nil, false); code != 200 || !strings.Contains(string(data), "loadSuricataAutomation") {
		t.Fatal("static asset", code)
	}
	upload := func(sid int) map[string]any {
		return map[string]any{"action": "upload", "name": fmt.Sprint(sid), "engine_major": 7, "rules": fmt.Sprintf(`alert icmp any any -> any any (msg:"test"; sid:%d; rev:1;)`, sid)}
	}
	if code, _ := call(viewer, "POST", "/admin/api/suricata", upload(1), true); code != 403 {
		t.Fatal("viewer", code)
	}
	if code, _ := call(owner, "POST", "/admin/api/suricata", upload(1), false); code != 403 {
		t.Fatal("csrf", code)
	}
	var a, b rules.Manifest
	for i, v := range []*rules.Manifest{&a, &b} {
		code, data := call(owner, "POST", "/admin/api/suricata", upload(i+1), true)
		if code != 200 {
			t.Fatal(code, string(data))
		}
		_ = json.Unmarshal(data, v)
	}
	var catalog struct {
		PublicKey string `json:"public_key"`
	}
	code, data := call(viewer, "GET", "/admin/api/suricata", nil, false)
	if code != 200 {
		t.Fatal(code)
	}
	_ = json.Unmarshal(data, &catalog)
	if a.Verify(catalog.PublicKey) != nil {
		t.Fatal("invalid signature")
	}
	assign := func(id string, rev int64, rollback bool) int {
		code, _ := call(owner, "POST", "/admin/api/suricata", map[string]any{"action": "assign", "change": rules.Change{AgentID: creds.AgentID, BundleID: id, ExpectedRevision: rev, Rollback: rollback}}, true)
		return code
	}
	if c := assign(a.ID, 0, false); c != 200 {
		t.Fatal(c)
	}
	if c := assign(b.ID, 0, false); c != 409 {
		t.Fatal("CAS", c)
	}
	receiver := httptest.NewServer(ingest.NewHandler(s))
	defer receiver.Close()
	client, _ := ingest.NewClient(receiver.URL, creds, nil)
	defer client.Close()
	data, e = client.SuricataBundle(ctx, a)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = rules.Unpack(a, data); e != nil {
		t.Fatal(e)
	}
	if _, e = client.SuricataBundle(ctx, b); e == nil {
		t.Fatal("unassigned download")
	}
	h.ObservedAt = time.Now().UTC()
	h.Sensor.ObservedAt = h.ObservedAt
	h.Sensor.Rules = &rules.Status{Version: 1, EngineMajor: 7, Revision: 1, DesiredID: a.ID, AppliedID: a.ID, State: "applied", UpdatedAt: h.ObservedAt}
	receipt, e := client.Heartbeat(ctx, h)
	if e != nil || receipt.Suricata == nil || receipt.Suricata.Bundle.ID != a.ID {
		t.Fatal(receipt, e)
	}
	if c := assign(b.ID, 1, false); c != 200 {
		t.Fatal(c)
	}
	if c, _ := call(owner, "POST", "/admin/api/suricata", map[string]string{"action": "delete", "id": a.ID}, true); c != 409 {
		t.Fatal("deleted fallback", c)
	}
	if c := assign("", 2, true); c != 200 {
		t.Fatal("rollback", c)
	}
	p, _ := s.SuricataAssignment(ctx, creds.AgentID)
	if p.Bundle.ID != a.ID || p.Revision != 3 {
		t.Fatal(p)
	}
	acGroup := admin.WithPrincipal(ctx, admin.User{Username: "owner", Role: "administrator", Version: 1})
	groupID, e := s.GroupCommand(acGroup, jobs.GroupCommand{Action: "create", Name: "IDS group"}, time.Now())
	if e != nil {
		t.Fatal(e)
	}
	_, e = s.GroupCommand(acGroup, jobs.GroupCommand{Action: "members.add", GroupID: groupID, GroupVersion: 1, AgentIDs: []string{creds.AgentID}}, time.Now())
	if e != nil {
		t.Fatal(e)
	}
	if code, _ := call(owner, "POST", "/admin/api/suricata-automation", map[string]any{"action": "group", "group": rules.GroupChange{GroupPolicy: rules.GroupPolicy{GroupID: groupID, Enabled: true, EngineMajor: 7, Mode: "pinned", BundleID: a.ID}}}, true); code != 200 {
		t.Fatal("group API", code)
	}
	h.ObservedAt = time.Now().UTC()
	h.Sensor.ObservedAt = h.ObservedAt
	h.Sensor.Rules.UpdatedAt = h.ObservedAt
	receipt, e = client.Heartbeat(ctx, h)
	if e != nil || receipt.Suricata == nil || receipt.Suricata.GroupID != "" || receipt.Suricata.GroupRevision != 0 {
		t.Fatal("wire must remain compatible", receipt, e)
	}
	serverAssignment, _ := s.SuricataAssignment(ctx, creds.AgentID)
	if serverAssignment.GroupID != groupID {
		t.Fatal("missing persisted owner", serverAssignment)
	}
	if code, _ := call(owner, "POST", "/admin/api/suricata", map[string]any{"action": "download", "engine_major": 7}, true); code != 202 {
		t.Fatal("durable manual download", code)
	}
	feeds, e := s.SuricataFeeds(ctx)
	if e != nil || !feeds[0].Requested {
		t.Fatal(feeds, e)
	}
	// Revocation prevents package download even if the agent still knows the URL.
	ac := admin.WithPrincipal(ctx, admin.User{Username: "owner", Role: "administrator", Version: 1})
	if e = s.AdminCommand(ac, admin.Command{Action: "agent.revoke", AgentID: creds.AgentID}); e != nil {
		t.Fatal(e)
	}
	if _, e = client.SuricataBundle(ctx, a); e == nil {
		t.Fatal("revoked download")
	}
}
