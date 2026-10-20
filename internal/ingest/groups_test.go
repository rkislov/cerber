// SPDX-License-Identifier: Apache-2.0
package ingest_test

import (
	"encoding/json"
	"github.com/rkislov/cerber/internal/ingest"
	"github.com/rkislov/cerber/internal/jobs"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestGroupJobsKeepV1AgentWireAndReportOwnership(t *testing.T) {
	s, asset, c := setup(t)
	other := ingest.Credentials{AgentID: "other-agent", Token: strings.Repeat("b", 64)}
	if e := s.RegisterAgent(ctx, other.AgentID, asset, ingest.Hash([]byte(other.Token))); e != nil {
		t.Fatal(e)
	}
	now := time.Now().UTC()
	group, e := s.GroupCommand(ctx, jobs.GroupCommand{Action: "create", Name: "Fixture group"}, now)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.GroupCommand(ctx, jobs.GroupCommand{Action: "members.add", GroupID: group, GroupVersion: 1, AgentIDs: []string{c.AgentID, other.AgentID}}, now); e != nil {
		t.Fatal(e)
	}
	run, e := s.GroupCommand(ctx, jobs.GroupCommand{Action: "run", GroupID: group, GroupVersion: 2, Kind: "updates"}, now)
	if e != nil {
		t.Fatal(e)
	}
	server := httptest.NewServer(ingest.NewHandler(s))
	defer server.Close()
	r, _ := http.NewRequest("POST", server.URL+"/v1/agent/jobs/claim", strings.NewReader("{}"))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer "+c.Token)
	r.Header.Set("X-Cerber-Agent", c.AgentID)
	res, e := server.Client().Do(r)
	if e != nil {
		t.Fatal(e)
	}
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != 200 {
		t.Fatal(res.StatusCode, string(body))
	}
	var raw struct {
		Job map[string]json.RawMessage `json:"job"`
	}
	if e = json.Unmarshal(body, &raw); e != nil {
		t.Fatal(e)
	}
	if _, ok := raw.Job["group_run_id"]; ok {
		t.Fatal("new field breaks older strict v1 agent decoder")
	}
	var assigned struct {
		Job jobs.Job `json:"job"`
	}
	json.Unmarshal(body, &assigned)
	client, e := ingest.NewClient(server.URL, c, nil)
	if e != nil {
		t.Fatal(e)
	}
	defer client.Close()
	receipt, e := client.Send(ctx, report("linux"))
	if e != nil {
		t.Fatal(e)
	}
	if e = client.FinishJob(ctx, jobs.Result{JobID: assigned.Job.ID, Status: "partial", Code: "partial_coverage", ReportID: receipt.ReportID}); e != nil {
		t.Fatal(e)
	}
	second, e := ingest.NewClient(server.URL, other, nil)
	if e != nil {
		t.Fatal(e)
	}
	defer second.Close()
	job, e := second.ClaimJob(ctx)
	if e != nil || job == nil {
		t.Fatal(job, e)
	}
	if e = second.FinishJob(ctx, jobs.Result{JobID: job.ID, Status: "succeeded", Code: "complete", ReportID: receipt.ReportID}); e == nil {
		t.Fatal("accepted another agent's report")
	}
	if e = second.FinishJob(ctx, jobs.Result{JobID: job.ID, Status: "failed", Code: "collection_failed"}); e != nil {
		t.Fatal(e)
	}
	summary, e := s.AgentGroupRun(ctx, run)
	if e != nil || summary.Total != 2 || summary.Partial != 1 || summary.Failed != 1 || summary.State != "partial" {
		t.Fatal(summary, e)
	}
	members, e := s.GroupRunMembers(ctx, run, "", 101)
	if e != nil {
		t.Fatal(e)
	}
	for _, m := range members {
		if m.AgentID == c.AgentID && m.InventoryID != receipt.SnapshotID {
			t.Fatal("wrong report linked", m)
		}
	}
}
