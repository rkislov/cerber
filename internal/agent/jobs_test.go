// SPDX-License-Identifier: Apache-2.0
package agent

import (
	"github.com/rkislov/cerber/internal/inventory"
	"github.com/rkislov/cerber/internal/jobs"
	"testing"
)

func TestJobOutcomeNeverTreatsMissingCoverageAsSuccess(t *testing.T) {
	s := inventory.Snapshot{Coverage: []inventory.Coverage{{Section: "os", Status: "complete"}, {Section: "packages", Status: "complete"}, {Section: "applications", Status: "unsupported"}, {Section: "updates_available", Status: "not_requested"}}}
	if r := JobResult(jobs.Job{ID: "job", Kind: "inventory"}, s, "report"); r.Status != "succeeded" {
		t.Fatal(r)
	}
	if r := JobResult(jobs.Job{ID: "job", Kind: "updates"}, s, "report"); r.Status != "partial" {
		t.Fatal("unchecked updates accepted", r)
	}
	s.Coverage[3].Status = "complete"
	if r := JobResult(jobs.Job{ID: "job", Kind: "updates"}, s, "report"); r.Status != "succeeded" {
		t.Fatal(r)
	}
	s.Coverage[1].Status = "partial"
	if r := JobResult(jobs.Job{ID: "job", Kind: "inventory"}, s, "report"); r.Status != "partial" {
		t.Fatal("partial inventory accepted", r)
	}
	if r := JobResult(jobs.Job{ID: "job", Kind: "inventory"}, inventory.Snapshot{}, "report"); r.Status != "partial" {
		t.Fatal("missing coverage accepted", r)
	}
}
