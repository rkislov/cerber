// SPDX-License-Identifier: Apache-2.0
package endpoint

import (
	"context"
	"github.com/rkislov/cerber/internal/vuln"
	"testing"
	"time"
)

func TestAssessmentHistoryPreservesTransitionsNotPolls(t *testing.T) {
	s, _ := fixture(t)
	ctx := context.Background()
	m := vuln.Match{Record: vuln.Record{ID: "CVE-2024-6387"}, CPE: "fixture"}
	a := vuln.PackageAssessment{Status: "affected", SnapshotID: "first", CheckedAt: time.Now(), Rule: "ubuntu-osv-package/1"}
	save := func() {
		t.Helper()
		if e := s.saveAssessment(ctx, "plan:192.0.2.1", m, a); e != nil {
			t.Fatal(e)
		}
	}
	save()
	a.CheckedAt = time.Now()
	a.SnapshotID = "second"
	save()
	a.Status = "fixed"
	save()
	rows, e := s.AssessmentHistory(ctx, "plan:192.0.2.1", "")
	if e != nil || len(rows) != 2 || rows[0].Assessment.Status != "fixed" || rows[1].Assessment.SnapshotID != "first" {
		t.Fatal(rows, e)
	}
	rows, e = s.AssessmentHistory(ctx, "other:192.0.2.1", "")
	if e != nil || len(rows) != 0 {
		t.Fatal(rows, e)
	}
}
