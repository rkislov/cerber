package inventory

import (
	"testing"
	"time"
)

func snap() Snapshot {
	return Snapshot{SchemaVersion: 1, ID: "s", AssetID: "a", Collector: "test/1", CollectedAt: time.Now().UTC(), Coverage: []Coverage{{Section: "applications", Status: "complete"}}, Components: []Component{{ID: "app", Kind: "application", Name: "App", Version: "1.0", Source: "test"}}, Updates: []Update{}}
}
func TestDiffDoesNotInferRemovalFromPartialCollection(t *testing.T) {
	before := snap()
	after := snap()
	after.CollectedAt = before.CollectedAt.Add(time.Second)
	after.Components = nil
	after.Coverage = []Coverage{{Section: "applications", Status: "partial"}}
	got, err := Diff(before, after)
	if err != nil || len(got) != 0 {
		t.Fatal(got, err)
	}
	after.Coverage[0].Status = "complete"
	got, err = Diff(before, after)
	if err != nil || len(got) != 1 || got[0].Type != "removed" {
		t.Fatal(got, err)
	}
}
func TestDiffVersionAndUnknownBaseline(t *testing.T) {
	before := snap()
	after := snap()
	after.CollectedAt = before.CollectedAt.Add(time.Second)
	after.Components[0].Version = "2.0"
	got, err := Diff(before, after)
	if err != nil || len(got) != 1 || got[0].Type != "changed" {
		t.Fatal(got, err)
	}
	before.Components = nil
	before.Coverage[0].Status = "partial"
	got, err = Diff(before, after)
	if err != nil || got[0].Type != "observed" {
		t.Fatal(got, err)
	}
	after.AssetID = "other"
	if _, err := Diff(before, after); err == nil {
		t.Fatal("cross-asset diff accepted")
	}
}
func TestValidationRejectsMissingCoverageAndDuplicateIdentities(t *testing.T) {
	value := snap()
	if err := value.Validate(); err != nil {
		t.Fatal(err)
	}
	value.Components = append(value.Components, value.Components[0])
	if err := value.Validate(); err == nil {
		t.Fatal("duplicate accepted")
	}
	value = snap()
	value.Coverage = nil
	if err := value.Validate(); err == nil {
		t.Fatal("missing coverage accepted")
	}
}
