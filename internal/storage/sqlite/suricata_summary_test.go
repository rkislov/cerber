package sqlite

import (
	"testing"
	"time"
)

func TestSuricataSummaryCountsOnlyLatestAndSeparatesStaleSensors(t *testing.T) {
	f := newRolloutFixture(t)
	publishFeed(t, f.s, f.ctx, autoBundle(t, 9000, "et-open"))
	publishFeed(t, f.s, f.ctx, autoBundle(t, 9001, "et-open"))
	v, e := f.s.SuricataSummary(f.ctx, f.now)
	if e != nil || v.Latest == nil || v.Latest.Count != 1 || len(v.Applied) != 1 || v.Applied[0].Count != 1 || v.Applied[0].Sensors != 2 || v.Applied[0].FreshSensors != 2 {
		t.Fatal(v, e)
	}
	v, e = f.s.SuricataSummary(f.ctx, f.now.Add(4*time.Minute))
	if e != nil || v.Applied[0].FreshSensors != 0 || v.Applied[0].Sensors != 2 {
		t.Fatal(v, e)
	}
}
