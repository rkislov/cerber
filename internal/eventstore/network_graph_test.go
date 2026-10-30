package eventstore

import (
	"context"
	"github.com/rkislov/cerber/internal/telemetry"
	"testing"
	"time"
)

func TestNetworkContextHonorsProcessExit(t *testing.T) {
	s := storageFixture(t)
	at := time.Now().UTC().Add(-time.Minute)
	f := map[string]string{"ProcessID": "42", "Application": "test.exe", "Direction": "%%14593", "SourceAddress": "192.0.2.1", "DestAddress": "192.0.2.2", "SourcePort": "12345", "DestPort": "445", "Protocol": "6"}
	good := chainEvent(t, s, "host", "asset", at.Add(time.Second), 5156, f)
	chainEvent(t, s, "host", "asset", at.Add(2*time.Second), 4689, map[string]string{"ProcessId": "0x2a"})
	chainEvent(t, s, "host", "asset", at.Add(3*time.Second), 5156, f)
	c := telemetry.EventChain{Steps: []telemetry.ChainStep{{EventID: "process", AgentID: "host", AssetID: "asset", At: at, Code: "4688", Action: "process_created", Identity: telemetry.Identity{LocalSession: "0x123"}, WindowsActivity: &telemetry.WindowsActivity{ProcessID: "0x2a", Process: "test.exe"}}}}
	tx, e := s.db.BeginTx(context.Background(), nil)
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Rollback()
	e = networkContext(context.Background(), tx, &c, func(telemetry.Normalized) (bool, error) { return true, nil })
	if e != nil || len(c.Steps) != 2 || c.Steps[1].EventID != good {
		t.Fatal(c, e)
	}
}
func TestNetworkTupleIsDirectionalAndHostScoped(t *testing.T) {
	a := telemetry.ChainStep{Code: "5156", AgentID: "a", AssetID: "a", At: time.Now(), WindowsActivity: &telemetry.WindowsActivity{Direction: "%%14593", Protocol: "6", SourceAddress: "192.0.2.1", DestinationAddress: "192.0.2.2", SourcePort: "1234", DestinationPort: "445"}}
	b := a
	b.AgentID = "b"
	b.AssetID = "b"
	w := *a.WindowsActivity
	b.WindowsActivity = &w
	w.Direction = "%%14592"
	if !networkTupleMatch(a, b) {
		t.Fatal("matching TCP flow lost")
	}
	w.SourcePort = "9999"
	if networkTupleMatch(a, b) {
		t.Fatal("ports ignored")
	}
	w.SourcePort = "1234"
	b.At = b.At.Add(time.Minute)
	if networkTupleMatch(a, b) {
		t.Fatal("time ignored")
	}
}
