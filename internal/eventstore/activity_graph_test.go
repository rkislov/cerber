package eventstore

import (
	"context"
	"github.com/rkislov/cerber/internal/telemetry"
	"testing"
	"time"
)

func TestActivityContextRequiresHostSIDAndSession(t *testing.T) {
	s := storageFixture(t)
	at := time.Now().UTC().Add(-time.Minute)
	fields := map[string]string{"SubjectUserName": "Alice", "SubjectDomainName": "LAB", "SubjectUserSid": chainSID, "SubjectLogonId": "0x123", "NewProcessName": "test.exe"}
	good := chainEvent(t, s, "host", "asset", at.Add(time.Second), 4688, fields)
	chainEvent(t, s, "other", "asset", at.Add(2*time.Second), 4688, fields)
	fields["SubjectLogonId"] = "0x124"
	chainEvent(t, s, "host", "asset", at.Add(3*time.Second), 4688, fields)
	c := telemetry.EventChain{Steps: []telemetry.ChainStep{{EventID: "anchor", AgentID: "host", AssetID: "asset", At: at, Action: "logon", Identity: telemetry.Identity{AccountKey: "windows-sid:" + chainSID, LocalSession: "0x123"}}}}
	tx, e := s.db.BeginTx(context.Background(), nil)
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Rollback()
	_, e = activityContext(context.Background(), tx, &c)
	if e != nil || len(c.Steps) != 2 || c.Steps[1].EventID != good || len(c.Links) != 1 {
		t.Fatal(c, e)
	}
}
