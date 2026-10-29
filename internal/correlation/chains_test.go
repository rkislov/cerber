// SPDX-License-Identifier: Apache-2.0
package correlation

import (
	"github.com/rkislov/cerber/internal/telemetry"
	"testing"
	"time"
)

func chainN(agent, asset, key string, seq int64) telemetry.Normalized {
	return telemetry.Normalized{ID: telemetry.ID(agent, asset, key), AgentID: agent, AssetID: asset, Sequence: seq, EventTime: time.Unix(1700000000+seq, 0), ReceivedAt: time.Unix(1700000000+seq, 0), Status: "parsed", Class: "authentication", Action: "logon", Outcome: "success", User: "root", SourceIP: "192.0.2.1", Identity: &telemetry.Identity{SSHKey: key}}
}
func TestSSHChainDoesNotCountNamesAddressesOrDuplicateAssets(t *testing.T) {
	a := chainN("a", "asset-a", "SHA256:first", 1)
	b := chainN("b", "asset-b", "SHA256:first", 2)
	c := chainN("c", "asset-c", "SHA256:first", 3)
	d := Chain("chain.ssh_key_hosts", c, []telemetry.Normalized{a, b, c}, 3, false)
	if d == nil || d.Chain.Hosts != 3 || len(d.Chain.Links) != 2 {
		t.Fatal(d)
	}
	b.Identity = &telemetry.Identity{SSHKey: "SHA256:other"}
	if Chain("chain.ssh_key_hosts", c, []telemetry.Normalized{a, b, c}, 3, false) != nil {
		t.Fatal("names and IPs joined")
	}
	b.Identity = a.Identity
	b.AssetID = a.AssetID
	if Chain("chain.ssh_key_hosts", c, []telemetry.Normalized{a, b, c}, 3, false) != nil {
		t.Fatal("same asset counted twice")
	}
	b.AssetID = "asset-b"
	b.Sequence = 99
	if Chain("chain.ssh_key_hosts", c, []telemetry.Normalized{a, b, c}, 3, false) != nil {
		t.Fatal("future sequence used")
	}
}
func TestGUIDNeedsSameDomainIdentityAndNonzeroGUID(t *testing.T) {
	a := chainN("a", "asset-a", "", 1)
	a.Identity = &telemetry.Identity{AccountKey: "windows-sid:one", SessionGUID: "guid-one", LogonType: 3}
	b := chainN("b", "asset-b", "", 2)
	b.Identity = &telemetry.Identity{AccountKey: "windows-sid:two", SessionGUID: "guid-one", LocalSession: "0x123", LogonType: 3}
	if Chain("chain.logon_guid_hosts", b, []telemetry.Normalized{a, b}, 2, false) != nil {
		t.Fatal("different SID joined by GUID")
	}
	b.Identity.AccountKey = a.Identity.AccountKey
	b.Identity.SessionGUID = "guid-two"
	if Chain("chain.logon_guid_hosts", b, []telemetry.Normalized{a, b}, 2, false) != nil {
		t.Fatal("different GUID joined")
	}
	b.Identity.SessionGUID = a.Identity.SessionGUID
	if Chain("chain.logon_guid_hosts", b, []telemetry.Normalized{a, b}, 2, false) == nil {
		t.Fatal("same identity missing")
	}
	b.Identity.SessionGUID = ""
	if Chain("chain.logon_guid_hosts", b, []telemetry.Normalized{a, b}, 2, false) != nil {
		t.Fatal("empty GUID joined")
	}
}
