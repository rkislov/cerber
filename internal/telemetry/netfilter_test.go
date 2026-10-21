// SPDX-License-Identifier: Apache-2.0
package telemetry

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"
)

func TestNetfilterTrustedTransport(t *testing.T) {
	now := time.Now().UTC()
	for _, v := range []struct {
		prefix, transport string
		match             bool
	}{{"[UFW BLOCK] ", "kernel", true}, {"CERBER_IPT_DROP ", "kernel", true}, {"CERBER_NFT_DROP ", "kernel", true}, {"[UFW BLOCK] ", "syslog", false}, {"arbitrary LOG ", "kernel", false}} {
		data, _ := json.Marshal(map[string]string{"MESSAGE": v.prefix + "IN=eth0 OUT= SRC=192.0.2.3 DST=192.0.2.4 PROTO=TCP SPT=12000 DPT=443", "_TRANSPORT": v.transport, "_HOSTNAME": "fw", "__REALTIME_TIMESTAMP": fmt.Sprint(now.UnixMicro())})
		n := Normalize(RawRecord{ReceivedAt: now, Raw: Raw{Source: "journald", ObservedAt: now, Data: data}})
		if (n.Class == "firewall") != v.match {
			t.Fatalf("%+v -> %+v", v, n)
		}
		if v.match && (n.SourceIP != "192.0.2.3" || n.DestinationPort != 443 || n.Action != "deny") {
			t.Fatal(n)
		}
	}
}
