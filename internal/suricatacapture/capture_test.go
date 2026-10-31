// SPDX-License-Identifier: Apache-2.0
package suricatacapture

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPassiveRenderAndLocalConfig(t *testing.T) {
	dir := t.TempDir()
	c := Runtime{Config: Config{Interface: "eth1", Mode: "span", EVEPath: filepath.Join(dir, "eve", "eve.json")}, YAML: filepath.Join(dir, "config", "suricata.yaml"), Template: filepath.Join(dir, "base.yaml"), RulesDirectory: filepath.Join(dir, "rules")}
	base := "%YAML 1.1\n---\nvars:\n  address-groups:\n    HOME_NET: any\noutputs:\n - fast:\n    enabled: yes\naf-packet:\n - interface: eth0\n   copy-mode: ips\nstream:\n  inline: auto\nrule-files:\n - unmanaged.rules\nlogging:\n  outputs: []\n"
	s, e := c.Render(base)
	if e != nil {
		t.Fatal(e)
	}
	for _, bad := range []string{"copy-mode", "unmanaged.rules", "inline: auto", "fast:", "interface: eth0"} {
		if strings.Contains(s, bad) {
			t.Fatal("unsafe inherited config", bad)
		}
	}
	for _, required := range []string{"community-id: true", "payload: no", "inline: no", "active.rules", "suricata.socket", "filemode: 660", "types:\n        - alert:"} {
		if !strings.Contains(s, required) {
			t.Fatal(required)
		}
	}
	if _, e = c.Render(base + "outputs: []\n"); e == nil {
		t.Fatal("duplicate section accepted")
	}
	for _, iface := range []string{"lo", "any", "eth0;id", "../../x", "eth0\n"} {
		bad := c
		bad.Interface = iface
		if iface == "any" {
			continue
		}
		if bad.Validate() == nil {
			t.Fatal(iface)
		}
	}
	c.Mode = "test"
	if c.Validate() == nil {
		t.Fatal("test interface must be fixed")
	}
	c.Interface = "cerber-span"
	if c.Validate() != nil {
		t.Fatal(c)
	}
}
func TestProbeReportsPacketsDropsAndMissingInterface(t *testing.T) {
	c := Config{Interface: "eth1", Mode: "tap", EVEPath: filepath.Join(t.TempDir(), "eve.json")}
	os.WriteFile(c.EVEPath, []byte("{}\n"), 0600)
	replies := map[string]string{"version": `"7.0.3 RELEASE"`, "uptime": `20`, "capture-mode": `"AF_PACKET_DEV"`, "iface-list": `{"ifaces":["eth1"]}`, "iface-stat": `{"pkts":120,"drop":3,"invalid-checksums":2}`}
	command := func(_ context.Context, name string, args map[string]string) (json.RawMessage, error) {
		if name == "iface-stat" && args["iface"] != "eth1" {
			t.Fatal(args)
		}
		return json.RawMessage(replies[name]), nil
	}
	s := Probe(context.Background(), c, command)
	if s.Validate() != nil || s.State != "receiving" || s.Packets != 120 || s.Dropped != 3 || s.EVEBytes != 3 {
		t.Fatal(s)
	}
	replies["iface-list"] = `{"ifaces":["eth2"]}`
	s = Probe(context.Background(), c, command)
	if s.State != "unavailable" || s.Error == "" {
		t.Fatal(s)
	}
	replies["iface-list"] = `{"ifaces":["eth1"]}`
	replies["iface-stat"] = `{"pkts":-1}`
	if Probe(context.Background(), c, command).State != "unavailable" {
		t.Fatal("invalid counter accepted")
	}
}
