// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"github.com/rkislov/cerber/internal/admin"
	"github.com/rkislov/cerber/internal/app"
	"github.com/rkislov/cerber/internal/ingest"
	"github.com/rkislov/cerber/internal/storage/sqlite"
	"github.com/rkislov/cerber/internal/suricatacapture"
	"os"
	"path/filepath"
)

func must(e error) {
	if e != nil {
		panic(e)
	}
}
func write(path string, v any) {
	b, e := json.MarshalIndent(v, "", "  ")
	must(e)
	must(os.WriteFile(path, b, 0600))
}
func random() string {
	b := make([]byte, 32)
	_, e := rand.Read(b)
	must(e)
	return hex.EncodeToString(b)
}
func main() {
	root := "/lab"
	ctx := context.Background()
	if len(os.Args) > 1 && os.Args[1] == "render" {
		b, e := os.ReadFile("/etc/suricata/suricata.yaml")
		must(e)
		r := suricatacapture.Runtime{Config: suricatacapture.Config{Mode: "test", Interface: "cerber-span", EVEPath: "/lab/eve/eve.json"}, RulesDirectory: "/lab/rules", YAML: "/lab/state/suricata.yaml", Template: "/etc/suricata/suricata.yaml"}
		text, e := r.Render(string(b))
		must(e)
		must(os.WriteFile("/lab/state/suricata.yaml", []byte(text), 0600))
		return
	}
	for _, d := range []string{"state", "eve", "evidence"} {
		must(os.MkdirAll(filepath.Join(root, d), 0700))
	}
	s, e := sqlite.Open(ctx, filepath.Join(root, "state/control.db"))
	must(e)
	defer s.Close()
	password := random()
	hash, e := admin.HashPassword(password)
	must(e)
	must(s.AdminCommand(ctx, admin.Command{Action: "user.create", Username: "lab", Role: "administrator", PasswordHash: hash}))
	write(root+"/state/admin-login.json", map[string]string{"username": "lab", "password": password})
	a, e := (app.Service{Repo: s}).AddAsset(ctx, "192.0.2.30", "ТЕСТ · изолированный нагрузочный стенд")
	must(e)
	cred := ingest.Credentials{AgentID: "loadlab-sensor", Token: random()}
	must(s.RegisterAgent(ctx, cred.AgentID, a.ID, ingest.Hash([]byte(cred.Token))))
	write(root+"/state/credentials.json", cred)
	write(root+"/state/sensor.json", map[string]any{"schema_version": 1, "server": "http://127.0.0.1:18791", "credentials": "/lab/state/credentials.json", "spool": "/lab/state/queue.db", "inputs": []map[string]any{{"id": "pcap-eve", "format": "suricata", "protocol": "file", "path": "/lab/eve/eve.json"}}})
}
