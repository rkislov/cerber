// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/rkislov/cerber/internal/agent"
	"github.com/rkislov/cerber/internal/ingest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestConfigCLIValidationAndExclusiveArguments(t *testing.T) {
	root := t.TempDir()
	credentials := filepath.Join(root, "credentials.json")
	token := strings.Repeat("b", 64)
	data, _ := json.Marshal(ingest.Credentials{AgentID: "agent", Token: token})
	os.WriteFile(credentials, data, 0600)
	config := agent.Config{SchemaVersion: 1, Database: filepath.Join(root, "unopened.db"), AssetID: "local", Credentials: credentials, Server: "https://siem.example", Interval: "1h"}
	file := filepath.Join(root, "agent.json")
	data, _ = json.Marshal(config)
	os.WriteFile(file, data, 0600)
	var out, diagnostics bytes.Buffer
	if err := run(context.Background(), []string{"agent", "validate-config", "-config", file}, &out, &diagnostics); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(out.Bytes(), []byte(token)) || !strings.Contains(out.String(), `"valid":true`) {
		t.Fatal(out.String())
	}
	if _, err := os.Stat(config.Database); !os.IsNotExist(err) {
		t.Fatal("validation touched database", err)
	}
	for _, args := range [][]string{{"-db", config.Database, "agent", "run", "-config", file}, {"agent", "run", "-config", file, "-asset", "override"}} {
		if err := run(context.Background(), args, &out, &diagnostics); err == nil {
			t.Fatal("accepted ambiguous config overrides", args)
		}
	}
	if _, err := os.Stat(config.Database); !os.IsNotExist(err) {
		t.Fatal("rejected invocation touched database", err)
	}
}
