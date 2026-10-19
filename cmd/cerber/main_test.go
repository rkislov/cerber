package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"path/filepath"
	"strconv"
	"testing"
)

func TestCLIWorkflow(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cerber.db")
	call := func(args ...string) map[string]any {
		t.Helper()
		var out, errOut bytes.Buffer
		if err := run(context.Background(), append([]string{"-db", path}, args...), &out, &errOut); err != nil {
			t.Fatalf("%v: %v %s", args, err, errOut.String())
		}
		var result map[string]any
		if err := json.Unmarshal(out.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		return result
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	asset := call("asset", "add", "-ip", "127.0.0.1")
	target := call("target", "add", "-name", "local", "-assets", asset["id"].(string))
	task := call("task", "create", "-target", target["id"].(string), "-ports", strconv.Itoa(ln.Addr().(*net.TCPAddr).Port))
	result := call("task", "run", "-id", task["id"].(string))
	if result["task"].(map[string]any)["status"] != "completed" {
		t.Fatal(result)
	}
	if len(result["observations"].([]any)) != 1 {
		t.Fatal(result)
	}
}
func TestBadPorts(t *testing.T) {
	for _, value := range []string{"", "0", "65536", "-1", "22,,80", "22-80"} {
		if _, err := parsePorts(value); err == nil {
			t.Fatalf("accepted %q", value)
		}
	}
}
