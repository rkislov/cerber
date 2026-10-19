package windows

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/rkislov/cerber/internal/inventory"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestCollectorOptionsAndPartialResults(t *testing.T) {
	c := Collector{CheckAvailable: true, Runner: func(ctx context.Context, source string) ([]byte, error) {
		if !strings.HasPrefix(source, "$CheckAvailable = $true") || strings.Contains(source, "Get-CimInstance Win32_Product") {
			t.Fatal("unsafe collector script")
		}
		return json.Marshal(inventory.Snapshot{ID: "pending", AssetID: "pending", SchemaVersion: 1, Collector: "windows-test", CollectedAt: time.Now().UTC(), Coverage: []inventory.Coverage{{Section: "os", Status: "error", Detail: "access denied"}}})
	}}
	snapshot, err := c.Collect(context.Background())
	if err != nil || snapshot.CoverageStatus("os") != "error" {
		t.Fatal(snapshot, err)
	}
	c.Runner = func(ctx context.Context, _ string) ([]byte, error) { <-ctx.Done(); return nil, ctx.Err() }
	c.Timeout = time.Millisecond
	if _, err = c.Collect(context.Background()); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
}
func TestPowerShellSyntaxOnWindows(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("PowerShell AST check requires Windows")
	}
	// Parse only: do not execute inventory queries or contact Windows Update in CI.
	path, err := exec.LookPath("powershell.exe")
	if err != nil {
		t.Fatal(err)
	}
	absolute, err := filepath.Abs("inventory.ps1")
	if err != nil {
		t.Fatal(err)
	}
	source := `$errors=$null; $tokens=$null; [void][System.Management.Automation.Language.Parser]::ParseFile($args[0],[ref]$tokens,[ref]$errors); if($errors.Count -gt 0) { $errors | Out-String | Write-Error; exit 1 }`
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	// -Command positional handling is avoided by passing the path through a dedicated environment variable.
	cmd := exec.CommandContext(ctx, path, "-NoProfile", "-NonInteractive", "-Command", strings.Replace(source, "$args[0]", "$env:CERBER_TEST_SCRIPT_PATH", 1))
	cmd.Env = append(cmd.Environ(), "CERBER_TEST_SCRIPT_PATH="+absolute)
	if data, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("PowerShell syntax: %v %s", err, data)
	}
}
