// SPDX-License-Identifier: Apache-2.0
package eventcollector

import (
	"context"
	"github.com/rkislov/cerber/internal/telemetry"
	"os"
	"runtime"
	"testing"
)

func TestNativeEventRead(t *testing.T) {
	if os.Getenv("CERBER_NATIVE_SMOKE") != "1" {
		t.Skip("native CI only")
	}
	source := "journald"
	if runtime.GOOS == "windows" {
		source = "windows:System"
	} else if runtime.GOOS != "linux" {
		t.Skip("requires Linux or Windows")
	}
	n := Native{Source: source}
	records, e := n.Read(context.Background(), "")
	if e != nil {
		t.Fatal(e)
	}
	if len(records) == 0 {
		t.Fatal("expected native fixture system events")
	}
	b := telemetry.Batch{SchemaVersion: 1, ID: telemetry.ID("native-batch"), AgentID: "native-fixture", Records: records}
	if e = b.Validate(); e != nil {
		t.Fatal(e)
	}
	if _, e = n.Read(context.Background(), records[len(records)-1].Cursor); e != nil {
		t.Fatal("incremental cursor", e)
	}
}
