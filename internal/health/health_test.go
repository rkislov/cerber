// SPDX-License-Identifier: Apache-2.0
package health

import (
	"context"
	"database/sql"
	_ "modernc.org/sqlite"
	"testing"
)

func TestDatabaseAvailabilityAndClosedDatabase(t *testing.T) {
	db, e := sql.Open("sqlite", ":memory:")
	if e != nil {
		t.Fatal(e)
	}
	if _, e = db.Exec("PRAGMA user_version=11"); e != nil {
		t.Fatal(e)
	}
	v := CheckDB(context.Background(), db, "control", ":memory:")
	if v.Status != "ok" || v.Schema != 11 {
		t.Fatal(v)
	}
	db.Close()
	if CheckDB(context.Background(), db, "control", ":memory:").Status != "unavailable" {
		t.Fatal("closed database reported healthy")
	}
}
func TestSnapshotCachesIndependentProbeResults(t *testing.T) {
	calls := 0
	read := New(t.TempDir(), func(context.Context) Database { calls++; return Database{Name: "control", Status: "ok"} }, func(context.Context) Database { return Database{Name: "events", Status: "unavailable"} })
	a := read(context.Background())
	b := read(context.Background())
	if calls != 1 || !a.At.Equal(b.At) || len(a.Databases) != 2 || a.Databases[1].Status != "unavailable" {
		t.Fatal(a, b, calls)
	}
}
