// SPDX-License-Identifier: Apache-2.0
package patch

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"strings"
	"testing"
	"time"
)

func TestExecutorCrashRecoveryAndDurableReplay(t *testing.T) {
	db, e := sql.Open("sqlite", ":memory:")
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	_, e = db.Exec(`CREATE TABLE executions(id TEXT PRIMARY KEY,request TEXT NOT NULL,result TEXT)`)
	if e != nil {
		t.Fatal(e)
	}
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	q := request()
	ticket, _ := Sign(q, key)
	calls := 0
	execute := func(_ context.Context, q Request) Result {
		calls++
		r := Failure(q, "fixture")
		r.Status = "succeeded"
		r.Items[0].Status = "ready"
		return r
	}
	r, e := processTicket(context.Background(), db, pub, q.AgentID, q.Manager, ticket, execute, time.Now())
	if e != nil || r.Status != "succeeded" || calls != 1 {
		t.Fatal(r, e, calls)
	}
	r, e = processTicket(context.Background(), db, pub, q.AgentID, q.Manager, ticket, execute, time.Now().Add(2*time.Hour))
	if e != nil || r.Status != "succeeded" || calls != 1 {
		t.Fatal("replayed result", r, e, calls)
	}
	q.ID = strings.Repeat("b", 32)
	q.Mode = "install"
	ticket, _ = Sign(q, key)
	if _, e = db.Exec("INSERT INTO executions(id,request) VALUES(?,?)", q.ID, string(ticket.Payload)); e != nil {
		t.Fatal(e)
	}
	r, e = processTicket(context.Background(), db, pub, q.AgentID, q.Manager, ticket, execute, time.Now())
	if e != nil || r.Status != "unknown" || calls != 1 {
		t.Fatal("repeated interrupted mutation", r, e, calls)
	}
	q.ID = strings.Repeat("c", 32)
	ticket, _ = Sign(q, key)
	r, e = processTicket(context.Background(), db, pub, q.AgentID, q.Manager, ticket, execute, q.ExpiresAt)
	if e != nil || r.Status != "failed" || calls != 1 {
		t.Fatal("expired", r, e, calls)
	}
	if _, e = processTicket(context.Background(), db, pub, "other", q.Manager, ticket, execute, time.Now()); e == nil {
		t.Fatal("wrong agent")
	}
}
