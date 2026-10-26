package ingest

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"
)

type testRoundTrip func(*http.Request) (*http.Response, error)

func (f testRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestAgentGatewayBackpressure(t *testing.T) {
	calls := 0
	tr := &agentTransport{base: testRoundTrip(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.UserAgent() != "Cerber-Agent/1" || r.Header.Get("Accept") != "application/json" || r.Header.Get("Authorization") != "Bearer fixture" {
			t.Fatal("machine identity/auth missing")
		}
		return &http.Response{StatusCode: 429, Header: http.Header{}}, nil
	})}
	req, _ := http.NewRequest("POST", "https://example.test/v1/agent/events", nil)
	req.Header.Set("Authorization", "Bearer fixture")
	if _, e := tr.RoundTrip(req); e != nil {
		t.Fatal(e)
	}
	if time.Until(tr.next) < 69*time.Second {
		t.Fatal("gateway cooldown must outlast a 60s idle window")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := tr.RoundTrip(req.WithContext(ctx)); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
	if calls != 1 {
		t.Fatal("request replayed during cooldown")
	}
	if req.Header.Get("User-Agent") != "" {
		t.Fatal("caller headers mutated")
	}
}
