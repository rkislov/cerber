package microsoft

import (
	"context"
	"fmt"
	"github.com/rkislov/cerber/internal/inventory"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestNumericVersions(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		want int
	}{{"10.0.9.0", "10.0.10.0", -1}, {"2.1", "2.1.0.0", 0}, {"155.0.1.20", "154.99.99.99", 1}} {
		got, err := CompareVersion(tc.a, tc.b)
		if err != nil || got != tc.want {
			t.Fatal(tc, got, err)
		}
	}
	for _, bad := range []string{"", "1.2-beta", "1.2.3.4.5", "1. 2", "4294967296.0", "1.-2"} {
		if _, err := CompareVersion(bad, "1.0"); err == nil {
			t.Fatal(bad)
		}
	}
}
func TestSelectsArchitectureChannelAndParsesMicrosoftDates(t *testing.T) {
	date := time.Now().Add(-time.Hour).UTC().Format("2006-01-02T15:04:05")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `[{"Product":"Stable","Releases":[{"Platform":"Windows","Architecture":"x64","ProductVersion":"10.0.10.0","PublishedTime":%q},{"Platform":"Windows","Architecture":"arm64","ProductVersion":"99.0.0.0","PublishedTime":%q},{"Platform":"Linux","Architecture":"x64","ProductVersion":"999.0.0.0","PublishedTime":%q}]}]`, date, date, date)
	}))
	defer server.Close()
	client := EdgeClient{endpoint: server.URL}
	result, err := client.Check(context.Background(), inventory.Component{ID: "edge", Version: "10.0.9.0"}, "Stable", "x64")
	if err != nil || result.Status != "update_available" || result.AvailableVersion != "10.0.10.0" || result.SourcePublishedAt != date {
		t.Fatal(result, err)
	}
	result, err = client.Check(context.Background(), inventory.Component{ID: "edge", Version: "unknown"}, "Stable", "x64")
	if err != nil || result.Status != "unknown" {
		t.Fatal(result, err)
	}
	if _, err = client.Check(context.Background(), inventory.Component{}, "Canary", "x64"); err == nil {
		t.Fatal("unsupported channel accepted")
	}
}
func TestRejectsRedirectsAndMalformedMetadata(t *testing.T) {
	for _, body := range []string{`not json`, `[]`, `[{"Product":"Stable","Releases":[{"Platform":"Windows","Architecture":"x64","ProductVersion":"bad","PublishedTime":"2026-01-01T00:00:00Z"}]}]`} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, body) }))
		_, err := (EdgeClient{endpoint: server.URL}).Check(context.Background(), inventory.Component{Version: "1.0"}, "Stable", "x64")
		server.Close()
		if err == nil {
			t.Fatal("bad metadata accepted")
		}
	}
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("followed redirect") }))
	defer target.Close()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, target.URL, 302) }))
	defer server.Close()
	if _, err := (EdgeClient{endpoint: server.URL}).Check(context.Background(), inventory.Component{}, "Stable", "x64"); err == nil {
		t.Fatal("redirect accepted")
	}
}
