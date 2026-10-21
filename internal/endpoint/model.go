// SPDX-License-Identifier: Apache-2.0
package endpoint

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"github.com/rkislov/cerber/internal/integrations"
	"net/netip"
	"strings"
	"time"
)

var ErrInvalid = errors.New("invalid endpoint command")

type Policy struct {
	ID                  string   `json:"id"`
	Name                string   `json:"name"`
	Class               string   `json:"class"`
	Version             int64    `json:"version"`
	Mode                string   `json:"mode"`
	Scan                bool     `json:"scan"`
	ScanIntervalMinutes int      `json:"scan_interval_minutes"`
	ScanHourUTC         int      `json:"scan_hour_utc"`
	SyncMinutes         int      `json:"sync_minutes"`
	Exclude             []string `json:"exclude"`
	Protected           []string `json:"protected"`
	Agents              []string `json:"agents"`
	GroupID             string   `json:"group_id,omitempty"`
}

func (p Policy) Validate() error {
	if p.Name == "" || len(p.Name) > 120 || p.Class != "server" && p.Class != "workstation" && p.Class != "mobile" || p.Mode != "off" && p.Mode != "learning" && p.Mode != "confirm" || p.ScanIntervalMinutes < 60 || p.ScanIntervalMinutes > 43200 || p.ScanHourUTC < 0 || p.ScanHourUTC > 23 || p.SyncMinutes < 5 || p.SyncMinutes > 1440 || len(p.Exclude) > 100 || len(p.Protected) > 100 || len(p.Agents) > 1000 {
		return ErrInvalid
	}
	if p.Class == "mobile" && (p.Scan || p.Mode != "off") {
		return ErrInvalid
	}
	for _, path := range p.Exclude {
		if len(path) > 4096 || strings.ContainsAny(path, "\x00\r\n") || !(strings.HasPrefix(path, "/") || len(path) > 2 && path[1] == ':' && (path[2] == '\\' || path[2] == '/')) {
			return ErrInvalid
		}
	}
	for _, a := range p.Protected {
		if _, e := netip.ParseAddr(a); e != nil {
			if _, e = netip.ParsePrefix(a); e != nil {
				return ErrInvalid
			}
		}
	}
	return nil
}

type Block struct {
	ID      string    `json:"id"`
	Agent   string    `json:"agent"`
	IP      string    `json:"ip"`
	Created time.Time `json:"created"`
	Expires time.Time `json:"expires"`
	Actor   string    `json:"actor"`
	Reason  string    `json:"reason"`
	State   string    `json:"state"`
}
type Finding struct {
	ID     string    `json:"id"`
	Path   string    `json:"path"`
	SHA256 string    `json:"sha256"`
	MD5    string    `json:"md5"`
	IOC    string    `json:"ioc"`
	At     time.Time `json:"at"`
}
type Report struct {
	WantFeed      bool              `json:"want_feed"`
	PolicyVersion int64             `json:"policy_version"`
	FeedVersion   string            `json:"feed_version"`
	At            time.Time         `json:"at"`
	Scanned       int               `json:"scanned"`
	Skipped       int               `json:"skipped"`
	ScanState     string            `json:"scan_state"`
	Error         string            `json:"error"`
	Blocks        map[string]string `json:"blocks"`
	Findings      []Finding         `json:"findings"`
}
type Bundle struct {
	Agent       string             `json:"agent"`
	Issued      time.Time          `json:"issued"`
	Expires     time.Time          `json:"expires"`
	Policy      Policy             `json:"policy"`
	Blocks      []Block            `json:"blocks"`
	FeedVersion string             `json:"feed_version"`
	IOCs        []integrations.IOC `json:"iocs,omitempty"`
}
type Signed struct {
	Payload   json.RawMessage `json:"payload"`
	Signature []byte          `json:"signature"`
}

func Sign(b Bundle, key ed25519.PrivateKey) (Signed, error) {
	p, e := json.Marshal(b)
	if e != nil {
		return Signed{}, e
	}
	return Signed{Payload: p, Signature: ed25519.Sign(key, append([]byte("cerber/endpoint/1:"), p...))}, nil
}
func (s Signed) Verify(key ed25519.PublicKey, agent string, now time.Time) (Bundle, error) {
	var b Bundle
	if !ed25519.Verify(key, append([]byte("cerber/endpoint/1:"), s.Payload...), s.Signature) || json.Unmarshal(s.Payload, &b) != nil || b.Agent != agent || !now.Before(b.Expires) || b.Issued.After(now.Add(time.Minute)) || b.Expires.Sub(b.Issued) > 25*time.Hour || b.Policy.Validate() != nil {
		return b, ErrInvalid
	}
	return b, nil
}
