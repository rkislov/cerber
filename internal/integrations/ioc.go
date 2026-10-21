// SPDX-License-Identifier: Apache-2.0
package integrations

import (
	"archive/zip"
	"bufio"
	"bytes"
	"context"
	"encoding/csv"
	"fmt"
	"github.com/rkislov/cerber/internal/telemetry"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type IOC struct {
	ID         string    `json:"id"`
	Value      string    `json:"value"`
	Type       string    `json:"type"`
	Malware    string    `json:"malware"`
	Confidence int       `json:"confidence"`
	First      time.Time `json:"first"`
	Last       time.Time `json:"last"`
}
type Index struct {
	Values map[string][]IOC
	Count  int
}

func indicatorKey(kind, value string) (string, bool) {
	switch kind {
	case "ip:port":
		a, e := netip.ParseAddrPort(value)
		if e != nil {
			return "", false
		}
		return "ip:port:" + netip.AddrPortFrom(a.Addr().Unmap(), a.Port()).String(), true
	case "ip", "ipv4", "ipv6":
		a, e := netip.ParseAddr(value)
		if e != nil {
			return "", false
		}
		return "ip:" + a.Unmap().String(), true
	case "domain":
		v := strings.ToLower(strings.TrimSuffix(value, "."))
		if v == "" || strings.ContainsAny(v, " /:\r\n") {
			return "", false
		}
		return "domain:" + v, true
	case "url":
		u, e := url.Parse(value)
		if e != nil || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") {
			return "", false
		}
		u.Host = strings.ToLower(u.Host)
		return "url:" + u.String(), true
	}
	return "", false
}
func NewIndex(items []IOC) *Index {
	x := &Index{Values: map[string][]IOC{}, Count: len(items)}
	for _, v := range items {
		if k, ok := indicatorKey(v.Type, v.Value); ok {
			x.Values[k] = append(x.Values[k], v)
			if v.Type == "ip:port" {
				if a, e := netip.ParseAddrPort(v.Value); e == nil {
					key := "ip_observed:" + a.Addr().Unmap().String()
					x.Values[key] = append(x.Values[key], v)
				}
			}
		}
	}
	return x
}
func (x *Index) Match(n telemetry.Normalized) []telemetry.Detection {
	if x == nil || n.Status != "parsed" {
		return nil
	}
	keys := map[string]bool{}
	add := func(k, v string) {
		if key, ok := indicatorKey(k, v); ok {
			keys[key] = true
		}
	}
	for _, ip := range []string{n.SourceIP, n.DestinationIP} {
		add("ip", ip)
		if a, e := netip.ParseAddr(ip); e == nil {
			keys["ip_observed:"+a.Unmap().String()] = true
		}
	}
	if a, e := netip.ParseAddr(n.DestinationIP); e == nil && n.DestinationPort > 0 && n.DestinationPort <= 65535 {
		add("ip:port", netip.AddrPortFrom(a.Unmap(), uint16(n.DestinationPort)).String())
	}
	if u, e := url.Parse(n.Request); e == nil && u.Hostname() != "" {
		add("domain", u.Hostname())
		add("url", n.Request)
	}
	out := []telemetry.Detection{}
	seen := map[string]bool{}
	for k := range keys {
		for _, v := range x.Values[k] {
			if seen[v.ID] || n.EventTime.Before(v.First) || !v.Last.IsZero() && n.EventTime.After(v.Last.AddDate(0, 6, 0)) {
				continue
			}
			if strings.HasPrefix(k, "ip_observed:") {
				exact, _ := indicatorKey(v.Type, v.Value)
				if keys[exact] {
					continue
				}
			}
			seen[v.ID] = true
			rule, severity, title := "threatfox.ioc_match", "high", fmt.Sprintf("ThreatFox IOC %s: %s · %s · confidence %d", v.ID, v.Value, v.Malware, v.Confidence)
			if strings.HasPrefix(k, "ip_observed:") {
				rule = "threatfox.ip_match"
				severity = "medium"
				title += " · IP совпал; порт IOC не подтверждён"
			}
			out = append(out, telemetry.Detection{ID: telemetry.ID("threatfox.ioc_match/1", n.ID, v.ID), Rule: rule, Version: 1, AgentID: n.AgentID, AssetID: n.AssetID, SourceIP: n.SourceIP, Severity: severity, Title: title, CreatedAt: time.Now().UTC(), FirstSeen: n.EventTime, LastSeen: n.EventTime, Evidence: []string{n.ID}, State: "open", GroupKey: "threatfox:" + v.ID})
		}
	}
	return out
}

// Full exports are mandatory, including first sync. Never substitutes a seven-day API response.
func downloadFull(ctx context.Context, key string) ([]IOC, error) {
	endpoint := "https://threatfox-api.abuse.ch/v2/files/exports/" + url.PathEscape(key) + "/full.csv.zip"
	req, e := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if e != nil {
		return nil, fmt.Errorf("ThreatFox export request failed")
	}
	client := &http.Client{Timeout: 3 * time.Minute, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	r, e := client.Do(req)
	if e != nil {
		return nil, fmt.Errorf("ThreatFox full export download failed")
	}
	defer r.Body.Close()
	if r.StatusCode != 200 {
		return nil, fmt.Errorf("ThreatFox full export HTTP %d", r.StatusCode)
	}
	b, e := io.ReadAll(io.LimitReader(r.Body, 128<<20+1))
	if e != nil || len(b) > 128<<20 {
		return nil, fmt.Errorf("ThreatFox export size limit")
	}
	return parseExport(b, time.Now().UTC())
}
func parseExport(b []byte, now time.Time) ([]IOC, error) {
	z, e := zip.NewReader(bytes.NewReader(b), int64(len(b)))
	if e != nil {
		return nil, fmt.Errorf("ThreatFox invalid ZIP")
	}
	if len(z.File) > 10 {
		return nil, fmt.Errorf("ThreatFox unexpected ZIP entries")
	}
	var file *zip.File
	for _, f := range z.File {
		if strings.HasSuffix(f.Name, ".csv") {
			if file != nil {
				return nil, fmt.Errorf("ThreatFox ambiguous CSV")
			}
			file = f
		}
	}
	if file == nil || file.UncompressedSize64 > 512<<20 {
		return nil, fmt.Errorf("ThreatFox missing or oversized CSV")
	}
	r, e := file.Open()
	if e != nil {
		return nil, fmt.Errorf("ThreatFox CSV open failed")
	}
	defer r.Close()
	scan := bufio.NewScanner(io.LimitReader(r, 512<<20+1))
	scan.Buffer(make([]byte, 4096), 1<<20)
	header := map[string]int{}
	items := []IOC{}
	ids := map[string]bool{}
	for scan.Scan() {
		line := strings.TrimSpace(scan.Text())
		if line == "" {
			continue
		}
		comment := strings.HasPrefix(line, "#")
		line = strings.TrimSpace(strings.TrimPrefix(line, "#"))
		if comment && !strings.Contains(line, "ioc_value") {
			continue
		}
		reader := csv.NewReader(strings.NewReader(line))
		reader.TrimLeadingSpace = true
		row, e := reader.Read()
		if e != nil {
			return nil, fmt.Errorf("ThreatFox malformed CSV")
		}
		if len(header) == 0 {
			for i, v := range row {
				header[strings.TrimSpace(v)] = i
			}
			for _, v := range []string{"ioc_id", "ioc_value", "ioc_type", "first_seen_utc", "confidence_level"} {
				if _, ok := header[v]; !ok {
					return nil, fmt.Errorf("ThreatFox CSV schema mismatch")
				}
			}
			continue
		}
		get := func(k string) string {
			i, ok := header[k]
			if !ok || i >= len(row) {
				return ""
			}
			return row[i]
		}
		first, e := time.Parse("2006-01-02 15:04:05", get("first_seen_utc"))
		if e != nil {
			return nil, fmt.Errorf("ThreatFox invalid observation time")
		}
		last := first
		if get("last_seen_utc") != "" {
			last, e = time.Parse("2006-01-02 15:04:05", get("last_seen_utc"))
			if e != nil {
				return nil, fmt.Errorf("ThreatFox invalid last observation")
			}
		}
		confidence, e := strconv.Atoi(get("confidence_level"))
		if e != nil || confidence < 0 || confidence > 100 {
			return nil, fmt.Errorf("ThreatFox invalid confidence")
		}
		v := IOC{ID: get("ioc_id"), Value: get("ioc_value"), Type: get("ioc_type"), Malware: get("malware_printable"), Confidence: confidence, First: first, Last: last}
		if v.ID == "" || ids[v.ID] {
			return nil, fmt.Errorf("ThreatFox invalid duplicate ID")
		}
		ids[v.ID] = true
		if len(ids) > 1000000 {
			return nil, fmt.Errorf("ThreatFox indicator limit")
		}
		if !last.Before(now.AddDate(0, -6, 0)) {
			items = append(items, v)
		}
	}
	if scan.Err() != nil || len(items) == 0 {
		return nil, fmt.Errorf("ThreatFox empty or incomplete export")
	}
	return items, nil
}
