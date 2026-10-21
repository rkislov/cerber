// SPDX-License-Identifier: Apache-2.0
package telemetry

import (
	"encoding/json"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// CEF is an explicit adapter, never inferred from untrusted free-text log messages.
// Unknown actions are retained but cannot become allow/block detections.
var cefKey = regexp.MustCompile(`(?:^| )([A-Za-z][A-Za-z0-9]*)=`)

func normalizeCEF(r RawRecord, n Normalized) Normalized {
	bad := func() Normalized {
		n.Status = "quarantine"
		n.Class = "unknown"
		n.Message = "Invalid or unsupported CEF event"
		n.EventTime = r.ReceivedAt
		return n
	}
	var v struct {
		Line    string `json:"line"`
		Profile string `json:"profile"`
	}
	if json.Unmarshal(r.Raw.Data, &v) != nil || len(v.Line) > 15000 || strings.ContainsAny(v.Line, "\r\n\x00") || (v.Profile != "firewall" && v.Profile != "fess") {
		return bad()
	}
	line := v.Line
	if strings.HasPrefix(line, "<") {
		i := strings.Index(line, " CEF:0|")
		if i < 0 {
			return bad()
		}
		line = line[i+1:]
	}
	if !strings.HasPrefix(line, "CEF:0|") {
		return bad()
	}
	parts := []string{}
	var b strings.Builder
	escaped := false
	for i, c := range line {
		if escaped {
			if c != '|' && c != '\\' {
				b.WriteByte('\\')
			}
			b.WriteRune(c)
			escaped = false
			continue
		}
		if c == '\\' {
			escaped = true
			continue
		}
		if c == '|' {
			parts = append(parts, b.String())
			b.Reset()
			if len(parts) == 7 {
				parts = append(parts, line[i+1:])
				break
			}
		} else {
			b.WriteRune(c)
		}
	}
	if len(parts) != 8 {
		return bad()
	}
	sev, e := strconv.Atoi(parts[6])
	if e != nil || sev < 0 || sev > 10 {
		return bad()
	}
	ext := map[string]string{}
	indexes := cefKey.FindAllStringSubmatchIndex(parts[7], -1)
	for i, m := range indexes {
		key := parts[7][m[2]:m[3]]
		end := len(parts[7])
		if i+1 < len(indexes) {
			end = indexes[i+1][0]
		}
		if _, ok := ext[key]; ok {
			return bad()
		}
		value := strings.TrimSpace(parts[7][m[1]:end])
		value = strings.ReplaceAll(value, `\=`, `=`)
		value = strings.ReplaceAll(value, `\\`, `\`)
		ext[key] = value
	}
	at, e := time.Parse(time.RFC3339Nano, ext["rt"])
	if e != nil {
		return bad()
	}
	ip, e := netip.ParseAddr(ext["src"])
	if e != nil && !(v.Profile == "fess" && parts[5] == "Audit" && ext["src"] == "") {
		return bad()
	}
	n.EventTime = at.UTC()
	if ip.IsValid() {
		n.SourceIP = ip.Unmap().String()
	}
	n.Parser = "cef-network/2"
	n.Class = v.Profile
	n.Product = parts[1] + "/" + parts[2]
	n.Code = parts[4]
	n.Message = parts[5]
	n.Device = ext["dvchost"]
	n.Request = ext["request"]
	n.User = strings.ToLower(ext["suser"])
	n.Action = "log"
	n.Outcome = "unknown"
	if v.Profile == "fess" && parts[5] != "WAF event" && parts[5] != "Proxy access" && parts[5] != "Audit" {
		return bad()
	}
	if n.EventTime.After(r.ReceivedAt.Add(5 * time.Minute)) {
		return bad()
	}
	if v.Profile == "fess" && parts[5] == "Audit" {
		n.Class = "audit"
		n.Action = "configuration_change"
		return n
	}
	action := strings.ToLower(ext["act"])
	if action == "" && v.Profile == "fess" {
		action = strings.ToLower(parts[4])
	}
	switch action {
	case "deny", "denied", "drop", "dropped", "block", "blocked", "reject":
		n.Action = "deny"
		n.Outcome = "failure"
	case "allow", "allowed", "accept", "accepted", "proxied", "pass":
		n.Action = "allow"
		n.Outcome = "success"
	}
	if ext["dst"] != "" {
		dst, e := netip.ParseAddr(ext["dst"])
		if e != nil {
			return bad()
		}
		n.DestinationIP = dst.Unmap().String()
	}
	if ext["dpt"] != "" {
		port, e := strconv.Atoi(ext["dpt"])
		if e != nil || port < 1 || port > 65535 {
			return bad()
		}
		n.DestinationPort = port
	}
	if n.EventTime.After(r.ReceivedAt.Add(5 * time.Minute)) {
		return bad()
	}
	return n
}
