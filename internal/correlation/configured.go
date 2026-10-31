// SPDX-License-Identifier: Apache-2.0
package correlation

import (
	"github.com/rkislov/cerber/internal/telemetry"
)

// Configured evaluates one built-in condition. Scope and window filtering are
// supplied by the shared live/preview adapter. Rule implementation version stays 1.
func Configured(rule string, n telemetry.Normalized, previous []telemetry.Normalized, threshold int) *telemetry.Detection {
	if n.Status != "parsed" {
		return nil
	}
	title, severity := "", "medium"
	switch rule {
	case "suricata.alert":
		return Suricata(n)
	case "auth.repeated_failures", "auth.success_after_failures":
		if n.Class != "authentication" || n.User == "" || n.SourceIP == "" || len(previous) < threshold {
			return nil
		}
		if rule == "auth.repeated_failures" && n.Outcome == "failure" {
			title = "Серия неудачных входов"
		} else if rule == "auth.success_after_failures" && n.Outcome == "success" {
			title = "Успешный вход после серии отказов"
			severity = "high"
		}
	case "windows.audit_log_cleared":
		if n.Class == "audit" && n.Action == "log_cleared" {
			title = "Очищен журнал аудита Windows"
			severity = "high"
		}
	case "firewall.syn_scan", "firewall.port_scan":
		if n.Class != "firewall" || n.SourceIP == "" || n.DestinationIP == "" || rule == "firewall.syn_scan" && n.Action != "syn" || rule == "firewall.port_scan" && n.Action != "deny" {
			return nil
		}
		ports := map[int]bool{}
		for _, p := range previous {
			if p.DestinationPort > 0 {
				ports[p.DestinationPort] = true
			}
		}
		if len(ports) >= threshold {
			title = "TCP SYN на множество портов"
			if rule == "firewall.port_scan" {
				title = "Вероятное сканирование портов"
				severity = "high"
			}
		}
	case "firewall.denied_burst":
		if n.Class == "firewall" && n.Action == "deny" && n.SourceIP != "" && len(previous) >= threshold {
			title = "Серия блокировок межсетевым экраном"
		}
	case "fess.blocked_burst":
		if n.Class == "fess" && n.Action == "deny" && n.SourceIP != "" && len(previous) >= threshold {
			title = "Серия блокировок FESS WAF"
		}
	case "fess.allowed_after_blocks":
		if n.Class == "fess" && n.Action == "allow" && n.SourceIP != "" && len(previous) >= threshold {
			title = "Разрешённый запрос после блокировок FESS"
			severity = "high"
		}
	}
	if title == "" {
		return nil
	}
	d := &telemetry.Detection{ID: telemetry.ID(rule, "1", n.ID), Rule: rule, Version: 1, AgentID: n.AgentID, AssetID: n.AssetID, User: n.User, SourceIP: n.SourceIP, Severity: severity, Title: title, CreatedAt: n.ReceivedAt, FirstSeen: n.EventTime, LastSeen: n.EventTime, Evidence: []string{}, State: "open"}
	if n.Class == "fess" || n.Class == "firewall" {
		d.User = ""
		d.GroupKey = telemetry.ID(n.Class, n.Product, n.Device, n.DestinationIP)
	}
	present := false
	for _, p := range previous {
		d.Evidence = append(d.Evidence, p.ID)
		if p.EventTime.Before(d.FirstSeen) {
			d.FirstSeen = p.EventTime
		}
		present = present || p.ID == n.ID
	}
	if !present {
		d.Evidence = append(d.Evidence, n.ID)
	}
	return d
}
func CandidateRules(n telemetry.Normalized) []string {
	switch n.Class {
	case "network_alert":
		return []string{"suricata.alert"}
	case "authentication":
		if n.Outcome == "failure" {
			return []string{"auth.repeated_failures"}
		}
		if n.Outcome == "success" {
			return []string{"auth.success_after_failures"}
		}
	case "audit":
		return []string{"windows.audit_log_cleared"}
	case "firewall":
		if n.Action == "syn" {
			return []string{"firewall.syn_scan"}
		}
		if n.Action == "deny" {
			return []string{"firewall.port_scan", "firewall.denied_burst"}
		}
	case "fess":
		if n.Action == "deny" {
			return []string{"fess.blocked_burst"}
		}
		if n.Action == "allow" {
			return []string{"fess.allowed_after_blocks"}
		}
	}
	return nil
}
