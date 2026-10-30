// SPDX-License-Identifier: Apache-2.0
package correlation

import (
	"fmt"
	"github.com/rkislov/cerber/internal/telemetry"
	"sort"
	"strings"
)

func ChainRule(rule string) bool {
	if WindowsFlowRule(rule) {
		return true
	}
	switch rule {
	case "chain.domain_account_hosts", "chain.logon_guid_hosts", "chain.ssh_key_hosts", "chain.remote_logon_audit_clear":
		return true
	}
	return false
}
func ChainCandidates(n telemetry.Normalized) []string {
	if n.Identity == nil || n.Status != "parsed" {
		return nil
	}
	if n.Action == "log_cleared" && n.Identity.AccountKey != "" && n.Identity.LocalSession != "" {
		return []string{"chain.remote_logon_audit_clear"}
	}
	if n.Class != "authentication" || n.Outcome != "success" {
		return nil
	}
	if n.Identity.SSHKey != "" {
		return []string{"chain.ssh_key_hosts"}
	}
	if domainLogon(n) {
		out := []string{"chain.domain_account_hosts"}
		if n.Identity.SessionGUID != "" {
			out = append(out, "chain.logon_guid_hosts")
		}
		if WindowsFlowTarget(n) {
			out = append(out, "chain.kerberos_logon", "chain.explicit_credentials_logon")
		}
		return out
	}
	return nil
}
func domainLogon(n telemetry.Normalized) bool {
	return n.Identity != nil && n.Identity.AccountKey != "" && n.Class == "authentication" && n.Outcome == "success" && (n.Identity.LogonType == 3 || n.Identity.LogonType == 10) && telemetry.RemoteAddress(n.SourceIP)
}
func ChainKey(rule string, n telemetry.Normalized) string {
	if n.Identity == nil {
		return ""
	}
	switch rule {
	case "chain.ssh_key_hosts":
		return n.Identity.SSHKey
	case "chain.logon_guid_hosts":
		if n.Identity.AccountKey != "" && n.Identity.SessionGUID != "" {
			return telemetry.ID(n.Identity.AccountKey, n.Identity.SessionGUID)
		}
	default:
		return n.Identity.AccountKey
	}
	return ""
}

// Chain evaluates only explicit identifiers. Same names, IPs and local logon IDs
// never join distinct hosts. A chain describes observations, not proven movement.
func Chain(rule string, n telemetry.Normalized, history []telemetry.Normalized, threshold int, truncated bool) *telemetry.Detection {
	key := ChainKey(rule, n)
	if !ChainRule(rule) || key == "" || n.AgentID == "" || n.AssetID == "" || n.Identity == nil {
		return nil
	}
	currentAllowed := false
	for _, id := range ChainCandidates(n) {
		currentAllowed = currentAllowed || id == rule
	}
	if !currentAllowed {
		return nil
	}
	items := []telemetry.Normalized{}
	var local *telemetry.Normalized
	for _, p := range history {
		if p.Status != "parsed" || p.Identity == nil || p.AgentID == "" || p.AssetID == "" || p.EventTime.After(n.EventTime) || p.Sequence > n.Sequence || p.Class != "authentication" || p.Outcome != "success" {
			continue
		}
		if rule == "chain.ssh_key_hosts" {
			if p.Identity.SSHKey != key {
				continue
			}
		} else if !domainLogon(p) || ChainKey(rule, p) != key {
			continue
		}
		if rule == "chain.remote_logon_audit_clear" && p.AgentID == n.AgentID && p.AssetID == n.AssetID && p.Identity.LocalSession == n.Identity.LocalSession && p.EventTime.Before(n.EventTime) {
			if local == nil || p.EventTime.After(local.EventTime) {
				copy := p
				local = &copy
			}
		}
		items = append(items, p)
	}
	if rule == "chain.remote_logon_audit_clear" {
		if local == nil {
			return nil
		}
		filtered := []telemetry.Normalized{}
		for _, p := range items {
			if p.AgentID != n.AgentID && p.AssetID != n.AssetID && p.EventTime.Before(local.EventTime) {
				filtered = append(filtered, p)
			}
		}
		items = append(filtered, *local)
	} else {
		items = append(items, n)
	}
	// One latest representative per distinct agent and asset; duplicate enrollment
	// of one asset cannot raise the distinct-host count.
	sort.Slice(items, func(i, j int) bool {
		if items[i].EventTime.Equal(items[j].EventTime) {
			return items[i].Sequence > items[j].Sequence
		}
		return items[i].EventTime.After(items[j].EventTime)
	})
	seenAgent, seenAsset := map[string]bool{}, map[string]bool{}
	chosen := []telemetry.Normalized{}
	for _, p := range items {
		if seenAgent[p.AgentID] || seenAsset[p.AssetID] {
			continue
		}
		seenAgent[p.AgentID] = true
		seenAsset[p.AssetID] = true
		chosen = append(chosen, p)
	}
	hosts := len(chosen)
	if hosts < threshold || hosts < 2 {
		return nil
	}
	if len(chosen) > 20 {
		chosen = chosen[:20]
		truncated = true
	}
	if rule == "chain.remote_logon_audit_clear" {
		chosen = append(chosen, n)
	}
	sort.Slice(chosen, func(i, j int) bool {
		if chosen[i].EventTime.Equal(chosen[j].EventTime) {
			return chosen[i].Sequence < chosen[j].Sequence
		}
		return chosen[i].EventTime.Before(chosen[j].EventTime)
	})
	title := map[string]string{"chain.domain_account_hosts": "Доменная учётная запись на нескольких узлах", "chain.logon_guid_hosts": "Общий Logon GUID на нескольких узлах", "chain.ssh_key_hosts": "SSH-ключ использован на нескольких узлах", "chain.remote_logon_audit_clear": "Входы на разных узлах и очистка аудита в сеансе"}[rule]
	d := &telemetry.Detection{ID: telemetry.ID(rule, "1", n.ID), Rule: rule, Version: 1, AgentID: n.AgentID, AssetID: n.AssetID, User: n.User, SourceIP: n.SourceIP, GroupKey: telemetry.ID(rule, key), Severity: "medium", Title: title, CreatedAt: n.ReceivedAt, FirstSeen: chosen[0].EventTime, LastSeen: n.EventTime, State: "open", Evidence: []string{}}
	if strings.HasSuffix(rule, "audit_clear") {
		d.Severity = "high"
	}
	c := &telemetry.EventChain{Version: 1, Key: key, Hosts: hosts, Truncated: truncated, Steps: []telemetry.ChainStep{}, Links: []telemetry.ChainLink{}, Limitations: "Наблюдаемая последовательность, не доказательство атаки или прямого перемещения между соседними узлами. Идентификаторы сообщены источниками; возможны штатное администрирование и общий ключ. IP не подтверждает владельца. Локальный Logon ID действует только на одном агенте/активе и может повторяться после перезагрузки. Учитываются уже обработанные события оперативного журнала; поздние события не переигрывают прошлые срабатывания. Active response этими правилами не запускается автоматически."}
	for j, p := range chosen {
		d.Evidence = append(d.Evidence, p.ID)
		c.Steps = append(c.Steps, telemetry.ChainStep{Code: p.Code, Outcome: p.Outcome, WindowsAuth: p.WindowsAuth, EventID: p.ID, AgentID: p.AgentID, AssetID: p.AssetID, At: p.EventTime, User: p.User, SourceIP: p.SourceIP, Action: p.Action, Identity: *p.Identity})
		if j > 0 {
			kind, basis := "domain_sid", "Одинаковый SID доменной учётной записи из событий Windows; имена и адреса не являются ключом"
			if rule == "chain.logon_guid_hosts" {
				kind, basis = "logon_guid", "Одинаковые SID доменной учётной записи и ненулевой Logon GUID"
			}
			if rule == "chain.ssh_key_hosts" {
				kind, basis = "ssh_key", "Одинаковый SHA-256 отпечаток публичного SSH-ключа; пользователи на узлах могут различаться"
			}
			if p.Action == "log_cleared" {
				kind, basis = "local_session", fmt.Sprintf("Тот же агент и актив, SID и локальный Logon ID %s; очистка после входа", p.Identity.LocalSession)
			}
			c.Links = append(c.Links, telemetry.ChainLink{From: chosen[j-1].ID, To: p.ID, Kind: kind, Basis: basis})
		}
	}
	d.Chain = c
	return d
}
