// SPDX-License-Identifier: Apache-2.0
package correlation

import (
	"github.com/rkislov/cerber/internal/telemetry"
	"net/netip"
	"sort"
	"time"
)

const InvestigationWindow = 30 * time.Minute
const InvestigationLimit = 100

type RelatedDetection struct {
	AnchorIDs []string            `json:"anchor_ids"`
	Detection telemetry.Detection `json:"detection"`
	Linked    bool                `json:"linked"`
	Reasons   []string            `json:"reasons"`
	Keys      []string            `json:"keys"`
}
type Hypothesis struct {
	ID           string   `json:"id"`
	Rule         string   `json:"rule"`
	Version      int      `json:"version"`
	Title        string   `json:"title"`
	Basis        string   `json:"basis"`
	DetectionIDs []string `json:"detection_ids"`
}
type Investigation struct {
	IncidentID      string                `json:"incident_id,omitempty"`
	IncidentVersion int                   `json:"incident_version,omitempty"`
	At              time.Time             `json:"at"`
	WindowSeconds   int                   `json:"window_seconds"`
	Anchors         []telemetry.Detection `json:"anchors"`
	Related         []RelatedDetection    `json:"related"`
	Hypotheses      []Hypothesis          `json:"hypotheses"`
	Truncated       bool                  `json:"truncated"`
	Limitations     string                `json:"limitations"`
}

func SameInvestigationAsset(a, b telemetry.Detection) bool {
	return a.AgentID != "" && a.AssetID != "" && a.AgentID == b.AgentID && a.AssetID == b.AssetID
}
func SharedEvidence(a, b telemetry.Detection) bool {
	seen := map[string]bool{}
	for _, id := range a.Evidence {
		if telemetry.Identifier(id) {
			seen[id] = true
		}
	}
	for _, id := range b.Evidence {
		if seen[id] {
			return true
		}
	}
	return false
}
func sameRemote(a, b string) bool {
	x, e := netip.ParseAddr(a)
	if e != nil || x.Zone() != "" || x.IsUnspecified() || x.IsMulticast() || x.IsLoopback() {
		return false
	}
	y, e := netip.ParseAddr(b)
	return e == nil && y.Zone() == "" && x.Unmap() == y.Unmap()
}

// Relations require an authenticated asset identity and a direct anchor match.
// They are not transitive and never constitute evidence of causation.
func RelatedReasons(anchor, candidate telemetry.Detection) ([]string, []string) {
	if !SameInvestigationAsset(anchor, candidate) || anchor.LastSeen.IsZero() || candidate.LastSeen.IsZero() || candidate.LastSeen.Before(anchor.LastSeen.Add(-InvestigationWindow)) || candidate.LastSeen.After(anchor.LastSeen.Add(InvestigationWindow)) {
		return nil, nil
	}
	reasons, keys := []string{}, []string{}
	if SharedEvidence(anchor, candidate) {
		keys = append(keys, "same_event")
		reasons = append(reasons, "Общий ID исходного события на том же агенте и активе")
	}
	if anchor.User != "" && anchor.User == candidate.User {
		keys = append(keys, "same_user")
		reasons = append(reasons, "Одинаковая строка имени пользователя на том же активе; доменную принадлежность уточните в исходниках")
	}
	if sameRemote(anchor.SourceIP, candidate.SourceIP) {
		keys = append(keys, "same_remote_ip")
		reasons = append(reasons, "Одинаковый адрес источника на том же активе; NAT и общие адреса могут объединять разных инициаторов")
	}
	return reasons, keys
}
func InvestigationHypotheses(items []telemetry.Detection) []Hypothesis {
	out := []Hypothesis{}
	sort.Slice(items, func(i, j int) bool {
		if items[i].LastSeen.Equal(items[j].LastSeen) {
			return items[i].ID < items[j].ID
		}
		return items[i].LastSeen.Before(items[j].LastSeen)
	})
	for i, a := range items {
		for _, b := range items[i+1:] {
			if len(out) >= 20 {
				return out
			}
			if !SameInvestigationAsset(a, b) || a.Version != 1 || b.Version != 1 || a.LastSeen.IsZero() || b.LastSeen.Sub(a.LastSeen) > InvestigationWindow {
				continue
			}
			rule, title, basis := "", "", ""
			if a.Rule == "auth.success_after_failures" && b.Rule == "windows.audit_log_cleared" && a.User != "" && a.User == b.User && !b.LastSeen.Equal(a.LastSeen) {
				rule = "investigation.auth_then_audit_clear"
				title = "Вход после отказов и последующая очистка аудита"
				basis = "Один агент и актив, одинаковая строка пользователя; очистка аудита произошла позже, в пределах 30 минут. Возможны плановые действия администратора."
			}
			perimeter := func(d telemetry.Detection) bool {
				return d.Rule == "fess.allowed_after_blocks" || d.Rule == "firewall.accept_after_blocks"
			}
			ioc := func(d telemetry.Detection) bool {
				return d.Rule == "threatfox.ip_match" || d.Rule == "threatfox.ioc_match"
			}
			if (perimeter(a) && ioc(b) || perimeter(b) && ioc(a)) && SharedEvidence(a, b) {
				rule = "investigation.allowed_with_ioc"
				title = "Разрешение после блокировок и совпадение IOC"
				basis = "Срабатывания ссылаются на один исходный ID события того же агента и актива. Совпадение IOC не подтверждает успешную атаку."
			}
			if rule != "" {
				out = append(out, Hypothesis{ID: telemetry.ID(rule, "1", a.ID, b.ID), Rule: rule, Version: 1, Title: title, Basis: basis, DetectionIDs: []string{a.ID, b.ID}})
			}
		}
	}
	return out
}
