// SPDX-License-Identifier: Apache-2.0
package correlation

import (
	"github.com/rkislov/cerber/internal/telemetry"
	"sort"
)

func WindowsFlowRule(rule string) bool {
	return rule == "chain.kerberos_logon" || rule == "chain.explicit_credentials_logon"
}
func WindowsFlowTarget(n telemetry.Normalized) bool {
	return domainLogon(n) && n.Action == "logon" && n.Identity.SessionGUID != "" && n.Identity.AccountRef != ""
}
func CredentialMatches(p, n telemetry.Normalized) bool {
	return WindowsFlowTarget(n) && p.Status == "parsed" && p.Class == "credentials" && p.Action == "explicit_credentials" && p.WindowsAuth != nil && p.Identity != nil && p.AgentID != n.AgentID && p.AssetID != n.AssetID && p.WindowsAuth.TargetGUID != "" && p.WindowsAuth.TargetGUID == n.Identity.SessionGUID && p.WindowsAuth.AccountRef != "" && p.WindowsAuth.AccountRef == n.Identity.AccountRef && p.EventTime.Before(n.EventTime) && p.Sequence <= n.Sequence
}
func TicketMatches(p, n telemetry.Normalized) bool {
	return WindowsFlowTarget(n) && p.Status == "parsed" && p.Class == "kerberos" && p.Action == "kerberos_service_ticket" && p.Outcome == "success" && p.WindowsAuth != nil && p.Identity != nil && p.AgentID != n.AgentID && p.AssetID != n.AssetID && p.Identity.SessionGUID != "" && p.Identity.SessionGUID == n.Identity.SessionGUID && p.WindowsAuth.AccountRef != "" && p.WindowsAuth.AccountRef == n.Identity.AccountRef && p.EventTime.Before(n.EventTime) && p.Sequence <= n.Sequence
}
func latestFlow(a *telemetry.Normalized, p telemetry.Normalized) *telemetry.Normalized {
	if a == nil || p.EventTime.After(a.EventTime) || p.EventTime.Equal(a.EventTime) && p.Sequence > a.Sequence {
		copy := p
		return &copy
	}
	return a
}

// WindowsFlow preserves source actor and credential target as distinct identities.
// A matching GUID + exact qualified name is an association, never ticket redemption.
func WindowsFlow(rule string, n telemetry.Normalized, history []telemetry.Normalized, threshold int, truncated bool) *telemetry.Detection {
	if !WindowsFlowRule(rule) || !WindowsFlowTarget(n) {
		return nil
	}
	var cred, ticket, actor *telemetry.Normalized
	for _, p := range history {
		if CredentialMatches(p, n) {
			cred = latestFlow(cred, p)
		}
		if TicketMatches(p, n) {
			ticket = latestFlow(ticket, p)
		}
	}
	if rule == "chain.kerberos_logon" && ticket == nil || rule == "chain.explicit_credentials_logon" && cred == nil {
		return nil
	}
	if cred != nil && cred.Identity.AccountKey != "" && cred.Identity.LocalSession != "" {
		for _, p := range history {
			if p.Status == "parsed" && p.Class == "authentication" && p.Action == "logon" && p.Outcome == "success" && p.Identity != nil && p.AgentID == cred.AgentID && p.AssetID == cred.AssetID && p.Identity.AccountKey == cred.Identity.AccountKey && p.Identity.LocalSession == cred.Identity.LocalSession && p.EventTime.Before(cred.EventTime) && p.Sequence <= n.Sequence && (p.Identity.SessionGUID == "" || cred.Identity.SessionGUID == "" || p.Identity.SessionGUID == cred.Identity.SessionGUID) {
				actor = latestFlow(actor, p)
			}
		}
	}
	selected := []telemetry.Normalized{n}
	for _, p := range []*telemetry.Normalized{actor, cred, ticket} {
		if p != nil {
			selected = append(selected, *p)
		}
	}
	agents, assets := map[string]bool{}, map[string]bool{}
	for _, p := range selected {
		if p.AgentID == "" || p.AssetID == "" {
			return nil
		}
		agents[p.AgentID] = true
		assets[p.AssetID] = true
	}
	hosts := len(agents)
	if len(assets) < hosts {
		hosts = len(assets)
	}
	if hosts < 2 || hosts < threshold {
		return nil
	}
	sort.Slice(selected, func(i, j int) bool {
		if selected[i].EventTime.Equal(selected[j].EventTime) {
			return selected[i].Sequence < selected[j].Sequence
		}
		return selected[i].EventTime.Before(selected[j].EventTime)
	})
	title := "Kerberos-билет и последующий сетевой вход"
	if rule == "chain.explicit_credentials_logon" {
		title = "Явное использование реквизитов и последующий сетевой вход"
	}
	d := &telemetry.Detection{ID: telemetry.ID(rule, "1", n.ID), Rule: rule, Version: 1, AgentID: n.AgentID, AssetID: n.AssetID, User: n.User, SourceIP: n.SourceIP, GroupKey: telemetry.ID(rule, n.Identity.AccountKey, n.AgentID), Severity: "medium", Title: title, CreatedAt: n.ReceivedAt, FirstSeen: selected[0].EventTime, LastSeen: n.EventTime, State: "open", Evidence: []string{}}
	c := &telemetry.EventChain{Version: 2, Key: telemetry.ID(n.Identity.AccountRef, n.Identity.SessionGUID), Hosts: hosts, Truncated: truncated, Steps: []telemetry.ChainStep{}, Links: []telemetry.ChainLink{}, Limitations: "Связи по ненулевому GUID и точно совпадающему доменному имени из источников; SID целевого входа не приписывается инициатору 4648 или пользователю билета 4769. 4648 означает попытку, не успешный вход. ServiceSid — SID службы. Выдача билета не доказывает его использование, а принадлежность запрошенной службы целевому узлу отдельно не проверена. DNS/NetBIOS-алиасы без каталога не объединяются. Локальный сеанс ограничен агентом/активом и может повторяться после перезагрузки. Это могут быть штатные SSO/RunAs/задачи. Учитываются уже обработанные события; поздняя доставка не пересчитывает старые входы. Active response не запускается."}
	for _, p := range selected {
		d.Evidence = append(d.Evidence, p.ID)
		c.Steps = append(c.Steps, telemetry.ChainStep{Outcome: p.Outcome, Code: p.Code, WindowsAuth: p.WindowsAuth, EventID: p.ID, AgentID: p.AgentID, AssetID: p.AssetID, At: p.EventTime, User: p.User, SourceIP: p.SourceIP, Action: p.Action, Identity: *p.Identity})
	}
	link := func(a, b telemetry.Normalized, kind, basis string) {
		c.Links = append(c.Links, telemetry.ChainLink{From: a.ID, To: b.ID, Kind: kind, Basis: basis})
	}
	if actor != nil {
		link(*actor, *cred, "actor_local_session", "Тот же агент/актив, SID инициатора и локальный SubjectLogonId; сеанс входа предшествует 4648. Инициатор и целевые реквизиты могут принадлежать разным людям.")
	}
	if ticket != nil {
		link(*ticket, n, "kerberos_guid", "LogonGuid 4769 совпал с LogonGuid 4624, доменное имя пользователя совпало точно. Статус 4769 — 0x0. Использование именно этого билета не доказано.")
	}
	if cred != nil {
		if ticket != nil && cred.EventTime.Before(ticket.EventTime) {
			link(*cred, *ticket, "credential_ticket_guid", "TargetLogonGuid 4648 совпал с LogonGuid 4769 и совпало точное доменное имя целевых реквизитов; запрос билета позже попытки.")
		} else {
			link(*cred, n, "explicit_target_guid", "TargetLogonGuid 4648 совпал с LogonGuid 4624 и совпало точное доменное имя целевых реквизитов. Subject LogonGuid инициатора не используется вместо TargetLogonGuid.")
		}
	}
	d.Chain = c
	return d
}
