// SPDX-License-Identifier: Apache-2.0
package correlation

import "github.com/rkislov/cerber/internal/telemetry"

// Network evaluates only normalized, explicit actions. An allow after blocks is
// investigative evidence, not proof that an attack bypassed the WAF.
func Network(n telemetry.Normalized, previous []telemetry.Normalized) *telemetry.Detection {
	if n.Status != "parsed" || n.SourceIP == "" {
		return nil
	}
	rule, title, severity := "", "", "medium"
	if n.Class == "firewall" && n.Action == "syn" && n.DestinationIP != "" {
		ports := map[int]bool{}
		for _, p := range previous {
			if p.DestinationPort > 0 {
				ports[p.DestinationPort] = true
			}
		}
		if len(ports) < 20 {
			return nil
		}
		rule, title = "firewall.syn_scan", "TCP SYN на множество портов"
	} else if n.Class == "firewall" && n.Action == "deny" && len(previous) >= 20 {
		rule, title = "firewall.denied_burst", "Серия блокировок межсетевым экраном"
		ports := map[int]bool{}
		for _, p := range previous {
			if p.DestinationPort > 0 {
				ports[p.DestinationPort] = true
			}
		}
		if len(ports) >= 20 && n.DestinationIP != "" {
			rule, title, severity = "firewall.port_scan", "Вероятное сканирование портов", "high"
		}
	} else if n.Class == "fess" && n.Action == "deny" && len(previous) >= 10 {
		rule, title = "fess.blocked_burst", "Серия блокировок FESS WAF"
	} else if n.Class == "fess" && n.Action == "allow" && len(previous) >= 5 {
		rule, title, severity = "fess.allowed_after_blocks", "Разрешённый запрос после блокировок FESS", "high"
	}
	if rule == "" {
		return nil
	}
	evidence := []string{}
	first := n.EventTime
	present := false
	for _, p := range previous {
		evidence = append(evidence, p.ID)
		if p.EventTime.Before(first) {
			first = p.EventTime
		}
		if p.ID == n.ID {
			present = true
		}
	}
	if !present {
		evidence = append(evidence, n.ID)
	}
	return &telemetry.Detection{ID: telemetry.ID(rule, "1", n.ID), GroupKey: telemetry.ID(n.Class, n.Product, n.Device, n.DestinationIP), Rule: rule, Version: 1, AgentID: n.AgentID, AssetID: n.AssetID, SourceIP: n.SourceIP, Severity: severity, Title: title, CreatedAt: n.ReceivedAt, FirstSeen: first, LastSeen: n.EventTime, Evidence: evidence, State: "open"}
}

func NetworkCatalog() []RuleDescription {
	out := []RuleDescription{}
	for _, v := range []struct{ id, title, condition string }{
		{"firewall.syn_scan", "TCP SYN на множество портов", "Наблюдались SYN на 20 различных портов одного IP за 5 минут; это не подтверждает блокировку или успешное соединение"},
		{"firewall.denied_burst", "Серия блокировок межсетевым экраном", "20 отказов за 5 минут"},
		{"firewall.port_scan", "Вероятное сканирование портов", "Отказы на 20 различных портов одного адреса за 5 минут"},
		{"fess.blocked_burst", "Серия блокировок FESS WAF", "10 блокировок за 5 минут"},
		{"fess.allowed_after_blocks", "Разрешённый запрос после блокировок FESS", "Разрешённый запрос после 5 блокировок за 5 минут"},
	} {
		out = append(out, RuleDescription{ID: v.id, Version: 1, Title: v.title, Summary: v.title + "; требуется проверка аналитиком.", Condition: v.condition + ". Повторения ключа подавляются на 5 минут.", Scope: "Один агент, профиль, продукт, устройство, IP источника и назначение (IP для МЭ, виртуальный хост для WAF).", Limitations: "CEF с явно заданным профилем либо распознанные сообщения ядра netfilter. Префиксы CERBER_IPT/NFT требуют согласованного правила LOG + verdict. До 100 последних обработанных отказов. Поздние события не пересчитываются. Разрешение запроса не доказывает обход защиты; NAT может объединять пользователей. Достоверность полей зависит от доверия к отправителю.", FalsePositives: []string{"Разрешённый сканер", "Общий NAT", "Неверная конфигурация приложения"}, Investigation: []string{"Проверьте исходные CEF и временное окно", "Сопоставьте IP, назначение и согласованные работы", "Для WAF сравните requestId, URI и результат обработки в FESS"}})
	}
	return out
}
