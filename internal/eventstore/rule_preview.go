// SPDX-License-Identifier: Apache-2.0
package eventstore

import (
	"context"
	"database/sql"
	"encoding/json"
	"github.com/rkislov/cerber/internal/correlation"
	"github.com/rkislov/cerber/internal/integrations"
	"github.com/rkislov/cerber/internal/rulepolicy"
	"github.com/rkislov/cerber/internal/rulepreview"
	"github.com/rkislov/cerber/internal/telemetry"
	"sort"
	"time"
)

type RulePreviewRequest = rulepreview.Request
type RulePreview = rulepreview.Result
type RulePreviewRow = rulepreview.Row

// PreviewRule shares evaluation with live processing but has no write or
// notification sink. Suppression is simulated only among selected test events.
func (s *Store) PreviewRule(ctx context.Context, req RulePreviewRequest, index *integrations.Index, iocRevision string) (RulePreview, error) {
	out := RulePreview{DryRun: true, At: time.Now().UTC(), Rows: []RulePreviewRow{}, Limitations: "Изолированная проверка: боевые срабатывания, курсоры, уведомления и active response не изменяются. История берётся из оперативного журнала до выбранной последовательности; архивы не читаются. До 100 записей / 8 МиБ истории в окне и 200 результатов; текущий состав групп и текущий набор IOC. Подавление моделируется только между выбранными событиями, без учёта уже созданных боевых срабатываний. Более специфичное правило сканирования портов имеет приоритет над серией блокировок."}
	cfg, e := rulepolicy.Canonical(req.Rule, req.Config)
	if e != nil || len(req.EventIDs) < 1 || len(req.EventIDs) > 100 {
		return out, rulepolicy.ErrInvalid
	}
	if rulepolicy.Single(req.Rule) && req.Rule != "windows.audit_log_cleared" && index == nil {
		return out, rulepolicy.ErrNotFound
	}
	out.Policy = cfg
	if correlation.ChainRule(req.Rule) {
		out.Limitations = "Изолированная межузловая проверка: срабатывания, курсоры, уведомления и active response не изменяются. До 100 выбранных событий, 200 записей / 8 МиБ истории на опорное событие, 20 узлов плюс очистка аудита в цепочке. История берётся из оперативного журнала до выбранной последовательности; архивы не читаются. Каждый участник проходит группы и исключения; используется текущий состав групп. Только явный SID/Logon GUID/SSH-отпечаток, имена и IP не объединяют узлы. Подавление моделируется между выбранными результатами по общему ключу, без уже созданных боевых срабатываний. Это последовательность наблюдений, не доказательство атаки."
	}
	if correlation.WindowsFlowRule(req.Rule) {
		out.Limitations = "Проверка Windows-flow без записи срабатываний, уведомлений, курсоров и AR. До 100 событий 4648 + 100 событий 4769 + один локальный сеанс / 8 МиБ истории. Проверяется ненулевой TargetLogonGuid/LogonGuid и точное доменное имя либо текущая проверка AD/LDAPS по SID/objectGUID; роли инициатора и целевых реквизитов разделены. Только уже обработанные события оперативного журнала в окне; архивы не читаются. Все участники проходят текущие группы и исключения. Подавление моделируется только между выбранными результатами."
	}
	if correlation.WindowsFlowRule(req.Rule) {
		if e = s.prepareDirectory(ctx, req.EventIDs...); e != nil {
			return out, e
		}
	}
	out.IOCRevision = iocRevision
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	tx, e := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if e != nil {
		return out, e
	}
	defer tx.Rollback()
	policies, e := loadRulePolicies(ctx, tx)
	if e != nil {
		return out, e
	}
	version := policies[req.Rule]
	out.ActiveRevision = version.Revision
	version.Config = cfg
	version.Revision = 0
	policies[req.Rule] = version
	r := ruleRuntime{store: s, policies: policies, members: map[string][]string{}}
	events := []telemetry.Normalized{}
	inputBytes := 0
	seen := map[string]bool{}
	for _, id := range req.EventIDs {
		if !telemetry.Identifier(id) || seen[id] {
			return out, rulepolicy.ErrInvalid
		}
		seen[id] = true
		var p string
		e = tx.QueryRowContext(ctx, "SELECT payload FROM normalized_events WHERE id=?", id).Scan(&p)
		if e == sql.ErrNoRows {
			return out, rulepolicy.ErrNotFound
		}
		if e != nil {
			return out, e
		}
		inputBytes += len(p)
		if inputBytes > 8<<20 {
			return out, rulepolicy.ErrInvalid
		}
		var n telemetry.Normalized
		if e = json.Unmarshal([]byte(p), &n); e != nil {
			return out, e
		}
		events = append(events, n)
	}
	sort.Slice(events, func(i, j int) bool { return events[i].Sequence < events[j].Sequence })
	prior := []telemetry.Detection{}
	totalFindings := 0
	for _, n := range events {
		row := RulePreviewRow{EventID: n.ID, Sequence: n.Sequence, Findings: []telemetry.Detection{}}
		groups, e := r.groups(ctx, req.Rule, n)
		if e != nil {
			return out, e
		}
		matched, reason := rulepolicy.ScopeEvent(cfg, n.AgentID, n.User, n.SourceIP, n.DestinationIP, groups)
		row.Reason = reason
		if n.Status != "parsed" {
			row.Reason = "Событие не разобрано или находится в карантине"
		} else if reason == "" {
			if req.Rule == "threatfox.ip_match" || req.Rule == "threatfox.ioc_match" {
				for _, d := range index.MatchForRule(n, req.Rule, 201) {
					if d.Rule == req.Rule {
						if totalFindings >= 200 {
							out.Truncated = true
							break
						}
						totalFindings++
						d.Policy = rulepolicy.Application(version, matched)
						row.Findings = append(row.Findings, d)
					}
				}
				row.Reason = "Совпадений с текущим набором IOC нет"
			} else {
				var d *telemetry.Detection
				var why string
				var truncated bool
				var e error
				if correlation.ChainRule(req.Rule) {
					d, why, truncated, e = r.evaluateChain(ctx, tx, req.Rule, n)
				} else {
					d, why, truncated, e = r.evaluate(ctx, tx, n)
				}
				if e != nil {
					return out, e
				}
				row.HistoryTruncated = truncated
				row.Reason = why
				if d != nil {
					if d.Rule == req.Rule {
						row.Findings = append(row.Findings, *d)
					} else {
						row.Reason = "Событие соответствует другому или более специфичному правилу: " + d.Rule
					}
				}
			}
			if len(row.Findings) > 0 && cfg.SuppressionSeconds > 0 {
				filtered := []telemetry.Detection{}
				for _, d := range row.Findings {
					suppressed := false
					for _, p := range prior {
						delta := d.LastSeen.Sub(p.LastSeen)
						if delta < 0 {
							delta = -delta
						}
						if p.Rule == d.Rule && (correlation.ChainRule(d.Rule) || p.AgentID == d.AgentID && p.User == d.User && p.SourceIP == d.SourceIP) && p.GroupKey == d.GroupKey && delta <= time.Duration(cfg.SuppressionSeconds)*time.Second {
							suppressed = true
							break
						}
					}
					if !suppressed {
						filtered = append(filtered, d)
						prior = append(prior, d)
					}
				}
				if len(filtered) == 0 {
					row.Reason = "Повтор подавлен другим результатом в этой изолированной проверке"
				}
				row.Findings = filtered
			}
			if len(row.Findings) > 0 {
				row.Reason = "Условия выполнены; в боевом режиме дополнительно учитывается подавление существующими срабатываниями"
			}
		}
		out.Rows = append(out.Rows, row)
	}
	return out, tx.Commit()
}
