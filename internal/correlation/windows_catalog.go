// SPDX-License-Identifier: Apache-2.0
package correlation

func WindowsFlowCatalog() []RuleDescription {
	out := []RuleDescription{}
	for _, r := range []struct{ id, title, condition string }{
		{"chain.kerberos_logon", "Kerberos-билет и последующий сетевой вход", "4769 с успешным Status=0x0 предшествует 4624 типа 3/10 на другом агенте/активе. Ненулевой LogonGuid и точное доменное имя целевой учётной записи совпадают."},
		{"chain.explicit_credentials_logon", "Явное использование реквизитов и последующий сетевой вход", "4648 на одном узле предшествует 4624 типа 3/10 на другом. TargetLogonGuid 4648 равен LogonGuid входа, точное доменное имя целевых реквизитов совпадает. Subject LogonGuid не заменяет TargetLogonGuid."},
	} {
		out = append(out, RuleDescription{ID: r.id, Version: 1, Title: r.title, Summary: "Наблюдаемая связь доменной авторизации; штатные SSO, RunAs и задачи не исключены.", Condition: r.condition, Scope: "По умолчанию минимум 2 узла, окно 15 минут, подавление по SID целевого входа и его агенту 15 минут. При наличии добавляются 4648, успешный 4769 и локальный сеанс инициатора 4624 с тем же SID/Logon ID внутри одного агента и актива. Все участники проходят группы и исключения.", Limitations: "4769 не содержит SID пользователя: ServiceSid не присваивается пользователю. 4648 — попытка использования реквизитов, не подтверждение успешного входа. GUID нулевой/отсутствующий или разное точное имя/realm не объединяются; DNS/NetBIOS-алиасы без каталога не угадываются. Использование именно этого билета и принадлежность службы конечному узлу не доказаны. До 100 записей 4648 + 100 записей 4769 + один локальный сеанс / 8 МиБ; максимум 4 события в цепочке. Только уже обработанные события в окне, архивы и поздние записи не переигрываются. Порог настраивается от 2 до 3 узлов. Автоматического AR нет.", FalsePositives: []string{"Штатный Kerberos SSO", "RunAs, задачи планировщика, администрирование"}, Investigation: []string{"Разделите инициатора 4648 и учётную запись используемых реквизитов", "Проверьте TargetLogonGuid, LogonGuid, точный realm и Status билета", "Изучите ServiceName/ServiceSid, процесс и исходные события всех узлов"}, References: []string{"https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4648", "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4769"}})
	}
	return out
}
