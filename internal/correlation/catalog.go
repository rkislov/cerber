// SPDX-License-Identifier: Apache-2.0
package correlation

import "github.com/rkislov/cerber/internal/telemetry"

type RuleDescription struct {
	ID             string   `json:"id"`
	Version        int      `json:"version"`
	Title          string   `json:"title"`
	Summary        string   `json:"summary"`
	Condition      string   `json:"condition"`
	Scope          string   `json:"scope"`
	Limitations    string   `json:"limitations"`
	FalsePositives []string `json:"false_positives"`
	Investigation  []string `json:"investigation"`
	References     []string `json:"references"`
}

func Catalog() []RuleDescription {
	return append(NetworkCatalog(), []RuleDescription{
		{ID: "threatfox.ip_match", Version: 1, Title: "IP совпал с ThreatFox без подтверждения порта", Summary: "IP события совпал с адресной частью IOC ip:port. Порт не совпал или отсутствует.", Condition: "Совпадение IP источника или назначения с актуальным IOC ip:port, без точного совпадения порта назначения.", Scope: "Нормализованные IP-адреса.", Limitations: "Порт не подтверждён; средняя важность. Это сигнал для проверки, а не доказательство соединения с вредоносной службой.", References: []string{"https://threatfox.abuse.ch/"}},
		{ID: "threatfox.ioc_match", Version: 1, Title: "Совпадение с IOC ThreatFox", Summary: "Структурированный адрес или URL события совпал с актуальным индикатором ThreatFox.", Condition: "Точное совпадение IP, IP:port назначения, домена URL или URL. Время события не ранее first_seen и не позднее last_seen + 6 месяцев.", Scope: "Все сохранённые нормализованные события; после обновления полного набора выполняется повторная проверка.", Limitations: "IP:port требует порт назначения; исходный порт и хеши файлов пока не нормализуются. Совпадение не доказывает компрометацию. События в архиве не пересчитываются автоматически.", FalsePositives: []string{"Повторное назначение IP, NAT, разрешённое исследование"}, Investigation: []string{"Проверьте исходное событие, IOC ID, направление и назначение соединения; уточните индикатор на ThreatFox"}, References: []string{"https://threatfox.abuse.ch/"}},
		{ID: "auth.repeated_failures", Version: 1, Title: "Серия неудачных входов", Summary: "Наблюдались повторные отказы входа. Возможны подбор пароля, ошибка пользователя или устаревшие учётные данные службы.", Condition: "Не менее 5 отказов за 5 минут. Повторные срабатывания того же ключа подавляются на 5 минут.", Scope: "Один агент + нормализованный пользователь + IP источника. Windows Security 4625 или распознанный отказ OpenSSH.", Limitations: "Время окна берётся из события. Нет межхостового объединения; без пользователя или IP правило не срабатывает. Поздние события не вызывают пересчёт уже обработанных входов; доказательства ограничены 100 отказами плюс текущая запись.", FalsePositives: []string{"Несколько опечаток пользователя", "Служба или задача использует старый пароль", "Разрешённая проверка защищённости"}, Investigation: []string{"Откройте исходные события и проверьте пользователя, IP и время", "Сопоставьте IP с узлом/сетевым шлюзом; исключите общий адрес NAT", "Уточните у владельца узла, ожидались ли попытки; проверьте последующие успешные входы"}, References: []string{"https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4625"}},
		{ID: "auth.success_after_failures", Version: 1, Title: "Успешный вход после серии отказов", Summary: "После серии отказов зафиксирован успешный вход с теми же пользователем и IP на том же агенте. Само по себе это не доказывает компрометацию.", Condition: "Успешный вход и минимум 5 ранее обработанных отказов в предшествующие 5 минут по времени событий.", Scope: "Один агент + пользователь + IP. Windows Security 4624/4625 или распознанные сообщения OpenSSH.", Limitations: "Учитываются доступные к моменту обработки события; поздние отказы задним числом не пересчитывают успешный вход. Ключ без IP/пользователя не анализируется. Срабатывание не означает наличие уязвимости БДУ.", FalsePositives: []string{"Пользователь вспомнил или сменил пароль", "Исправлены реквизиты службы", "Разрешённый тест доступа"}, Investigation: []string{"Проверьте исходник успешного входа и связанные отказы", "Уточните, разрешён ли пользователь и источник; проверьте тип входа в исходнике Windows", "Изучите дальнейшие действия учётной записи и примените принятый в организации порядок реагирования"}, References: []string{"https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4624"}},
		{ID: "windows.audit_log_cleared", Version: 1, Title: "Очищен журнал аудита Windows", Summary: "Получено событие Security 1102 от провайдера Microsoft-Windows-Security-Auditing. Очистка могла быть административной операцией либо попыткой скрыть активность.", Condition: "Одно событие Security 1102; временной порог не требуется.", Scope: "Агент Windows и канал Security. Состояние пользователя и адрес источника уточняются по исходнику.", Limitations: "Правило видит только доставленное событие, а не полную историю журнала до очистки. Потеря/очистка недоставленных записей не восстанавливается автоматически.", FalsePositives: []string{"Плановое обслуживание журнала", "Подготовка тестового стенда"}, Investigation: []string{"Откройте исходную запись и определите инициатора операции", "Сопоставьте время с согласованными административными работами", "Проверьте соседние журналы, архивы и доступность событий до очистки"}, References: []string{"https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-1102"}},
	}...)
}
func Describe(id string, version int) (RuleDescription, error) {
	for _, r := range Catalog() {
		if r.ID == id && r.Version == version {
			return r, nil
		}
	}
	return RuleDescription{}, telemetry.ErrNotFound
}
