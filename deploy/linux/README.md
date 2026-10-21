# Установка службы Linux

Нужны systemd и готовый бинарник Cerber для архитектуры узла. Пакеты APT/RPM должны
читаться выбранной учётной записью. Ниже команды выполняются оператором с sudo.
Токен агента предварительно выпускается на SIEM через `siem enroll`.

```sh
sudo useradd --system --user-group --home-dir /var/lib/cerber --no-create-home --shell /usr/sbin/nologin cerber
sudo install -d -m 0755 /opt/cerber
sudo install -m 0755 ./bin/cerber /opt/cerber/cerber
sudo install -d -o root -g cerber -m 0750 /etc/cerber
sudo install -d -o cerber -g cerber -m 0700 /var/lib/cerber
sudo install -o root -g cerber -m 0640 /secure/path/agent-credentials.json /etc/cerber/credentials.json
sudo install -o root -g cerber -m 0640 /secure/path/organization-ca.pem /etc/cerber/organization-ca.pem
sudo -u cerber /opt/cerber/cerber -db /var/lib/cerber/agent.db asset add -ip 127.0.0.1 -name this-machine
```

Запомните локальный `id` из последней команды. Скопируйте `agent.example.json`,
замените `asset_id` и адрес SIEM. Это ID из локальной БД, не ID актива на сервере.
Если используется системный доверенный сертификат, удалите поле `ca_cert`.
Сохраните готовый конфиг в `/etc/cerber/agent.json` с владельцем `root:cerber`, режимом 0640.
Не кладите токен в конфиг — он уже в отдельном `credentials.json`.

```sh
sudo -u cerber /opt/cerber/cerber agent validate-config -config /etc/cerber/agent.json
sudo install -m 0644 deploy/linux/cerber-agent.service /etc/systemd/system/cerber-agent.service
sudo systemd-analyze verify /etc/systemd/system/cerber-agent.service
sudo systemctl daemon-reload
sudo systemctl enable --now cerber-agent
sudo systemctl status cerber-agent
sudo journalctl -u cerber-agent -f
```

Валидация проверяет JSON, абсолютные пути, токен и CA без обращения к сети и без
открытия/изменения БД. Наличие нужного локального актива проверяется при сборе.
Установка не меняет источники пакетов и доверенные ключи. Служба работает без root,
с доступом на запись только к `/var/lib/cerber`; конфиги и бинарник доступны ей для чтения.
`ProtectHome` скрывает пользовательские домашние каталоги: связанные с ними источники
инвентаря/репозитории могут оказаться недоступны и будут отражены в покрытии.

Оставьте `refresh_package_metadata=false`: обновление системного кеша APT/RPM обычно
нуждается в иных правах. Обновляйте кеш штатными средствами ОС. Автоматически повышать
права агента для этого не следует; сам Cerber sudo не запускает.

Остановка/перезапуск:

```sh
sudo systemctl stop cerber-agent
sudo systemctl restart cerber-agent
```

SIGTERM отменяет сбор и HTTP-запрос, неподтверждённые отчёты сохраняются. При сбое
процесса systemd повторяет запуск через 30 секунд, с ограничением частоты рестартов.
После изменения JSON перезапустите службу. Перед заменой бинарника остановите её,
сохраните прежнюю версию, установите новый бинарник и выполните старт/проверку журнала.
Не используйте одну БД одновременно для нескольких экземпляров агента.

Удаление службы сохраняет конфиги, секреты и историю:

```sh
sudo systemctl disable --now cerber-agent
sudo rm /etc/systemd/system/cerber-agent.service
sudo systemctl daemon-reload
```

Эти инструкции подходят для систем с systemd. Astra Linux, РЕД ОС и Альт требуют
проверки на конкретной редакции, включая SELinux/мандатные политики, доступ к пакетной
базе и настройку репозиториев; политики безопасности установщик не отключает.

Heartbeat отправляется независимо от сбора, по умолчанию раз в минуту. Необязательное поле
`heartbeat_interval` задаёт 1m–1h; после его изменения перезапустите службу. На SIEM
проверяйте `cerber -db ... siem agents`: недавний контакт и свежесть инвентаря оцениваются
раздельно. Порог offline задаётся при чтении и должен превышать интервал heartbeat с запасом.

## Установщик и полные системные права

```sh
sudo ./deploy/linux/Install-CerberAgent.sh --binary ./bin/cerber \
  --config /secure/agent.json --credentials /secure/credentials.json --start
```

При новом узле вместо `--config` можно передать `--server https://siem.example`,
`--address 192.0.2.10`, `--name workstation`: установщик создаст локальный актив и конфиг.
Для закрытого CA сначала подготовьте конфиг и CA в `/etc/cerber`.
Фиксированные пути: `/opt/cerber/cerber`, `/etc/cerber/agent.json`, `/var/lib/cerber/agent.db`.
На обновлении сохраняются актив, очереди и курсоры. Существующую службу установщик
останавливает; `--start` включает её после проверки. Копии конфигурации и бинарника
сохраняются в приватном `install-backups`; резервную копию всей БД делайте отдельно.
Нужны systemd, Python 3; для привилегированного режима также sudo/visudo.

```sh
sudo ./deploy/linux/Install-CerberAgent.sh --binary ./bin/cerber \
  --config /etc/cerber/agent.json --privileged --refresh-metadata --start
```

`--privileged` добавляет cerber в sudo/wheel и создаёт проверенный visudo файл:
NOPASSWD разрешён только для точной команды запуска root-owned агента с root-owned
фиксированным конфигом. Сам процесс агента получает UID 0 и полный доступ к ОС;
защитные ограничения записи стандартного unit для этого режима снимаются drop-in.
Произвольные команды sudo от имени cerber этим правилом не разрешаются.
`--refresh-metadata` включает обновление кеша APT/RPM перед проверкой (пакеты не устанавливает).
Без `--privileged` установщик удаляет свой sudoers/drop-in и возвращает обычную службу;
при понижении прав также отключите `refresh_package_metadata` в конфиге.
Права процесса передаются heartbeat и видны в карточке узла. Это сведения агента,
а не дистанционное доказательство целостности. Подписанный patch executor остаётся
отдельным модулем; установка обновлений не включается автоматически.

Полные права не меняют покрытие адаптеров: portable/Flatpak/Snap и история транзакций
пакетов пока не собираются; `updates_available=partial` отражает границы модели
доступности обновлений, даже если обновление метаданных выполнено успешно.

## Журналирование МЭ без изменения решений о доступе

```sh
sudo ./deploy/linux/Configure-FirewallLogging.py --backend nft
sudo ./deploy/linux/Configure-FirewallLogging.py --backend iptables --ufw-level medium
```

Нужны установленные nft/iptables и Python 3. Установщик не включает ufw/nftables.service
и не сбрасывает существующий ruleset. Создаётся отдельная служба
`cerber-firewall-logging`: для nft — таблица `inet cerber_observe` с LOG-only input-hook,
для iptables — цепочки LOG-only с неявным RETURN. Матч — входящий TCP SYN;
ограничение 10 записей/секунду, burst 40. Отдельная nft base chain с policy accept
не отменяет DROP/REJECT других chains. Префиксы `CERBER_NFT_SYN`/`CERBER_IPT_SYN`
означают наблюдение, не разрешение/отказ. При 20 различных портах за 5 минут
срабатывает `firewall.syn_scan`; scope и подавление те же, что у сетевых правил.

`--ufw-level` меняет только уровень журналирования UFW, сохраняя активность/неактивность.
Выключенный UFW не генерирует свои блокировки: его включение изменяет доступ и должно
планироваться отдельно. При активном UFW штатные `[UFW BLOCK]` обрабатываются агентом.

Для простого существующего правила OUTPUT DROP TCP RST можно добавить зеркальный LOG:

```sh
sudo ./deploy/linux/Configure-FirewallLogging.py --backend iptables \
  --drop-output-address 192.0.2.1/32 --drop-output-port 12345
```

Установщик проверяет наличие точного DROP перед добавлением LOG; исходный DROP не меняется.
Не используйте это для stateful/изменяемых матчей. При удалении исходного DROP уберите
и настройку зеркала, чтобы наблюдение не считалось отказом. Снимки до/после находятся
в `firewall-backups`. Служба при остановке удаляет только свои jumps/chains/table;
никаких `flush ruleset`, policy ACCEPT/DROP или восстановления целого чужого ruleset нет.
Не запускайте второй экземпляр или другой менеджер, управляющий этими именами.
