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
