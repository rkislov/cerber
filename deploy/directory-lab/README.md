# Каталог AD для проверки LDAPS

Образ собирает Samba AD DC из пакетов Debian 13 с обновлениями безопасности:

```sh
docker build -t cerber-directory-lab:local deploy/directory-lab
```

Домен стенда: `SIEMLAB` / `siem.lab.internal`, Base DN
`DC=siem,DC=lab,DC=internal`. Храните каталог данных и секреты вне репозитория.
В `/run/directory-secrets` контейнеру нужны read-only файлы:

- `credentials.json`: случайные уникальные пароли для `administrator`,
  `cerber-reader`, `alice`, `bob`, `disabled-user` (ключи JSON — эти имена);
- `ca.pem`, `server.pem`, `server.key`: CA и серверный сертификат с EKU
  serverAuth и SAN `127.0.0.1`, `localhost`, `dc-siem-lab.siem.lab.internal`.

Пример запуска после подготовки этих файлов:

```sh
docker network create cerber-directory-lab
docker run -d --name cerber-directory-lab --hostname dc-siem-lab \
  --restart unless-stopped --network cerber-directory-lab \
  -p 127.0.0.1:10636:636 --memory 384m --cpus 0.5 --pids-limit 128 \
  --security-opt no-new-privileges \
  --log-opt max-size=10m --log-opt max-file=2 \
  --tmpfs /tmp:rw,nosuid,size=64m --tmpfs /run/samba:rw,nosuid,size=16m \
  -v /absolute/private/lab/data:/var/lib/samba \
  -v /absolute/private/lab/secrets:/run/directory-secrets:ro \
  cerber-directory-lab:local
```

Никакие доменные DNS/Kerberos/SMB-порты на хосте не публикуются. Для SIEM,
работающего с host networking на этом же сервере, URL:
`ldaps://127.0.0.1:10636`, Bind UPN: `cerber-reader@siem.lab.internal`.
В настройках доверенного CA укажите `ca.pem`. Служебный пользователь — обычный
Domain Users, без административных групп. `disabled-user` отключён для проверки
отказов. Владелец TLS private key внутри контейнера — root, права 0600.

Инициализация пропускает SYSVOL ACL: это LDAP-стенд для проверки сопоставления
имён, а не домен для присоединения рабочих компьютеров или распространения GPO.
Сохранённые данные переживают пересоздание контейнера; пароли задаются при первом
создании пользователей. Сертификаты необходимо продлевать до окончания срока.
Никакие тестовые инциденты в рабочей БД SIEM для этого стенда не требуются.
