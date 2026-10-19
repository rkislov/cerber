# Установка службы Windows

Используйте x86_64-бинарник и повышенную PowerShell. Установщик регистрирует `CerberAgent`
с отложенным автоматическим запуском под `NT AUTHORITY\LocalService`. Доступ к секретам
и БД выдаётся SID этой службы (`NT SERVICE\CerberAgent`), а не всем процессам LocalService.
Права администратора нужны для установки и управления службой, не для её обычной работы.

Подготовьте фиксированные каталоги и локальный актив:

```powershell
New-Item -ItemType Directory -Force C:\ProgramData\Cerber\config,C:\ProgramData\Cerber\state
.\bin\cerber.exe -db C:\ProgramData\Cerber\state\agent.db asset add -ip 127.0.0.1 -name this-machine
```

Скопируйте выданные сервером учётные данные в
`C:\ProgramData\Cerber\config\credentials.json`, CA — в `organization-ca.pem` в том же каталоге.
Скопируйте `agent.example.json` в `C:\ProgramData\Cerber\config\agent.json`, укажите адрес SIEM
и **локальный** ID актива из предыдущей команды. Если сертификат уже доверен службе в системном
хранилище, поле `ca_cert` можно удалить. Доверие из пользовательского хранилища текущего
администратора может быть недоступно LocalService.

До передачи секретов убедитесь, что подготовленные каталоги не доступны для записи/чтения
посторонним; установщик затем задаёт закрытые ACL. Конфиг, токен и CA должны находиться внутри
`config`, БД — внутри `state`. Установщик не следует junction/symlink внутри управляемых деревьев.

```powershell
.\bin\cerber.exe agent validate-config -config C:\ProgramData\Cerber\config\agent.json
.\deploy\windows\Install-CerberAgent.ps1 -Binary .\bin\cerber.exe
Start-Service CerberAgent
Get-Service CerberAgent
Get-WinEvent -FilterHashtable @{LogName='Application';ProviderName='CerberAgent'} -MaxEvents 20
```

Установщик копирует бинарник в `C:\Program Files\Cerber\cerber.exe`, ограничивает ACL,
создаёт источник журнала Application и настраивает восстановление после сбоя через 30/60/300
секунд. Служба не запускается установщиком; выполните `Start-Service` после проверки настроек.
`Running` означает работу процесса, не подтверждение связи с SIEM: проверяйте журнал и данные
на сервере. Токен не передаётся через командную строку и не пишется в журнал.

SCM Stop/Shutdown отменяет текущий сбор/передачу. Служба сообщает StopPending и контрольные
точки до завершения, при этом неподтверждённая очередь остаётся в БД. При зависании остановки
после 30 секунд процесс завершится с ошибкой; SQLite/WAL восстановит подтверждённые транзакции
при следующем старте. Служба не принимает Pause/Continue.

```powershell
Stop-Service CerberAgent
Restart-Service CerberAgent
```

Ограниченная учётная запись может не прочитать optional features и другие защищённые разделы;
они сохраняют статус ошибки/частичного покрытия. HKCU отражает профиль служебной учётной записи,
а не интерактивного пользователя. Онлайн-поиск WUA/WSUS включается явно через
`check_windows_updates`; его доступность и сетевые политики нужно проверить на стенде.
Политики Windows Update, ExecutionPolicy, firewall и доверенные сертификаты установщик не меняет.

Для удаления регистрации остановите службу и выполните:

```powershell
.\deploy\windows\Uninstall-CerberAgent.ps1
```

Бинарник, БД, очередь, конфиги и журнал остаются. Для обновления: удалите регистрацию этим
скриптом, сохраните прежний бинарник, запустите установщик с новым бинарником и снова стартуйте
службу. Не запускайте консольный агент одновременно со службой на той же БД.
