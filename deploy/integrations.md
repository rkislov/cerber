# SMTP and ThreatFox settings

The named administrator console exposes **Настройки**. Operators, analysts, viewers and legacy bootstrap sessions cannot read or change integration settings. POST requests use the console's existing origin and CSRF checks.

Start the SIEM with both `-settings-file /state/integrations.json` and `-settings-key /run/integrations.key`. Create the key once from 32 cryptographically random bytes, restrict it to the service account (0600), and mount it read-only separately from state. Keep a protected backup of the key separately from encrypted state backups; losing it prevents decryption. No schema migration is required.

The settings file is encrypted and authenticated with AES-256-GCM and replaced atomically. The browser receives only secret-presence flags. Blank password/key inputs preserve saved secrets; explicit deletion is separate. Concurrent edits are rejected by version. The encrypted history records the last 1,000 changes, with actor, time and changed sections, without secret values.

SMTP supports verified TLS or mandatory STARTTLS and optional PLAIN authentication after TLS. The connection test does not submit MAIL, RCPT or DATA and sends no email. ThreatFox checks the saved Auth-Key against the fixed official API endpoint using the `types` query; redirects are rejected. Tests use saved settings, so save edits first. The feature provides settings and connectivity checks; automatic email notifications and IOC synchronization/matching are not enabled by this change.

The overview also exposes authenticated `/admin/api/system` snapshots, cached for five seconds. Linux reports process CPU (100% equals one CPU core), host load average, memory usage/limit for cgroups when available (otherwise host memory), and available disk space on the database volume. Other platforms report unavailable resource counters. Database probes read `PRAGMA user_version` with a one-second deadline; they check read availability, not integrity or write readiness. Sizes include a separate WAL measurement. Failed probes remain visible independently of the inventory overview.
