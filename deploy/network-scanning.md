# Network discovery through agents

The administrator console has a **Сканирование сети** section. An administrator
creates a CIDR scope, assigns an enrolled agent, selects a profile, first start
(optional, browser local time), and an interval (15 minutes–30 days). Pause,
resume, immediate start and cancellation are audited. Readers can inspect results.
An offline agent starts due work on its next successful endpoint exchange; the
server does not backfill every missed interval.

Any IPv4/IPv6 prefix length is accepted. Work is bounded to 256 unicast addresses
per assignment; larger prefixes advance a persistent cursor across scheduled
windows. Huge IPv6 ranges should be narrowed to known address scopes rather than
expected to finish enumerating. Non-unicast/link-local addresses are skipped.
Plans with no supported addresses are rejected. Only administrator-authorized
scopes are sent to agents; results outside an assignment are rejected.

## Scanner and coverage

Nmap must be installed on the assigned endpoint. The Linux installer option
`--network-scanner` installs the distribution's `nmap` package using apt/dnf/yum.
Windows agents require an administrator-installed Nmap executable in the service
PATH and its vendor-supplied dependencies. Windows execution has not been tested
on a live Windows endpoint. Missing Nmap produces an explicit failed run.

Profiles are fixed, with no user-provided command line or script paths:

* Discovery: Nmap `-sn`, no port scan.
* Services: TCP connect, 28 fixed ports, light version identification, numeric
  addresses, no DNS lookup. Open ports provide host evidence; `-Pn` alone does not.
* Vulnerabilities: services plus exactly `smb-vuln-ms17-010` and `ssl-heartbleed`.
  The broad NSE `vuln` category is deliberately not invoked. Findings labelled
  `scanner_confirmed` require structured NSE state `VULNERABLE`. Version strings
  and absence of findings do not establish whether an asset is vulnerable.

Defaults: 50 probes/second maximum, parallelism 16, one retry, 45 seconds/host,
15 seconds/script, 10 minutes/process, bounded output. Results too large for
reliable delivery fail explicitly. Discovery is affected by network filtering;
closed services and sleeping devices may not be observed. A host timeout or
invalid/incomplete XML fails the run rather than marking devices absent.

## Delivery, assets and persistence

Assignments travel in Ed25519-signed endpoint bundles. One lease per agent lasts
15 minutes; the server stores it before delivery. Agent execution is asynchronous
and does not block heartbeat or Active Response expiry. A root-private sidecar
persists the running marker and completed result; restart reports interruption
rather than silently repeating an old scan. Results are retried until exchange
acknowledges them. Cancellation reaches the agent on its next successful exchange;
the local execution deadline still limits disconnected work.

Plans, leases, bounded history (100 terminal runs) and up to 10,000 scoped assets
are stored in `control.db.endpoint.db` alongside endpoint policy state. The
network scope/plan and IP identify a network observation, not an authenticated
machine identity. First/last seen, changed services, newly discovered and
not-observed state are kept. Only a successful scan of the exact address window
can change an older asset to not observed. Failed, cancelled and unvisited windows
cannot establish absence. The map shows scope-to-asset relationships; it does not
claim physical switch/router topology. DHCP/NAT can change IP ownership.

Initial production verification uses the explicitly authorized client addresses
as `/32`; no adjacent public addresses are included.
