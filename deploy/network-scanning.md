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
* Vulnerabilities: services plus the five allowlisted probes listed below.
  The broad NSE `vuln` category is deliberately not invoked. Findings labelled
  `scanner_confirmed` require structured NSE state `VULNERABLE`. Version strings
  and absence of findings do not establish whether an asset is vulnerable.

Defaults: 50 probes/second maximum, parallelism 16, one retry, 90 seconds/host,
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

## Central BDU/CVE matching

The server maintains `control.db.endpoint.db.vuln.db` (SQLite WAL, private file).
BDU is a full daily import from `https://bdu.fstec.ru/files/documents/vulxml.zip`:
64 MiB archive / 1 GiB XML / 300,000 record limits. The streaming importer replaces
records, software ranges and CVE cross-references in one transaction. A failed
import preserves the previous snapshot. The console shows freshness, record count,
background activity and source failures; administrators can request a refresh.

NVD API 2.0 is queried centrally for concrete application CPE names observed by
Nmap, with `isVulnerable`; results are cached daily. Requests send CPE product and
version identifiers, never target IPs. Six seconds separate requests, pagination
is bounded, failures preserve the older cache and retry after 15 minutes. No NVD
API key is required. This is an observed-product cache, not a full NVD mirror.

BDU software aliases are deliberately reviewed: OpenSSH, nginx, Apache HTTP
Server, Postfix, Dovecot, MySQL, MariaDB, PostgreSQL, Samba, OpenSSL. Only supported
numeric versions and OpenSSH `p` revisions, exact versions and explicit Russian
`до` / `от ... до` ranges are evaluated. Unsupported version expressions are
skipped. CPE URI application names are converted to concrete CPE 2.3 identities;
missing versions, OS guesses and unknown vendor/product aliases do not establish
an affected service. NVD matching extends product coverage beyond those aliases.
BDU records are joined to NVD candidates by CVE, avoiding duplicate findings.

Every banner/catalog match is **version_candidate**, with port, CPE, range or
NVD basis, source link, CVSS score/vector and severity. A backported distribution
fix, runtime setting or prerequisite can invalidate a banner match. Only an NSE
probe's structured `VULNERABLE` state establishes **scanner_confirmed**. A missing
score is displayed as unknown. A stale cached NVD match is visibly marked.
Map colors summarize candidate severity as well as confirmed findings; they are
not a claim that exploitation succeeded. Detailed records are in each asset card.

The fixed probe list now also includes `ssl-poodle`, `ssl-ccs-injection`, and
`http-vuln-cve2015-1635`, all documented in Nmap's safe/vuln categories. No arbitrary
NSE script/category is accepted. These five probes are a bounded starting catalog,
not complete vulnerability coverage.

For the FSTEC site's Russian certificate chain, set `CERBER_BDU_CA` to an
operator-provided PEM bundle. It augments trust **only for BDU downloads**, while
certificate and hostname verification remain enabled. The deployment uses the
Russian Trusted Root CA downloaded over verified HTTPS from the government
certificate distribution service and its 2024 issuing certificate, whose signature
was verified against that root. No global OS trust changes are needed. In a
scratch image, copy that bundle into the image and pass the environment variable.

When Nmap supplies an unversioned application CPE and a separate concrete service
version, the version can complete that identity. Name-only fallback identities
are restricted to reviewed OpenSSH and Apache HTTP Server aliases. Ambiguous
versions containing distribution prose are not normalized into upstream versions.

NVD applicability trees are retained in readable form: version bounds, additional
AND/environment requirements, negation and constrained CPE attributes. An
unsupported range, unconstrained product version or explicit client-only record
is labelled **context_required**, rather than a verified server vulnerability.
Known comparable fixed-version boundaries are excluded locally as well as through
NVD filtering. Both candidate classes remain separate from NSE confirmation.
