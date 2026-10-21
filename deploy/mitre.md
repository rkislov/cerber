# MITRE ATT&CK and consequence assessments

**События и корреляции** provides a **MITRE и последствия** action for events and
detections, plus a summary of associations on the current detection page. The same
action is available on linked incident detections and vulnerability records in
network asset cards. CWE identifiers imported from BDU/NVD link to MITRE's weakness
catalog. CVSS continues to express vulnerability severity; ATT&CK is a taxonomy of
adversary goals/behaviors, not a numeric severity or attack-probability scale.

## Provenance and mapping version

`internal/attack/catalog.json` is a reviewed subset of active Enterprise techniques
from MITRE's official `mitre-attack/attack-stix-data` repository, retrieved
2026-10-21. It contains source SHA-256, technique versions, modification dates,
URLs and tactic identities. Technique metadata and ATT&CK names are attributed to
The MITRE Corporation. See [MITRE legal and branding information](https://attack.mitre.org/resources/legal-and-branding/).
The application code's Apache-2.0 license does not assert ownership of MITRE's
names or metadata. `/admin/api/mitre` exposes this versioned, authenticated subset;
it is not a claim to implement the complete ATT&CK matrix or every CVE mapping.

Associations are authored by Cerber, not official MITRE endorsements of these
particular rules or CVEs. Mapping version: `cerber-mitre/1@2026-10-21`. Current
metadata uses **T1685.005 / TA0112** for clearing Windows event logs, rather than
silently assigning the retired T1070.001 identity. Changes to these mappings
require source review and tests; there is no runtime dependence on MITRE servers.

## Evidence boundaries

* Repeated login failures: T1110.001 as a password-guessing hypothesis. A single
  failed login does not establish brute force.
* Success after failures: conditional T1110.001 and T1078. Successful authentication
  is observed; theft/abuse of credentials is not established.
* Windows Security 1102: observed log-clearing operation, conditional T1685.005.
  Legitimate maintenance remains possible.
* Port/SYN scan correlations: alternative T1046 (internal discovery) / T1595
  (external reconnaissance) associations. Source position and authorization must
  be checked; the service scan does not establish successful exploitation.
* Generic deny/allow WAF/firewall events and ThreatFox IOC matches do not receive
  a guessed exploit/C2/exfiltration technique. They retain explanatory effects and
  investigative next steps.

Historical normalized events/detections are annotated at read time without
rewriting evidence or changing IDs, severity, acknowledgements or retention.
Incident-linked detections use the same mapping. Unknown rule IDs/versions have
no automatic association. Page counters count associations, not confirmed attack
stages or total historical coverage. Authorized vulnerability scans can produce
scan correlations; analysts must check scheduled scanner activity.

## Vulnerabilities and possible effects

CIA effects are read from structured CVSS v2/v3/v4 vectors, including v4 subsequent
system metrics. This is potential source-described impact **if applicable and
exploited**, not a prediction that the effect occurred. Confidentiality impact
does not by itself establish exfiltration, and availability impact does not by
itself establish an observed DoS technique.

A deliberately small reviewed CVE scenario registry adds conditional T1190/T1210
for regreSSHion, MS17-010 and MS15-034; T1557 for POODLE/CCS Injection with an AiTM
prerequisite; and memory-disclosure effects for Heartbleed. Internet exposure,
internal reachability, package fixes, runtime prerequisites and service privileges
must be verified. A successful vulnerability probe does not establish malicious
exploitation. Unmapped CVEs retain CVSS-derived consequences and an explicit
statement that a unique technique is not assigned.

No new Active Response authorization, IP block, exploit attempt or automatic
incident action is triggered by these annotations. Unknown/insufficient data are
shown as unknown. Next steps describe the evidence analysts need to collect.
