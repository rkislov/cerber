// SPDX-License-Identifier: Apache-2.0
package netscan

// The allowlist is reviewed independently of arbitrary NSE categories. These
// scripts are documented by Nmap as safe vulnerability probes.
var Checks = map[string][]string{
	"smb-vuln-ms17-010": {"CVE-2017-0143"}, "ssl-heartbleed": {"CVE-2014-0160"},
	"ssl-poodle": {"CVE-2014-3566"}, "ssl-ccs-injection": {"CVE-2014-0224"},
	"http-vuln-cve2015-1635": {"CVE-2015-1635"},
}
