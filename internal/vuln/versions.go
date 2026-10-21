// SPDX-License-Identifier: Apache-2.0
package vuln

import (
	"regexp"
	"strconv"
	"strings"
)

var numeric = regexp.MustCompile(`^[0-9]+(?:\.[0-9]+)*(?:p[0-9]+)?$`)
var toRange = regexp.MustCompile(`^до ([0-9.p]+)( включительно)?$`)
var fromRange = regexp.MustCompile(`^от ([0-9.p]+) до ([0-9.p]+)( включительно)?$`)

func compare(a, b string) (int, bool) {
	if !numeric.MatchString(a) || !numeric.MatchString(b) {
		return 0, false
	}
	baseA, baseB := strings.SplitN(a, "p", 2), strings.SplitN(b, "p", 2)
	x, y := strings.Split(baseA[0], "."), strings.Split(baseB[0], ".")
	n := len(x)
	if len(y) > n {
		n = len(y)
	}
	for i := 0; i < n; i++ {
		av, bv := 0, 0
		var e error
		if i < len(x) {
			av, e = strconv.Atoi(x[i])
			if e != nil {
				return 0, false
			}
		}
		if i < len(y) {
			bv, e = strconv.Atoi(y[i])
			if e != nil {
				return 0, false
			}
		}
		if av < bv {
			return -1, true
		}
		if av > bv {
			return 1, true
		}
	}
	pa, pb := 0, 0
	var err error
	if len(baseA) > 1 {
		pa, err = strconv.Atoi(baseA[1])
		if err != nil {
			return 0, false
		}
	}
	if len(baseB) > 1 {
		pb, err = strconv.Atoi(baseB[1])
		if err != nil {
			return 0, false
		}
	}
	if pa < pb {
		return -1, true
	}
	if pa > pb {
		return 1, true
	}
	return 0, true
}
func affected(version, rule string) bool {
	rule = strings.TrimSpace(strings.ToLower(rule))
	if n, ok := compare(version, rule); ok {
		return n == 0
	}
	if r := fromRange.FindStringSubmatch(rule); r != nil {
		a, ok := compare(version, r[1])
		b, ok2 := compare(version, r[2])
		return ok && ok2 && a >= 0 && (b < 0 || b == 0 && r[3] != "")
	}
	if r := toRange.FindStringSubmatch(rule); r != nil {
		b, ok := compare(version, r[1])
		return ok && (b < 0 || b == 0 && r[2] != "")
	}
	return false
}
func software(name string) string {
	n := strings.ToLower(strings.TrimSpace(name))
	switch n {
	case "openssh", "nginx", "postfix", "dovecot", "mysql", "mariadb", "postgresql", "samba", "openssl":
		return n
	case "apache http server", "apache httpd", "apache http сервер":
		return "http_server"
	}
	return ""
}
func product(key string) (string, string) {
	v := strings.Split(key, ":")
	if len(v) != 13 {
		return "", ""
	}
	allowed := map[string]string{"openbsd:openssh": "openssh", "nginx:nginx": "nginx", "igor_sysoev:nginx": "nginx", "apache:http_server": "http_server", "postfix:postfix": "postfix", "dovecot:dovecot": "dovecot", "oracle:mysql": "mysql", "mariadb:mariadb": "mariadb", "postgresql:postgresql": "postgresql", "samba:samba": "samba", "openssl:openssl": "openssl"}
	return allowed[v[3]+":"+v[4]], v[5]
}
