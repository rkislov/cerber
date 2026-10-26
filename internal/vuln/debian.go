// SPDX-License-Identifier: Apache-2.0
package vuln

import (
	"fmt"
	"regexp"
	"strings"
)

var debVersion = regexp.MustCompile(`^[0-9][A-Za-z0-9.+:~\-]*$`)
var debRevision = regexp.MustCompile(`^[A-Za-z0-9+.~]+$`)

func digit(c byte) bool { return c >= '0' && c <= '9' }
func numericString(a, b string) int {
	a = strings.TrimLeft(a, "0")
	b = strings.TrimLeft(b, "0")
	if len(a) < len(b) {
		return -1
	}
	if len(a) > len(b) {
		return 1
	}
	return strings.Compare(a, b)
}
func debParts(v string) (epoch, upstream, revision string, err error) {
	if len(v) == 0 || len(v) > 512 {
		return "", "", "", fmt.Errorf("invalid Debian version")
	}
	epoch = "0"
	revision = "0"
	if i := strings.IndexByte(v, ':'); i >= 0 {
		epoch = v[:i]
		if epoch == "" {
			return "", "", "", fmt.Errorf("invalid epoch")
		}
		for i := range epoch {
			if !digit(epoch[i]) {
				return "", "", "", fmt.Errorf("invalid epoch")
			}
		}
		v = v[i+1:]
	}
	if !debVersion.MatchString(v) {
		return "", "", "", fmt.Errorf("invalid Debian version")
	}
	if i := strings.LastIndexByte(v, '-'); i >= 0 {
		revision = v[i+1:]
		v = v[:i]
		if v == "" || !debRevision.MatchString(revision) {
			return "", "", "", fmt.Errorf("invalid revision")
		}
	}
	return epoch, v, revision, nil
}
func debOrder(s string) int {
	if s == "" {
		return 0
	}
	c := s[0]
	if c == '~' {
		return -1
	}
	if digit(c) {
		return 0
	}
	if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' {
		return int(c)
	}
	return int(c) + 256
}
func debComparePart(a, b string) int {
	for a != "" || b != "" {
		for a != "" && !digit(a[0]) || b != "" && !digit(b[0]) {
			x, y := debOrder(a), debOrder(b)
			if x < y {
				return -1
			}
			if x > y {
				return 1
			}
			if a != "" {
				a = a[1:]
			}
			if b != "" {
				b = b[1:]
			}
		}
		i, j := 0, 0
		for i < len(a) && digit(a[i]) {
			i++
		}
		for j < len(b) && digit(b[j]) {
			j++
		}
		if c := numericString(a[:i], b[:j]); c != 0 {
			return c
		}
		a = a[i:]
		b = b[j:]
	}
	return 0
}

// CompareDebian implements dpkg ordering, including epoch, Debian revision and ~.
func CompareDebian(a, b string) (int, error) {
	ae, au, ar, e := debParts(a)
	if e != nil {
		return 0, e
	}
	be, bu, br, e := debParts(b)
	if e != nil {
		return 0, e
	}
	if c := numericString(ae, be); c != 0 {
		return c, nil
	}
	if c := debComparePart(au, bu); c != 0 {
		return c, nil
	}
	return debComparePart(ar, br), nil
}
