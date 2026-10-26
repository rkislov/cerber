// SPDX-License-Identifier: Apache-2.0
package vuln

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

var rpmPart = regexp.MustCompile(`^[A-Za-z0-9._+~^]+$`)

func rpmParts(v string) (epoch, version, release string, err error) {
	if len(v) == 0 || len(v) > 512 {
		return "", "", "", fmt.Errorf("invalid RPM EVR")
	}
	epoch = "0"
	if i := strings.IndexByte(v, ':'); i >= 0 {
		epoch = v[:i]
		v = v[i+1:]
		if epoch == "" {
			return "", "", "", fmt.Errorf("invalid RPM epoch")
		}
		for i := range epoch {
			if !digit(epoch[i]) {
				return "", "", "", fmt.Errorf("invalid RPM epoch")
			}
		}
	}
	if _, e := strconv.ParseUint(epoch, 10, 32); e != nil {
		return "", "", "", fmt.Errorf("invalid RPM epoch range")
	}
	i := strings.LastIndexByte(v, '-')
	if i < 1 || i == len(v)-1 {
		return "", "", "", fmt.Errorf("RPM EVR requires version and release")
	}
	version, release = v[:i], v[i+1:]
	if !rpmPart.MatchString(version) || !rpmPart.MatchString(release) {
		return "", "", "", fmt.Errorf("invalid RPM version/release")
	}
	return
}
func alpha(c byte) bool { return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' }
func rpmComparePart(a, b string) int {
	for a != "" || b != "" {
		for a != "" && !alpha(a[0]) && !digit(a[0]) && a[0] != '~' && a[0] != '^' {
			a = a[1:]
		}
		for b != "" && !alpha(b[0]) && !digit(b[0]) && b[0] != '~' && b[0] != '^' {
			b = b[1:]
		}
		if strings.HasPrefix(a, "~") || strings.HasPrefix(b, "~") {
			if !strings.HasPrefix(a, "~") {
				return 1
			}
			if !strings.HasPrefix(b, "~") {
				return -1
			}
			a, b = a[1:], b[1:]
			continue
		}
		if strings.HasPrefix(a, "^") || strings.HasPrefix(b, "^") {
			if a == "" {
				return -1
			}
			if b == "" {
				return 1
			}
			if !strings.HasPrefix(a, "^") {
				return 1
			}
			if !strings.HasPrefix(b, "^") {
				return -1
			}
			a, b = a[1:], b[1:]
			continue
		}
		if a == "" || b == "" {
			if a == b {
				return 0
			}
			if a == "" {
				return -1
			}
			return 1
		}
		numeric := digit(a[0])
		i, j := 0, 0
		for i < len(a) && (numeric && digit(a[i]) || !numeric && alpha(a[i])) {
			i++
		}
		for j < len(b) && (numeric && digit(b[j]) || !numeric && alpha(b[j])) {
			j++
		}
		if j == 0 {
			if numeric {
				return 1
			}
			return -1
		}
		var c int
		if numeric {
			c = numericString(a[:i], b[:j])
		} else {
			c = strings.Compare(a[:i], b[:j])
		}
		if c != 0 {
			return c
		}
		a, b = a[i:], b[j:]
	}
	return 0
}

// CompareRPM compares full E:V-R values. No upstream-only or cross-distribution ordering is inferred.
func CompareRPM(a, b string) (int, error) {
	ae, av, ar, e := rpmParts(a)
	if e != nil {
		return 0, e
	}
	be, bv, br, e := rpmParts(b)
	if e != nil {
		return 0, e
	}
	if c := numericString(ae, be); c != 0 {
		return c, nil
	}
	if c := rpmComparePart(av, bv); c != 0 {
		return c, nil
	}
	return rpmComparePart(ar, br), nil
}
