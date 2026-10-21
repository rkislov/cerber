// SPDX-License-Identifier: Apache-2.0
package vuln

import (
	"fmt"
	"strings"
)

type cpeMatch struct {
	Vulnerable     bool   `json:"vulnerable"`
	Criteria       string `json:"criteria"`
	StartIncluding string `json:"versionStartIncluding"`
	StartExcluding string `json:"versionStartExcluding"`
	EndIncluding   string `json:"versionEndIncluding"`
	EndExcluding   string `json:"versionEndExcluding"`
}
type nvdNode struct {
	Operator string     `json:"operator"`
	Negate   bool       `json:"negate"`
	Matches  []cpeMatch `json:"cpeMatch"`
	Nodes    []nvdNode  `json:"nodes"`
}

func criterion(c cpeMatch, key string) (bool, bool) {
	a, b := strings.Split(c.Criteria, ":"), strings.Split(key, ":")
	if len(a) != 13 || len(b) != 13 || !c.Vulnerable {
		return false, false
	}
	for i := 2; i <= 4; i++ {
		if a[i] != b[i] {
			return false, false
		}
	}
	unknown := false
	version := b[5]
	if a[5] != "*" {
		if a[5] != version {
			return false, false
		}
	} else if c.StartIncluding == "" && c.StartExcluding == "" && c.EndIncluding == "" && c.EndExcluding == "" {
		unknown = true
	}
	for _, v := range []struct {
		bound     string
		direction int
		inclusive bool
	}{{c.StartIncluding, 1, true}, {c.StartExcluding, 1, false}, {c.EndIncluding, -1, true}, {c.EndExcluding, -1, false}} {
		if v.bound == "" {
			continue
		}
		cmp, ok := compare(version, v.bound)
		if !ok {
			unknown = true
			continue
		}
		if cmp*v.direction < 0 || cmp == 0 && !v.inclusive {
			return false, false
		}
	}
	for i := 6; i < 13; i++ {
		if a[i] != "*" && a[i] != b[i] {
			unknown = true
		}
	}
	return true, unknown
}
func applicability(nodes []nvdNode, key, description string) (bool, bool, string) {
	if len(nodes) == 0 {
		return true, true, "NVD: условия CPE не опубликованы"
	}
	found, unconditional := false, false
	summaries := []string{}
	var walk func(nvdNode, bool)
	walk = func(n nvdNode, parent bool) {
		conditional := parent || n.Negate || n.Operator == "AND"
		for _, c := range n.Matches {
			match, unknown := criterion(c, key)
			if match {
				found = true
				if !conditional && !unknown {
					unconditional = true
				}
				text := c.Criteria
				for _, x := range []struct{ name, value string }{{">=", c.StartIncluding}, {">", c.StartExcluding}, {"<=", c.EndIncluding}, {"<", c.EndExcluding}} {
					if x.value != "" {
						text += " " + x.name + x.value
					}
				}
				if conditional {
					text += "; AND/negate: нужны сведения об окружении"
				}
				summaries = append(summaries, text)
			}
		}
		for _, child := range n.Nodes {
			walk(child, conditional)
		}
	}
	for _, n := range nodes {
		walk(n, false)
	}
	lower := strings.ToLower(description)
	clientOnly := strings.Contains(lower, "only on the client side") || strings.Contains(lower, "client-side only")
	if clientOnly {
		summaries = append(summaries, "Запись описывает клиентскую сторону; сетевой баннер сервера не подтверждает наличие уязвимого клиента")
	}
	text := strings.Join(summaries, "; ")
	if len(text) > 4000 {
		text = text[:4000]
	}
	if !found {
		return false, false, fmt.Sprint("no matching application CPE")
	}
	return true, !unconditional || clientOnly, text
}
