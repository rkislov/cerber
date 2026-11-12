// SPDX-License-Identifier: Apache-2.0
package suricatarules

import (
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"
)

const MaxClassification = 64 << 10
const filesFormat = "rules-classification-v1"

type ruleFiles struct {
	Rules          string `json:"rules"`
	Classification string `json:"classification"`
}

func validFormat(s string) bool { return s == "" || s == filesFormat }

var classLine = regexp.MustCompile(`^config classification:\s*([a-zA-Z0-9_-]+),[^,\r\n]+,\s*[1-4]$`)

// Only classification declarations are accepted, never includes or file paths.
func ValidateClassification(s string) error {
	if len(s) > MaxClassification || !utf8.ValidString(s) || strings.ContainsRune(s, 0) {
		return ErrInvalid
	}
	seen := map[string]bool{}
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		m := classLine.FindStringSubmatch(line)
		if m == nil || seen[m[1]] {
			return fmt.Errorf("%w: classification.config", ErrInvalid)
		}
		seen[m[1]] = true
	}
	if s != "" && len(seen) == 0 {
		return ErrInvalid
	}
	return nil
}
