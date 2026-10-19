// SPDX-License-Identifier: Apache-2.0
package linux

import (
	"bufio"
	"fmt"
	"strings"
)

// OSRelease parses data without sourcing a shell script or expanding variables.
func OSRelease(data []byte) (map[string]string, error) {
	values := map[string]string{}
	scan := bufio.NewScanner(strings.NewReader(string(data)))
	scan.Buffer(make([]byte, 4096), 1<<20)
	for scan.Scan() {
		line := strings.TrimSpace(scan.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return nil, fmt.Errorf("invalid os-release assignment")
		}
		for _, c := range key {
			if (c < 'A' || c > 'Z') && c != '_' && (c < '0' || c > '9') {
				return nil, fmt.Errorf("invalid os-release key")
			}
		}
		value = strings.TrimSpace(value)
		if strings.HasPrefix(value, `'`) {
			if len(value) < 2 || value[len(value)-1] != '\'' {
				return nil, fmt.Errorf("invalid os-release quote")
			}
			value = value[1 : len(value)-1]
		} else if strings.HasPrefix(value, `"`) {
			if len(value) < 2 || value[len(value)-1] != '"' {
				return nil, fmt.Errorf("invalid os-release quote")
			}
			value = value[1 : len(value)-1]
			var out strings.Builder
			for i := 0; i < len(value); i++ {
				if value[i] == '\\' && i+1 < len(value) {
					switch value[i+1] {
					case '\\', '"', '$', '`':
						i++
						out.WriteByte(value[i])
						continue
					}
				}
				out.WriteByte(value[i])
			}
			value = out.String()
		}
		values[key] = value
	}
	return values, scan.Err()
}
func hasFamily(values map[string]string, names ...string) bool {
	for _, v := range strings.Fields(values["ID"] + " " + values["ID_LIKE"]) {
		for _, name := range names {
			if v == name {
				return true
			}
		}
	}
	return false
}
