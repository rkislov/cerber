// SPDX-License-Identifier: Apache-2.0
package linux

import "testing"

func TestDPKGSourceMetadataAndLegacy(t *testing.T) {
	for _, line := range []string{"openssh-server\t1:9.6p1-3ubuntu13.20\tamd64\tinstall ok installed\topenssh\t1:9.6p1-3ubuntu13.20\n", "openssh-server\t1:9.6p1-3ubuntu13.20\tamd64\tinstall ok installed\n"} {
		rows, _, e := parsePackages(line, "debian")
		if e != nil || len(rows) != 1 {
			t.Fatal(rows, e)
		}
		if len(line) > 100 && rows[0].SourcePackage != "openssh" {
			t.Fatal(rows)
		}
	}
	if _, _, e := parsePackages("openssh-server\t1\tamd64\tinstall ok installed\t\t\n", "debian"); e == nil {
		t.Fatal("empty metadata accepted")
	}
}
