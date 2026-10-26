// SPDX-License-Identifier: Apache-2.0
package vuln

import (
	"archive/zip"
	"fmt"
	"github.com/rkislov/cerber/internal/inventory"
	"io"
	"os"
	"regexp"
	"strings"
	"time"
)

const independentOvalNS = ovalNS + "#independent"
const altCPEPattern = `cpe:\/o:alt:(?!sp)[a-z\-]+:p?(\d+)(?:\.\d)*`

var altCPE = regexp.MustCompile(`^cpe:/o:alt:([a-z-]+):p?(10|11)(?:\.[0-9]+)*$`)
var altEntry = regexp.MustCompile(`^ALT-PU-[0-9]{4}-[0-9]+\.xml$`)

// Matches exactly the vendor's os-release CPE branch guard, without executing PCRE.
func altBranch(os inventory.OS) string {
	m := altCPE.FindStringSubmatch(os.CPEName)
	if len(m) != 3 || strings.HasPrefix(m[1], "sp") {
		return ""
	}
	branch := "p" + m[2]
	if os.BranchID != "" && os.BranchID != branch {
		return ""
	}
	return branch
}
func compactALTNode(n ovalNode, section string, src ovalSource) [2]string {
	empty := [2]string{}
	if section == "tests" {
		if n.Name.Local != "textfilecontent54_test" || !n.attrsAllowed("id", "version", "comment", "check", "check_existence") || n.attr("check") != "all" || n.attr("check_existence") != "" && n.attr("check_existence") != "at_least_one_exists" || len(n.Children) != 2 {
			return empty
		}
		out := empty
		for _, c := range n.Children {
			if c.Name.Space != independentOvalNS || len(c.Children) > 0 {
				return empty
			}
			switch c.Name.Local {
			case "object":
				if !c.attrsAllowed("object_ref") {
					return empty
				}
				out[0] = c.attr("object_ref")
			case "state":
				if !c.attrsAllowed("state_ref") {
					return empty
				}
				out[1] = c.attr("state_ref")
			default:
				return empty
			}
		}
		return out
	}
	if !n.attrsAllowed("id", "version", "comment") {
		return empty
	}
	if section == "objects" {
		if n.Name.Local != "textfilecontent54_object" || len(n.Children) != 4 {
			return empty
		}
		values := map[string]string{}
		for _, c := range n.Children {
			if c.Name.Space != independentOvalNS || len(c.Children) > 0 || values[c.Name.Local] != "" || !c.attrsAllowed("datatype", "operation") {
				return empty
			}
			expectedType := "string"
			expectedOperation := ""
			if c.Name.Local == "instance" {
				expectedType = "int"
			}
			if c.Name.Local == "pattern" {
				expectedOperation = "pattern match"
			}
			if c.attr("datatype") != expectedType || c.attr("operation") != expectedOperation {
				return empty
			}
			values[c.Name.Local] = c.Text
		}
		if values["path"] != "/etc" || values["filename"] != "os-release" || values["pattern"] != altCPEPattern || values["instance"] != "1" {
			return empty
		}
		return [2]string{"@alt-platform", ""}
	}
	if n.Name.Local != "textfilecontent54_state" || len(n.Children) != 1 {
		return empty
	}
	c := n.Children[0]
	if c.Name.Space != independentOvalNS || c.Name.Local != "subexpression" || len(c.Children) > 0 || !c.attrsAllowed("operation") || c.attr("operation") != "equals" || c.Text != strings.TrimPrefix(src.ID, "alt-p") {
		return empty
	}
	return [2]string{"@" + c.Text, ""}
}
func altCriteriaTests(c ovalCriteria, guards map[string]bool) ([]string, bool) {
	if c.Invalid || c.Operator != "AND" || c.Negate != "" && c.Negate != "false" || len(c.Extend) > 0 || len(c.Tests) != 1 || len(c.Criteria) != 1 {
		return nil, false
	}
	t := c.Tests[0]
	if !guards[t.Ref] || t.Negate != "" && t.Negate != "false" {
		return nil, false
	}
	return criteriaTests(c.Criteria[0], 0)
}

// The official endpoint returns a ZIP of separate OVAL documents. Read entries
// directly, never extract paths or trust filename extensions as content validation.
func parseALTZip(r io.Reader, src ovalSource, tempdir string) (map[string]ovalRecord, time.Time, error) {
	f, e := os.CreateTemp(tempdir, "cerber-alt-oval-*.zip")
	if e != nil {
		return nil, time.Time{}, e
	}
	defer os.Remove(f.Name())
	defer f.Close()
	n, e := io.Copy(f, io.LimitReader(r, (128<<20)+1))
	if e != nil || n > 128<<20 {
		if e == nil {
			e = fmt.Errorf("ALT ZIP exceeds 128 MiB")
		}
		return nil, time.Time{}, e
	}
	z, e := zip.NewReader(f, n)
	if e != nil {
		return nil, time.Time{}, e
	}
	if len(z.File) == 0 || len(z.File) > 25000 {
		return nil, time.Time{}, fmt.Errorf("ALT ZIP entry count")
	}
	out := map[string]ovalRecord{}
	names := map[string]bool{}
	var total uint64
	var modified time.Time
	for _, entry := range z.File {
		if !altEntry.MatchString(entry.Name) || names[entry.Name] || !entry.Mode().IsRegular() || entry.Flags&1 != 0 || entry.UncompressedSize64 > 16<<20 {
			return nil, modified, fmt.Errorf("unsafe ALT ZIP entry")
		}
		names[entry.Name] = true
		total += entry.UncompressedSize64
		if total > 512<<20 {
			return nil, modified, fmt.Errorf("ALT expanded ZIP exceeds 512 MiB")
		}
		body, e := entry.Open()
		if e != nil {
			return nil, modified, e
		}
		records, at, e := parseOVAL(io.LimitReader(body, (16<<20)+1), src)
		closeErr := body.Close()
		if e != nil {
			return nil, modified, fmt.Errorf("ALT OVAL %s: %w", entry.Name, e)
		}
		if closeErr != nil {
			return nil, modified, closeErr
		}
		if at.After(modified) {
			modified = at
		}
		for id, v := range records {
			old := out[id]
			old.ID = id
			old.Definitions = append(old.Definitions, v.Definitions...)
			old.Checks = append(old.Checks, v.Checks...)
			old.Unsupported = old.Unsupported || v.Unsupported
			out[id] = old
		}
	}
	if len(out) == 0 {
		return nil, modified, fmt.Errorf("ALT ZIP has no CVE records")
	}
	return out, modified, nil
}
