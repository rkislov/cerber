// SPDX-License-Identifier: Apache-2.0
package telemetry

import (
	"encoding/json"
	"net/netip"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var sshFailure = regexp.MustCompile(`^Failed (?:password|publickey|keyboard-interactive/pam) for (?:invalid user )?([^ ]+) from ([^ ]+) port [0-9]+`)
var sshSuccess = regexp.MustCompile(`^Accepted (?:password|publickey|keyboard-interactive/pam) for ([^ ]+) from ([^ ]+) port [0-9]+`)

// Normalize is deterministic. Unparseable input is retained in quarantine, never discarded.
func Normalize(r RawRecord) Normalized {
	n := Normalized{Sequence: r.Sequence, ID: ID(r.AgentID, r.Raw.ID), AgentID: r.AgentID, AssetID: r.AssetID, Source: r.Raw.Source, ReceivedAt: r.ReceivedAt, EventTime: r.Raw.ObservedAt, Parser: "native-auth/1", Status: "parsed", Class: "system", Action: "log", Outcome: "unknown"}
	if SensorSource(r.Raw.Source) {
		return normalizeSensor(r, n)
	}
	if r.Raw.Source == "agent:ioc" {
		var f struct{ Path, SHA256, MD5, IOC string }
		if json.Unmarshal(r.Raw.Data, &f) != nil || len(f.SHA256) != 64 || len(f.MD5) != 32 {
			n.Status = "quarantine"
			return n
		}
		n.Class = "system"
		n.Action = "file_ioc"
		n.FilePath = f.Path
		n.SHA256 = f.SHA256
		n.MD5 = f.MD5
		n.Parser = "file-ioc/1"
		n.Message = "File hash matched an IOC on agent"
		return n
	}
	if r.Raw.Source == "network:cef" {
		return normalizeCEF(r, n)
	}
	fail := func() Normalized {
		n.Status = "quarantine"
		n.EventTime = r.ReceivedAt
		n.Class = "unknown"
		n.Message = "Invalid native event structure"
		return n
	}
	if r.Raw.Source == "journald" {
		var v map[string]json.RawMessage
		if json.Unmarshal(r.Raw.Data, &v) != nil {
			return fail()
		}
		field := func(k string) string { var s string; _ = json.Unmarshal(v[k], &s); return s }
		msg := field("MESSAGE")
		n.Message = msg
		micros, e := strconv.ParseInt(field("__REALTIME_TIMESTAMP"), 10, 64)
		if e != nil || micros <= 0 {
			return fail()
		}
		n.EventTime = time.UnixMicro(micros).UTC()
		normalizeNetfilter(&n, field("_TRANSPORT"), field("_HOSTNAME"), msg)
		exe := path.Base(field("_EXE"))
		if field("_UID") == "0" && (exe == "sshd" || exe == "sshd-session") {
			for i, re := range []*regexp.Regexp{sshFailure, sshSuccess} {
				if m := re.FindStringSubmatch(msg); m != nil {
					n.Class = "authentication"
					n.Action = "logon"
					n.Outcome = []string{"failure", "success"}[i]
					n.User = m[1]
					n.SourceIP = m[2]
					n.Identity = sshIdentity(field, msg)
					n.Parser = "native-auth/2"
					break
				}
			}
		}
	} else {
		var v struct {
			EventID  int               `json:"event_id"`
			Time     string            `json:"time"`
			Provider string            `json:"provider"`
			Computer string            `json:"computer"`
			Fields   map[string]string `json:"fields"`
		}
		if json.Unmarshal(r.Raw.Data, &v) != nil || v.EventID < 1 {
			return fail()
		}
		at, e := time.Parse(time.RFC3339Nano, v.Time)
		if e != nil {
			return fail()
		}
		n.EventTime = at.UTC()
		n.Code = strconv.Itoa(v.EventID)
		n.Message = v.Provider + " · " + n.Code
		if r.Raw.Source == "windows:System" && (v.Provider == "Microsoft-Windows-Kernel-General" && (v.EventID == 12 || v.EventID == 13) || v.Provider == "EventLog" && (v.EventID == 6005 || v.EventID == 6006)) {
			n.Class = "session"
			n.Action = "host_session_boundary"
			n.Parser = "windows-session/1"
			n.Identity = &Identity{Computer: v.Computer}
		}
		if r.Raw.Source == "windows:System" && v.EventID == 7045 && v.Provider == "Service Control Manager" {
			normalizeWindowsActivity(&n, v.Fields, v.Computer, v.EventID)
		}
		if r.Raw.Source == "windows:Security" && (v.Provider == "Microsoft-Windows-Security-Auditing" || v.EventID == 1102 && v.Provider == "Microsoft-Windows-Eventlog") {
			switch v.EventID {
			case 4624, 4625:
				n.Class = "authentication"
				n.Action = "logon"
				n.Outcome = "failure"
				if v.EventID == 4624 {
					n.Outcome = "success"
				}
				n.User = v.Fields["TargetUserName"]
				if d := v.Fields["TargetDomainName"]; d != "" && d != "-" {
					n.User = d + `\` + n.User
				}
				n.SourceIP = v.Fields["IpAddress"]
				n.Identity = windowsIdentity(v.Fields, v.Computer, "Target")
				n.Parser = "windows-auth/3"
			case 4634, 4647:
				n.Class = "session"
				n.Action = "session_ended"
				n.Outcome = "success"
				prefix := "Subject"
				if v.EventID == 4634 {
					prefix = "Target"
				}
				n.Identity = windowsIdentity(v.Fields, v.Computer, prefix)
				n.User = v.Fields[prefix+"UserName"]
				n.Parser = "windows-session/1"
			case 4688, 4689, 4697, 4698, 5156:
				normalizeWindowsActivity(&n, v.Fields, v.Computer, v.EventID)
			case 4648, 4769:
				normalizeWindowsAuth(&n, v.Fields, v.Computer, v.EventID)
			case 1102:
				n.Parser = "windows-audit/3"
				n.Identity = windowsIdentity(v.Fields, v.Computer, "Subject")
				n.User = v.Fields["SubjectUserName"]
				if domain := v.Fields["SubjectDomainName"]; domain != "" && domain != "-" && n.User != "" {
					n.User = domain + `\` + n.User
				}
				n.Class = "audit"
				n.Action = "log_cleared"
				n.Outcome = "success"
			}
		}
	}
	if ip, e := netip.ParseAddr(n.SourceIP); e == nil {
		n.SourceIP = ip.Unmap().String()
	} else {
		n.SourceIP = ""
	}
	n.User = strings.ToLower(n.User)
	if n.EventTime.After(r.ReceivedAt.Add(5 * time.Minute)) {
		n.Status = "quarantine"
		n.EventTime = r.ReceivedAt
		n.Class = "unknown"
		n.Message = "Source event time exceeds server time by more than 5 minutes"
	}
	return n
}
