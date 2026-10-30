// SPDX-License-Identifier: Apache-2.0
// Package netsensor runs an independent passive network telemetry receiver.
package netsensor

import (
	"encoding/json"
	"fmt"
	"github.com/rkislov/cerber/internal/telemetry"
	"io"
	"net/netip"
	"os"
	"path/filepath"
)

type Input struct {
	TemplateTTLSeconds int      `json:"template_ttl_seconds,omitempty"`
	ID                 string   `json:"id"`
	Format             string   `json:"format"`
	Protocol           string   `json:"protocol"`
	Listen             string   `json:"listen,omitempty"`
	Path               string   `json:"path,omitempty"`
	Allow              []string `json:"allow,omitempty"`
	AllowPlainRemote   bool     `json:"allow_plain_remote,omitempty"`
	Cert               string   `json:"cert,omitempty"`
	Key                string   `json:"key,omitempty"`
	ClientCA           string   `json:"client_ca,omitempty"`
}
type Config struct {
	SchemaVersion int     `json:"schema_version"`
	Server        string  `json:"server"`
	Credentials   string  `json:"credentials"`
	CACert        string  `json:"ca_cert,omitempty"`
	Spool         string  `json:"spool"`
	Inputs        []Input `json:"inputs"`
}

func Load(path string) (Config, error) {
	var c Config
	f, e := os.Open(path)
	if e != nil {
		return c, e
	}
	defer f.Close()
	d := json.NewDecoder(io.LimitReader(f, 65537))
	d.DisallowUnknownFields()
	if e = d.Decode(&c); e != nil {
		return c, fmt.Errorf("invalid sensor config")
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return c, fmt.Errorf("trailing sensor config")
	}
	return c, c.Validate()
}
func (i Input) Source() string {
	switch i.Format {
	case "netflow5", "netflow9", "ipfix":
		return "network:netflow"
	case "suricata":
		return "network:suricata"
	default:
		return "network:syslog"
	}
}
func (c Config) Validate() error {
	if c.SchemaVersion != 1 || !filepath.IsAbs(c.Spool) || !filepath.IsAbs(c.Credentials) || c.Spool == c.Credentials || c.CACert != "" && !filepath.IsAbs(c.CACert) || len(c.Inputs) < 1 || len(c.Inputs) > 8 {
		return fmt.Errorf("absolute separate paths and 1-8 inputs required")
	}
	seen := map[string]bool{}
	eveFile := false
	eveCount := 0
	for _, i := range c.Inputs {
		if !telemetry.AgentIdentifier(i.ID) || seen[i.ID] {
			return fmt.Errorf("invalid or duplicate input ID")
		}
		seen[i.ID] = true
		switch i.Format {
		case "syslog", "cef-firewall", "cef-fess", "netflow5", "netflow9", "ipfix", "suricata":
		default:
			return fmt.Errorf("unsupported input format")
		}
		if i.TemplateTTLSeconds != 0 && (i.TemplateTTLSeconds < 60 || i.TemplateTTLSeconds > 86400 || i.Format != "netflow9" && i.Format != "ipfix") {
			return fmt.Errorf("template TTL requires v9/IPFIX and 60-86400 seconds")
		}
		if i.Format == "suricata" {
			eveCount++
		}
		if i.Protocol == "file" {
			if i.Format != "suricata" || !filepath.IsAbs(i.Path) || i.Path == c.Spool || i.Listen != "" {
				return fmt.Errorf("file input requires separate absolute Suricata EVE path")
			}
			eveFile = true
			continue
		}
		if i.Protocol != "udp" && i.Protocol != "tcp" && i.Protocol != "tls" {
			return fmt.Errorf("unsupported transport")
		}
		if (i.Format == "netflow5" || i.Format == "netflow9" || i.Format == "ipfix") && i.Protocol != "udp" || i.Format == "suricata" && i.Protocol == "udp" {
			return fmt.Errorf("incompatible format and transport")
		}
		addr, e := netip.ParseAddrPort(i.Listen)
		if e != nil || addr.Port() == 0 || addr.Addr().Zone() != "" || i.Path != "" {
			return fmt.Errorf("literal listen address and port required")
		}
		if len(i.Allow) == 0 || len(i.Allow) > 128 {
			return fmt.Errorf("explicit peer CIDR allowlist required")
		}
		for _, p := range i.Allow {
			if _, e := netip.ParsePrefix(p); e != nil {
				return fmt.Errorf("invalid peer CIDR")
			}
		}
		if i.Protocol == "tcp" && !addr.Addr().IsLoopback() && !i.AllowPlainRemote {
			return fmt.Errorf("remote plain TCP requires allow_plain_remote; prefer mutual TLS")
		}
		if i.Protocol == "tls" {
			for _, p := range []string{i.Cert, i.Key, i.ClientCA} {
				if !filepath.IsAbs(p) {
					return fmt.Errorf("TLS requires certificate, key and client CA")
				}
			}
		}
	}
	if eveFile && eveCount != 1 {
		return fmt.Errorf("EVE file requires an exclusive source cursor")
	}
	return nil
}
func (i Input) permits(peer netip.Addr) bool {
	for _, s := range i.Allow {
		p, e := netip.ParsePrefix(s)
		if e == nil && p.Contains(peer.Unmap()) {
			return true
		}
	}
	return false
}
