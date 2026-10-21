// SPDX-License-Identifier: Apache-2.0
package netscan

import (
	"bytes"
	"context"
	"encoding/xml"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

const Ports = "21,22,25,53,80,110,135,139,143,389,443,445,465,587,636,993,995,1433,1521,22222,3306,3389,5432,5900,6379,8080,8443,9200"
const Scripts = "smb-vuln-ms17-010,ssl-heartbleed,ssl-poodle,ssl-ccs-injection,http-vuln-cve2015-1635"

// Args accepts no shell fragments, script names, filenames or arbitrary switches.
func Args(t Task) ([]string, error) {
	if e := t.Validate(); e != nil {
		return nil, e
	}
	args := []string{"-n", "--max-retries", "1", "--max-rate", "50", "--max-parallelism", "16", "--host-timeout", "90s", "-oX", "-"}
	if t.Profile == "discovery" {
		args = append(args, "-sn")
	} else {
		args = append(args, "-sT", "-Pn", "-sV", "--version-light", "-p", Ports)
		if t.Profile == "vulnerabilities" {
			args = append(args, "--script", Scripts, "--script-timeout", "15s")
		}
	}
	if strings.Contains(t.Targets[0], ":") {
		args = append(args, "-6")
	}
	args = append(args, t.Targets...)
	return args, nil
}

type limitedBuffer struct {
	bytes.Buffer
	limit int
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if b.Len()+len(p) > b.limit {
		return 0, fmt.Errorf("scanner output limit exceeded")
	}
	return b.Buffer.Write(p)
}
func Execute(ctx context.Context, t Task) Result {
	r := Result{ID: t.ID, State: "failed", Started: time.Now().UTC(), Hosts: []Host{}}
	args, e := Args(t)
	if e != nil {
		r.Error = e.Error()
		r.Finished = time.Now().UTC()
		return r
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "nmap", args...)
	cmd.WaitDelay = 3 * time.Second
	output := &limitedBuffer{limit: 768 << 10}
	stderr := &limitedBuffer{limit: 4096}
	cmd.Stdout = output
	cmd.Stderr = stderr
	e = cmd.Run()
	if e != nil {
		r.Error = "Nmap failed or is not installed; " + e.Error()
		if ctx.Err() != nil {
			r.Error = ctx.Err().Error()
		}
		r.Finished = time.Now().UTC()
		return r
	}
	hosts, e := Parse(output.Bytes(), t)
	if e != nil {
		r.Error = e.Error()
	} else {
		r.Hosts = hosts
		r.State = "completed"
	}
	r.Finished = time.Now().UTC()
	return r
}

type xmlRun struct {
	XMLName xml.Name `xml:"nmaprun"`
	Hosts   []struct {
		Status struct {
			State string `xml:"state,attr"`
		} `xml:"status"`
		Addresses []struct {
			Addr string `xml:"addr,attr"`
			Type string `xml:"addrtype,attr"`
		} `xml:"address"`
		Names []struct {
			Name string `xml:"name,attr"`
		} `xml:"hostnames>hostname"`
		Ports []struct {
			Port     int    `xml:"portid,attr"`
			Protocol string `xml:"protocol,attr"`
			State    struct {
				State string `xml:"state,attr"`
			} `xml:"state"`
			Service struct {
				Name    string   `xml:"name,attr"`
				Product string   `xml:"product,attr"`
				Version string   `xml:"version,attr"`
				CPE     []string `xml:"cpe"`
			} `xml:"service"`
			Scripts []xmlScript `xml:"script"`
		} `xml:"ports>port"`
		Scripts []xmlScript `xml:"hostscript>script"`
		Timeout string      `xml:"timedout,attr"`
	} `xml:"host"`
	Finished struct {
		Exit string `xml:"exit,attr"`
	} `xml:"runstats>finished"`
}
type xmlScript struct {
	ID     string     `xml:"id,attr"`
	Output string     `xml:"output,attr"`
	Tables []xmlTable `xml:"table"`
}
type xmlTable struct {
	Key   string `xml:"key,attr"`
	Elems []struct {
		Key   string `xml:"key,attr"`
		Value string `xml:",chardata"`
	} `xml:"elem"`
	Tables []xmlTable `xml:"table"`
}

func vulnerable(t xmlTable) bool {
	for _, e := range t.Elems {
		if e.Key == "state" && (e.Value == "VULNERABLE" || e.Value == "VULNERABLE (Exploitable)") {
			return true
		}
	}
	for _, v := range t.Tables {
		if vulnerable(v) {
			return true
		}
	}
	return false
}
func Parse(data []byte, t Task) ([]Host, error) {
	var x xmlRun
	if len(data) > 768<<10 {
		return nil, fmt.Errorf("output too large")
	}
	if e := xml.Unmarshal(data, &x); e != nil {
		return nil, e
	}
	if x.Finished.Exit != "success" {
		return nil, fmt.Errorf("incomplete Nmap report")
	}
	allowed := map[string]bool{}
	for _, a := range t.Targets {
		allowed[a] = true
	}
	out := []Host{}
	for _, v := range x.Hosts {
		if v.Timeout == "true" {
			return nil, fmt.Errorf("host scan timed out; absence cannot be inferred")
		}
		if v.Status.State != "up" {
			continue
		}
		h := Host{Services: []Service{}, Findings: []Finding{}}
		for _, a := range v.Addresses {
			if allowed[a.Addr] {
				h.IP = a.Addr
			}
		}
		if h.IP == "" {
			return nil, fmt.Errorf("out-of-scope host")
		}
		if len(v.Names) > 0 {
			h.Name = v.Names[0].Name
		}
		scripts := v.Scripts
		for _, p := range v.Ports {
			for i := range p.Scripts {
				p.Scripts[i].Output = fmt.Sprintf("Порт %d/%s · %s", p.Port, p.Protocol, p.Scripts[i].Output)
			}
			scripts = append(scripts, p.Scripts...)
			if p.State.State == "open" {
				h.Services = append(h.Services, Service{p.Port, p.Protocol, p.Service.Name, p.Service.Product, p.Service.Version, p.Service.CPE})
			}
		}
		for _, s := range scripts {
			if _, allowed := Checks[s.ID]; !allowed {
				continue
			}
			status := "not_confirmed"
			for _, table := range s.Tables {
				if vulnerable(table) {
					status = "scanner_confirmed"
				}
			}
			evidence := s.Output
			if len(evidence) > 4000 {
				evidence = evidence[:4000]
			}
			h.Findings = append(h.Findings, Finding{s.ID, status, evidence})
		}
		// Under -Pn Nmap reports every target up: require actual open service evidence.
		if t.Profile != "discovery" && len(h.Services) == 0 {
			continue
		}
		out = append(out, h)
	}
	return out, nil
}
