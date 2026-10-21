// SPDX-License-Identifier: Apache-2.0
package vuln

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

var client = &http.Client{Timeout: 2 * time.Minute, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

type metric struct {
	Type string `json:"type"`
	Data struct {
		Score  float64 `json:"baseScore"`
		Vector string  `json:"vectorString"`
	} `json:"cvssData"`
}
type nvdResponse struct {
	Total *int `json:"totalResults"`
	Items []struct {
		CVE struct {
			Configurations []nvdNode `json:"configurations"`
			Weaknesses     []struct {
				Descriptions []struct {
					Value string `json:"value"`
				} `json:"description"`
			} `json:"weaknesses"`
			ID           string `json:"id"`
			Status       string `json:"vulnStatus"`
			Descriptions []struct {
				Lang  string `json:"lang"`
				Value string `json:"value"`
			} `json:"descriptions"`
			Metrics struct {
				V4  []metric `json:"cvssMetricV40"`
				V31 []metric `json:"cvssMetricV31"`
				V30 []metric `json:"cvssMetricV30"`
				V2  []metric `json:"cvssMetricV2"`
			} `json:"metrics"`
		} `json:"cve"`
	} `json:"vulnerabilities"`
}

func parseNVD(data []byte, key string) ([]Record, int, error) {
	var doc nvdResponse
	if e := json.Unmarshal(data, &doc); e != nil {
		return nil, 0, e
	}
	if doc.Total == nil || *doc.Total < 0 || doc.Items == nil {
		return nil, 0, fmt.Errorf("invalid NVD response schema")
	}
	out := []Record{}
	for _, item := range doc.Items {
		v := item.CVE
		if !cveID.MatchString(v.ID) || v.Status == "Rejected" {
			continue
		}
		r := Record{ID: v.ID, Source: "NVD", URL: recordURL(v.ID), CPEs: []string{key}}
		for _, d := range v.Descriptions {
			if d.Lang == "en" {
				r.Description = d.Value
				break
			}
		}
		if len(r.Description) > 8000 {
			r.Description = r.Description[:8000]
		}
		match, conditional, basis := applicability(v.Configurations, key, r.Description)
		if !match {
			continue
		}
		r.ContextRequired = conditional
		r.Applicability = basis
		seenCWE := map[string]bool{}
		for _, w := range v.Weaknesses {
			for _, d := range w.Descriptions {
				if cweID.MatchString(d.Value) && !seenCWE[d.Value] {
					r.CWEs = append(r.CWEs, d.Value)
					seenCWE[d.Value] = true
				}
			}
		}
		r.Title = v.ID
		metrics := v.Metrics.V4
		if len(metrics) == 0 {
			metrics = v.Metrics.V31
		}
		if len(metrics) == 0 {
			metrics = v.Metrics.V30
		}
		if len(metrics) == 0 {
			metrics = v.Metrics.V2
		}
		if len(metrics) > 0 {
			m := metrics[0]
			for _, x := range metrics {
				if x.Type == "Primary" {
					m = x
					break
				}
			}
			if m.Data.Score >= 0 && m.Data.Score <= 10 {
				r.Score = m.Data.Score
				r.Vector = m.Data.Vector
			}
		}
		r.Severity = Severity(r.Score)
		out = append(out, r)
	}
	return out, *doc.Total, nil
}
func fetchNVD(ctx context.Context, key string) ([]Record, error) {
	out := []Record{}
	for start := 0; start < 10000; {
		q := url.Values{"cpeName": {key}, "isVulnerable": {""}, "resultsPerPage": {"2000"}, "startIndex": {fmt.Sprint(start)}}
		req, e := http.NewRequestWithContext(ctx, "GET", "https://services.nvd.nist.gov/rest/json/cves/2.0?"+q.Encode(), nil)
		if e != nil {
			return nil, e
		}
		req.Header.Set("User-Agent", "Cerber/1 vulnerability catalog")
		resp, e := client.Do(req)
		if e != nil {
			return nil, fmt.Errorf("NVD request failed")
		}
		if resp.StatusCode != 200 {
			resp.Body.Close()
			return nil, fmt.Errorf("NVD HTTP %d", resp.StatusCode)
		}
		data, e := io.ReadAll(io.LimitReader(resp.Body, 32<<20+1))
		resp.Body.Close()
		if e != nil || len(data) > 32<<20 {
			return nil, fmt.Errorf("NVD response limit or read failure")
		}
		records, total, e := parseNVD(data, key)
		if e != nil {
			return nil, e
		}
		out = append(out, records...)
		if total > 10000 {
			return nil, fmt.Errorf("NVD result exceeds catalog query limit")
		}
		start += 2000
		if start >= total {
			return out, nil
		}
		timer := time.NewTimer(6 * time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
	return nil, fmt.Errorf("NVD pagination incomplete")
}
