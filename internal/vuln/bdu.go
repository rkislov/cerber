// SPDX-License-Identifier: Apache-2.0
package vuln

import (
	"archive/zip"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"strings"
	"time"
)

type bduVul struct {
	ID          string `xml:"identifier"`
	Name        string `xml:"name"`
	Description string `xml:"description"`
	State       string `xml:"vul_state"`
	Soft        []struct {
		Name    string `xml:"name"`
		Vendor  string `xml:"vendor"`
		Version string `xml:"version"`
	} `xml:"vulnerable_software>soft"`
	Identifiers []struct {
		Type  string `xml:"type,attr"`
		Value string `xml:",chardata"`
	} `xml:"identifiers>identifier"`
	V2 bduVector `xml:"cvss>vector"`
	V3 bduVector `xml:"cvss3>vector"`
	V4 bduVector `xml:"cvss4>vector"`
}
type bduVector struct {
	Score float64 `xml:"score,attr"`
	Text  string  `xml:",chardata"`
}

func (c *Catalog) syncBDU(ctx context.Context) error {
	cl := *client
	cl.Timeout = 10 * time.Minute
	if ca := os.Getenv("CERBER_BDU_CA"); ca != "" {
		data, e := os.ReadFile(ca)
		if e != nil {
			return e
		}
		roots, e := x509.SystemCertPool()
		if e != nil {
			roots = x509.NewCertPool()
		}
		if !roots.AppendCertsFromPEM(data) {
			return fmt.Errorf("invalid scoped BDU CA")
		}
		cl.Transport = &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}}
	}
	req, _ := http.NewRequestWithContext(ctx, "GET", "https://bdu.fstec.ru/files/documents/vulxml.zip", nil)
	resp, e := cl.Do(req)
	if e != nil {
		return fmt.Errorf("BDU HTTPS verification or network failure")
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("BDU HTTP %d", resp.StatusCode)
	}
	f, e := os.CreateTemp("", "cerber-bdu-*.zip")
	if e != nil {
		return e
	}
	name := f.Name()
	defer os.Remove(name)
	n, e := io.Copy(f, io.LimitReader(resp.Body, 64<<20+1))
	f.Close()
	if e != nil || n > 64<<20 {
		return fmt.Errorf("BDU archive read/size failure")
	}
	z, e := zip.OpenReader(name)
	if e != nil {
		return e
	}
	defer z.Close()
	for _, item := range z.File {
		if strings.HasSuffix(item.Name, ".xml") {
			if item.UncompressedSize64 > 1024<<20 {
				return fmt.Errorf("BDU XML size limit")
			}
			r, e := item.Open()
			if e != nil {
				return e
			}
			defer r.Close()
			return c.ImportBDU(ctx, io.LimitReader(r, 1024<<20+1))
		}
	}
	return fmt.Errorf("BDU XML not found")
}

// ImportBDU replaces the complete index transactionally; bad XML leaves the prior
// catalog and its cross references available. No XML DTD/entity expansion is used.
func (c *Catalog) ImportBDU(ctx context.Context, input io.Reader) error {
	tx, e := c.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if _, e = tx.ExecContext(ctx, `DELETE FROM bdu;DELETE FROM bdu_cve;DELETE FROM bdu_cpe;CREATE TABLE IF NOT EXISTS bdu_software(product TEXT NOT NULL,version TEXT NOT NULL,id TEXT NOT NULL);DELETE FROM bdu_software;CREATE INDEX IF NOT EXISTS bdu_software_product ON bdu_software(product);`); e != nil {
		return e
	}
	d := xml.NewDecoder(input)
	count := 0
	root := false
	closed := false
	for {
		if e = ctx.Err(); e != nil {
			return e
		}
		token, err := d.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		switch v := token.(type) {
		case xml.Directive:
			return fmt.Errorf("XML directives forbidden")
		case xml.StartElement:
			if !root {
				if v.Name.Local != "vulnerabilities" {
					return fmt.Errorf("invalid BDU root")
				}
				root = true
				continue
			}
			if closed || v.Name.Local != "vul" {
				return fmt.Errorf("invalid BDU record")
			}
			var item bduVul
			if e = d.DecodeElement(&item, &v); e != nil {
				return e
			}
			if !bduID.MatchString(item.ID) {
				return fmt.Errorf("invalid BDU identifier")
			}
			if strings.Contains(strings.ToLower(item.State), "архив") || strings.Contains(strings.ToLower(item.State), "утрат") {
				continue
			}
			r := Record{ID: item.ID, Title: item.Name, Description: item.Description, Source: "БДУ ФСТЭК", URL: recordURL(item.ID), CVEs: []string{}}
			if len(r.Description) > 8000 {
				r.Description = r.Description[:8000]
			}
			score := item.V4
			if score.Score == 0 {
				score = item.V3
			}
			if score.Score == 0 {
				score = item.V2
			}
			if score.Score < 0 || score.Score > 10 || math.IsNaN(score.Score) || math.IsInf(score.Score, 0) {
				score = bduVector{}
			}
			r.Score = score.Score
			r.Vector = score.Text
			r.Severity = Severity(r.Score)
			for _, id := range item.Identifiers {
				if cveID.MatchString(id.Value) {
					r.CVEs = append(r.CVEs, id.Value)
					if _, e = tx.ExecContext(ctx, "INSERT OR IGNORE INTO bdu_cve VALUES(?,?)", id.Value, r.ID); e != nil {
						return e
					}
				}
			}
			data, _ := json.Marshal(r)
			if _, e = tx.ExecContext(ctx, "INSERT INTO bdu VALUES(?,?)", r.ID, string(data)); e != nil {
				return e
			}
			for _, s := range item.Soft {
				if p := software(s.Name); p != "" && len(s.Version) <= 1000 {
					if _, e = tx.ExecContext(ctx, "INSERT INTO bdu_software VALUES(?,?,?)", p, s.Version, r.ID); e != nil {
						return e
					}
				}
			}
			count++
			if count > 300000 {
				return fmt.Errorf("BDU record limit")
			}
		case xml.EndElement:
			if v.Name.Local == "vulnerabilities" {
				closed = true
			}
		case xml.CharData:
			if strings.TrimSpace(string(v)) != "" {
				return fmt.Errorf("unexpected XML text")
			}
		}
	}
	if !closed || count == 0 {
		return fmt.Errorf("empty/incomplete BDU export")
	}
	return tx.Commit()
}
