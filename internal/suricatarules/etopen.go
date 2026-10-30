// SPDX-License-Identifier: Apache-2.0
package suricatarules

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net/http"
	"path"
	"sort"
	"strings"
	"time"
)

// ET's 7.0.3 feed is the published ET Open feed for supported 7.x/8.x
// engines. Actual compatibility is checked with the selected engine's -T.
const ETURL = "https://rules.emergingthreats.net/open/suricata-7.0.3/emerging.rules.tar.gz"

func DownloadET(ctx context.Context, major int) (Bundle, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	client := &http.Client{Timeout: 2 * time.Minute, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	defer client.CloseIdleConnections()
	req, e := http.NewRequestWithContext(ctx, "GET", ETURL, nil)
	if e != nil {
		return Bundle{}, e
	}
	req.Header.Set("User-Agent", "Cerber-SIEM/1 (ET Open rule management)")
	res, e := client.Do(req)
	if e != nil {
		return Bundle{}, fmt.Errorf("ET Open download failed")
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return Bundle{}, fmt.Errorf("ET Open HTTP %d", res.StatusCode)
	}
	data, e := io.ReadAll(io.LimitReader(res.Body, MaxCompressed+1))
	if e != nil || len(data) > MaxCompressed {
		return Bundle{}, fmt.Errorf("ET Open archive exceeds limit")
	}
	rules, e := ExtractET(data)
	if e != nil {
		return Bundle{}, e
	}
	return Pack("ET Open "+time.Now().UTC().Format("2006-01-02 15:04"), "et-open", major, rules)
}
func ExtractET(data []byte) ([]byte, error) {
	z, e := gzip.NewReader(bytes.NewReader(data))
	if e != nil {
		return nil, ErrInvalid
	}
	defer z.Close()
	limited := &io.LimitedReader{R: z, N: 96<<20 + 1}
	tr := tar.NewReader(limited)
	files := map[string][]byte{}
	total := 0
	for entries := 0; ; entries++ {
		h, e := tr.Next()
		if e == io.EOF {
			break
		}
		if e != nil || entries > 512 {
			return nil, ErrInvalid
		}
		if path.IsAbs(h.Name) || path.Clean(h.Name) != strings.TrimSuffix(h.Name, "/") || strings.HasPrefix(h.Name, "../") || h.Typeflag != tar.TypeDir && h.Typeflag != tar.TypeReg {
			return nil, ErrInvalid
		}
		if h.Typeflag != tar.TypeReg || !strings.HasSuffix(h.Name, ".rules") {
			continue
		}
		if _, ok := files[h.Name]; ok {
			return nil, ErrInvalid
		}
		if h.Size < 0 || h.Size > MaxRules-int64(total) {
			return nil, ErrLimit
		}
		b, e := io.ReadAll(tr)
		if e != nil {
			return nil, e
		}
		total += len(b)
		files[h.Name] = b
	}
	if _, e = io.Copy(io.Discard, limited); e != nil {
		return nil, ErrInvalid
	}
	if limited.N <= 0 || len(files) == 0 {
		return nil, ErrInvalid
	}
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	var out bytes.Buffer
	for _, n := range names {
		out.Write(files[n])
		out.WriteByte('\n')
	}
	return out.Bytes(), nil
}
