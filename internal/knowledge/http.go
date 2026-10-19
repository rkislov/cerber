// SPDX-License-Identifier: Apache-2.0
package knowledge

import (
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"strings"
)

func validDigest(s string) bool {
	if len(s) != 64 || strings.ToLower(s) != s {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}
func NewHandler(repo Repository, token string) (http.Handler, error) {
	if repo.Root == "" {
		return nil, fmt.Errorf("repository directory is required")
	}
	if len(token) < 24 || strings.ContainsAny(token, "\r\n") {
		return nil, fmt.Errorf("knowledge token must contain at least 24 characters and no newlines")
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-store")
		if subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+token)) != 1 {
			w.Header().Set("WWW-Authenticate", "Bearer")
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if r.URL.Path == "/v1/knowledge/latest" {
			data, err := repo.Latest()
			if err != nil {
				http.Error(w, "knowledge package unavailable", http.StatusServiceUnavailable)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("ETag", `"`+digest(data)+`"`)
			if r.Method == http.MethodGet {
				_, _ = w.Write(data)
			}
			return
		}
		const prefix = "/v1/knowledge/packages/"
		if !strings.HasPrefix(r.URL.Path, prefix) {
			http.NotFound(w, r)
			return
		}
		hash := strings.TrimPrefix(r.URL.Path, prefix)
		if !validDigest(hash) {
			http.NotFound(w, r)
			return
		}
		file, err := os.Open(repo.packagePath(hash))
		if err != nil {
			http.NotFound(w, r)
			return
		}
		defer file.Close()
		info, err := file.Stat()
		if err != nil || !info.Mode().IsRegular() {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/xml")
		w.Header().Set("ETag", `"`+hash+`"`)
		http.ServeContent(w, r, "bdu.xml", info.ModTime(), file)
	}), nil
}
