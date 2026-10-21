// SPDX-License-Identifier: Apache-2.0
package endpoint

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strings"
)

func (s *Server) Handler(binding Receiver) http.Handler {
	slots := make(chan struct{}, 2)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if r.Method != "POST" {
			http.Error(w, "method not allowed", 405)
			return
		}
		id := r.Header.Get("X-Cerber-Agent")
		token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if len(id) != 32 || len(token) < 32 {
			http.Error(w, "unauthorized", 401)
			return
		}
		asset, e := binding.AgentBinding(r.Context(), id, tokenHash(token))
		if e != nil {
			http.Error(w, "unauthorized", 401)
			return
		}
		select {
		case slots <- struct{}{}:
			defer func() { <-slots }()
		default:
			http.Error(w, "endpoint busy", 429)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 256<<10)
		defer r.Body.Close()
		var report Report
		d := json.NewDecoder(r.Body)
		d.DisallowUnknownFields()
		var extra any
		if d.Decode(&report) != nil || d.Decode(&extra) != io.EOF {
			http.Error(w, "bad request", 400)
			return
		}
		reply, e := s.Exchange(r.Context(), id, asset, report)
		if e != nil {
			http.Error(w, "endpoint unavailable", 503)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(reply)
	})
}

func tokenHash(v string) string { h := sha256.Sum256([]byte(v)); return hex.EncodeToString(h[:]) }
