// SPDX-License-Identifier: Apache-2.0
package admin

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSettingsRequireNamedAdministrator(t *testing.T) {
	for _, u := range []User{{Role: "viewer", Username: "viewer"}, {Role: "operator", Username: "operator"}, {Role: "analyst", Username: "analyst"}, {Role: "administrator"}} {
		w := httptest.NewRecorder()
		if !integrationManagement(nil, w, httptest.NewRequest("GET", "/admin/api/settings", nil), u, make(chan struct{}, 2)) || w.Code != http.StatusForbidden {
			t.Fatal(u, w.Code)
		}
	}
	w := httptest.NewRecorder()
	integrationManagement(nil, w, httptest.NewRequest("GET", "/admin/api/settings", nil), User{Role: "administrator", Username: "roman"}, make(chan struct{}, 2))
	if w.Code != 200 {
		t.Fatal(w.Code)
	}
}
