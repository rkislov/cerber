// SPDX-License-Identifier: Apache-2.0
// Package attack provides versioned investigative associations, not an attack
// probability score or evidence that exploitation or a future stage occurred.
package attack

import (
	"embed"
	"encoding/json"
)

//go:embed catalog.json
var files embed.FS

type Tactic struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	URL  string `json:"url"`
}
type Technique struct {
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	URL       string   `json:"url"`
	Version   string   `json:"version"`
	Modified  string   `json:"modified"`
	Tactics   []Tactic `json:"tactics"`
	Condition string   `json:"condition,omitempty"`
}
type CatalogData struct {
	Source     string      `json:"source"`
	Retrieved  string      `json:"retrieved"`
	SHA256     string      `json:"source_sha256"`
	Techniques []Technique `json:"techniques"`
}

func Catalog() CatalogData {
	var c CatalogData
	b, _ := files.ReadFile("catalog.json")
	if json.Unmarshal(b, &c) != nil {
		panic("invalid embedded ATT&CK metadata")
	}
	return c
}

type Effect struct {
	Kind        string `json:"kind"`
	Extent      string `json:"extent,omitempty"`
	Description string `json:"description"`
	Basis       string `json:"basis"`
}
type Assessment struct {
	Version     string      `json:"version"`
	Kind        string      `json:"kind"`
	Observation string      `json:"observation"`
	Techniques  []Technique `json:"techniques"`
	Effects     []Effect    `json:"effects"`
	Limitations string      `json:"limitations"`
	Next        []string    `json:"next"`
}

func assessment(kind, observed string) *Assessment {
	return &Assessment{Version: "cerber-mitre/1@2026-10-21", Kind: kind, Observation: observed, Techniques: []Technique{}, Effects: []Effect{}, Next: []string{}, Limitations: "Соответствие ATT&CK — основание для проверки аналитиком. Намерение нарушителя, успешная эксплуатация и последующие стадии не установлены этим соответствием."}
}
func (a *Assessment) add(id, condition string) {
	for _, old := range a.Techniques {
		if old.ID == id {
			return
		}
	}
	for _, t := range Catalog().Techniques {
		if t.ID == id {
			t.Condition = condition
			a.Techniques = append(a.Techniques, t)
			return
		}
	}
}
func (a *Assessment) effect(kind, description, basis string) {
	a.Effects = append(a.Effects, Effect{Kind: kind, Description: description, Basis: basis})
}
