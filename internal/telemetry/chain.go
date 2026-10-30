// SPDX-License-Identifier: Apache-2.0
package telemetry

import "time"

type ChainStep struct {
	Outcome       string       `json:"outcome,omitempty"`
	Code          string       `json:"code,omitempty"`
	WindowsAuth   *WindowsAuth `json:"windows_auth,omitempty"`
	MatchedGroups []string     `json:"matched_groups"`
	EventID       string       `json:"event_id"`
	AgentID       string       `json:"agent_id"`
	AssetID       string       `json:"asset_id"`
	At            time.Time    `json:"at"`
	User          string       `json:"user"`
	SourceIP      string       `json:"source_ip,omitempty"`
	Action        string       `json:"action"`
	Identity      Identity     `json:"identity"`
}
type ChainLink struct {
	From  string `json:"from"`
	To    string `json:"to"`
	Kind  string `json:"kind"`
	Basis string `json:"basis"`
}
type EventChain struct {
	Version     int         `json:"version"`
	Key         string      `json:"key"`
	Hosts       int         `json:"hosts"`
	Steps       []ChainStep `json:"steps"`
	Links       []ChainLink `json:"links"`
	Truncated   bool        `json:"truncated"`
	Limitations string      `json:"limitations"`
}
