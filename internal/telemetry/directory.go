// SPDX-License-Identifier: Apache-2.0
package telemetry

import "time"

// DirectoryProof is an immutable, time-bounded observation of current AD state,
// never an assertion of account state at the historical event time.
type DirectoryProof struct {
	State      string    `json:"state"`
	CheckedAt  time.Time `json:"checked_at,omitempty"`
	ValidUntil time.Time `json:"valid_until,omitempty"`
	DNS        string    `json:"dns,omitempty"`
	NetBIOS    string    `json:"netbios,omitempty"`
	DomainSID  string    `json:"domain_sid,omitempty"`
	SID        string    `json:"sid,omitempty"`
	GUID       string    `json:"object_guid,omitempty"`
	SAM        string    `json:"sam,omitempty"`
	UPN        string    `json:"upn,omitempty"`
}
