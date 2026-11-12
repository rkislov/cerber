// SPDX-License-Identifier: Apache-2.0
package suricatarules

import "time"

type AppliedSummary struct {
	ID           string `json:"id"`
	Count        int    `json:"count"`
	EngineMajor  int    `json:"engine_major"`
	Sensors      int    `json:"sensors"`
	FreshSensors int    `json:"fresh_sensors"`
}
type Summary struct {
	Latest         *Manifest        `json:"latest"`
	Applied        []AppliedSummary `json:"applied"`
	PendingSensors int              `json:"pending_sensors"`
	AsOf           time.Time        `json:"as_of"`
}
