// SPDX-License-Identifier: Apache-2.0
// Package event defines versioned integration contracts, independent of a broker or database.
package event

import (
	"encoding/json"
	"github.com/rkislov/cerber/internal/domain"
	"time"
)

// Envelope describes a product event; source security logs will use their own
// raw/normalized schemas. This contract does not claim OCSF compliance.
type Envelope struct {
	Sequence      int64           `json:"sequence"`
	ID            string          `json:"id"`
	SchemaVersion int             `json:"schema_version"`
	Kind          string          `json:"kind"`
	AggregateID   string          `json:"aggregate_id"`
	Source        string          `json:"source"`
	OccurredAt    time.Time       `json:"occurred_at"`
	Payload       json.RawMessage `json:"payload"`
}

func New(kind, aggregateID string, payload any) (Envelope, error) {
	id, err := domain.NewID()
	if err != nil {
		return Envelope{}, err
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return Envelope{}, err
	}
	return Envelope{ID: id, SchemaVersion: 1, Kind: kind, AggregateID: aggregateID,
		Source: "cerber", OccurredAt: time.Now().UTC(), Payload: data}, nil
}
