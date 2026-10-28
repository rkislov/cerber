// SPDX-License-Identifier: Apache-2.0
package telemetry

import "time"

type RetentionPolicy struct {
	DatabaseMaxBytes int64 `json:"database_max_bytes,omitempty"`
	ArchiveMaxBytes  int64 `json:"archive_max_bytes,omitempty"`
	MinFreeBytes     int64 `json:"min_free_bytes,omitempty"`
	MaxBytes         int64 `json:"max_bytes,omitempty"`
	Enabled          bool  `json:"enabled"`
	HotDays          int   `json:"hot_days"`
	ArchiveDays      int   `json:"archive_days"`
	Version          int64 `json:"version"`
}

func (p RetentionPolicy) Validate() error {
	if p.MaxBytes != 0 && (p.MaxBytes < 64<<20 || p.MaxBytes > 1<<40) {
		return ErrInvalid
	}
	for _, n := range []int64{p.DatabaseMaxBytes, p.ArchiveMaxBytes, p.MinFreeBytes} {
		if n != 0 && (n < 256<<20 || n > 1<<40) {
			return ErrInvalid
		}
	}
	if p.Version < 1 || p.HotDays < 1 || p.HotDays > 3650 || p.ArchiveDays < 0 || p.ArchiveDays > 36500 {
		return ErrInvalid
	}
	return nil
}

type Archive struct {
	Sequence      int64     `json:"sequence"`
	ID            string    `json:"id"`
	CreatedAt     time.Time `json:"created_at"`
	Records       int       `json:"records"`
	Bytes         int64     `json:"bytes"`
	SHA256        string    `json:"sha256"`
	FirstSequence int64     `json:"first_sequence"`
	LastSequence  int64     `json:"last_sequence"`
	State         string    `json:"state"`
}
type RetentionStatus struct {
	Storage           StorageStatus   `json:"storage"`
	Policy            RetentionPolicy `json:"policy"`
	ArchiveConfigured bool            `json:"archive_configured"`
	LastSuccessAt     *time.Time      `json:"last_success_at,omitempty"`
	LastError         string          `json:"last_error,omitempty"`
	ProtectedEvents   int64           `json:"protected_events"`
	QuotaBytes        int64           `json:"quota_bytes"`
	Archives          int64           `json:"archives"`
}
type RetentionAudit struct {
	Sequence int64     `json:"sequence"`
	At       time.Time `json:"at"`
	Actor    string    `json:"actor"`
	Action   string    `json:"action"`
	Details  string    `json:"details"`
}

// ArchiveRecord v1 retains original source bytes as JSON and parser provenance.
type ArchiveRecord struct {
	SchemaVersion int        `json:"schema_version"`
	ID            string     `json:"id"`
	Sequence      int64      `json:"sequence"`
	AgentID       string     `json:"agent_id"`
	AssetID       string     `json:"asset_id"`
	ReceivedAt    time.Time  `json:"received_at"`
	Raw           Raw        `json:"raw"`
	Normalized    Normalized `json:"normalized"`
}

type ArchiveCheck struct {
	Archive  Archive  `json:"archive"`
	Verified bool     `json:"verified"`
	EventIDs []string `json:"event_ids"`
}

// StorageStatus separates logical journal accounting from physical filesystem use.
type StorageStatus struct {
	DatabaseBytes    int64      `json:"database_bytes"`
	WALBytes         int64      `json:"wal_bytes"`
	SHMBytes         int64      `json:"shm_bytes"`
	HotBytes         int64      `json:"hot_bytes"`
	ReusableBytes    int64      `json:"reusable_bytes"`
	ArchiveBytes     int64      `json:"archive_bytes"`
	ArchiveFiles     int64      `json:"archive_files"`
	DiskAvailable    uint64     `json:"disk_available"`
	ArchiveAvailable uint64     `json:"archive_available"`
	SharedVolume     bool       `json:"shared_volume"`
	AdmissionAllowed bool       `json:"admission_allowed"`
	Reason           string     `json:"reason,omitempty"`
	MeasurementError string     `json:"measurement_error,omitempty"`
	CheckpointAt     *time.Time `json:"checkpoint_at,omitempty"`
	CheckpointBusy   bool       `json:"checkpoint_busy"`
}
