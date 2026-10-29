// SPDX-License-Identifier: Apache-2.0
// Package eventcollector contains native readers and durable spool orchestration.
package eventcollector

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/rkislov/cerber/internal/telemetry"
)

type Runner func(context.Context, string, ...string) ([]byte, error)
type Source interface {
	Read(context.Context, string) ([]telemetry.Raw, error)
	Name() string
}
type Native struct {
	Source string
	Runner Runner
}

func (n Native) Name() string { return n.Source }

type capped struct{ bytes.Buffer }

func (b *capped) Write(p []byte) (int, error) {
	if b.Len()+len(p) > telemetry.MaxBatchBytes {
		return 0, errors.New("native event output limit; cursor retained")
	}
	return b.Buffer.Write(p)
}
func run(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	var out, errout capped
	cmd.Stdout = &out
	cmd.Stderr = &errout
	if e := cmd.Run(); e != nil {
		return nil, fmt.Errorf("native event reader failed (%s): %w", filepath.Base(name), e)
	}
	if errout.Len() > 0 {
		return nil, errors.New("native event reader reported warnings; cursor retained")
	}
	return out.Bytes(), nil
}
func (n Native) Read(ctx context.Context, cursor string) ([]telemetry.Raw, error) {
	if n.Source == "network:cef" || !telemetry.ValidSource(n.Source) || len(cursor) > 2048 || strings.ContainsAny(cursor, "\x00\r\n") {
		return nil, telemetry.ErrInvalid
	}
	runner := n.Runner
	if runner == nil {
		runner = run
		if n.Source == "journald" && runtime.GOOS != "linux" || n.Source != "journald" && runtime.GOOS != "windows" {
			return nil, errors.New("native event source requires its target OS")
		}
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	var data []byte
	var e error
	if n.Source == "journald" {
		args := []string{"--no-pager", "--quiet", "--output=json", "--all", "--output-fields=__CURSOR,__REALTIME_TIMESTAMP,MESSAGE,SYSLOG_IDENTIFIER,_COMM,_UID,_EXE,_TRANSPORT,_HOSTNAME", "--lines=100", "--reverse"}
		// journalctl --lines selects the newest entries. For incremental reads use
		// streaming forward order and stop after 100, preserving backlog rather than tailing it.
		if cursor != "" {
			args = []string{"--no-pager", "--quiet", "--output=json", "--all", "--output-fields=__CURSOR,__REALTIME_TIMESTAMP,MESSAGE,SYSLOG_IDENTIFIER,_COMM,_UID,_EXE,_TRANSPORT,_HOSTNAME", "--after-cursor=" + cursor}
			return n.readJournalStream(ctx, runner, args)
		}
		data, e = runner(ctx, "journalctl", args...)
		if e != nil {
			return nil, e
		}
		records, e := parseJournal(data)
		if e != nil {
			return nil, e
		}
		for i, j := 0, len(records)-1; i < j; i, j = i+1, j-1 {
			records[i], records[j] = records[j], records[i]
		}
		return records, nil
	}
	// Windows uses a per-record cursor containing record ID and source time.
	// A reset/cleared channel is detected before reading, rather than silently skipping.
	channel := strings.TrimPrefix(n.Source, "windows:")
	last := int64(0)
	if cursor != "" {
		parts := strings.Split(cursor, "|")
		if len(parts) != 2 {
			return nil, telemetry.ErrInvalid
		}
		last, e = strconv.ParseInt(parts[0], 10, 64)
		if e != nil || last < 1 {
			return nil, telemetry.ErrInvalid
		}
	}
	root := os.Getenv("SystemRoot")
	if root == "" && n.Runner == nil {
		return nil, errors.New("SystemRoot missing")
	}
	script := fmt.Sprintf(`$ErrorActionPreference='Stop'; [Console]::OutputEncoding=New-Object System.Text.UTF8Encoding($false); $channel='%s'; $last=%d; $latest=Get-WinEvent -LogName $channel -MaxEvents 1; if($last -gt 0){ $parts='%s'.Split('|'); $anchor=@(Get-WinEvent -LogName $channel -FilterXPath "*[System[EventRecordID=$last]]" -ErrorAction SilentlyContinue); if($anchor.Count -ne 1 -or $anchor[0].TimeCreated.ToUniversalTime().ToString('o') -ne $parts[1]){throw 'Event channel cursor unavailable; explicit reset required'} }; $filter="*[System[EventRecordID > $last]]"; if($last -eq 0){$events=@(Get-WinEvent -LogName $channel -MaxEvents 100 | Sort-Object RecordId)} elseif($latest.RecordId -le $last){$events=@()}else{$events=@(Get-WinEvent -LogName $channel -FilterXPath $filter -Oldest -MaxEvents 100)}; foreach($ev in $events){$x=[xml]$ev.ToXml(); $fields=@{}; foreach($d in $x.Event.EventData.Data){if($d.Name){$fields[[string]$d.Name]=[string]$d.'#text'}}; if($ev.Id -eq 1102 -and $ev.ProviderName -eq 'Microsoft-Windows-Eventlog'){foreach($d in $x.Event.UserData.LogFileCleared.ChildNodes){if($d.LocalName -in @('SubjectUserSid','SubjectUserName','SubjectDomainName','SubjectLogonId')){$fields[[string]$d.LocalName]=[string]$d.InnerText}}}; @{record_id=[string]$ev.RecordId; event_id=$ev.Id; time=$ev.TimeCreated.ToUniversalTime().ToString('o'); provider=$ev.ProviderName;computer=$ev.MachineName;fields=$fields;xml=$ev.ToXml()}|ConvertTo-Json -Compress -Depth 5}`, channel, last, cursor)
	// cursor originates locally, nevertheless never interpolate arbitrary text in PowerShell.
	if cursor != "" {
		parts := strings.Split(cursor, "|")
		if _, e = time.Parse(time.RFC3339Nano, parts[1]); e != nil {
			return nil, telemetry.ErrInvalid
		}
	}
	data, e = runner(ctx, filepath.Join(root, "System32", "WindowsPowerShell", "v1.0", "powershell.exe"), "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script)
	if e != nil {
		return nil, e
	}
	d := json.NewDecoder(bytes.NewReader(bytes.TrimPrefix(data, []byte{239, 187, 191})))
	out := []telemetry.Raw{}
	for {
		var v struct {
			RecordID string `json:"record_id"`
			Time     string `json:"time"`
		}
		var raw json.RawMessage
		e = d.Decode(&raw)
		if e == io.EOF {
			break
		}
		if e != nil {
			return nil, e
		}
		if json.Unmarshal(raw, &v) != nil {
			return nil, telemetry.ErrInvalid
		}
		id, e := strconv.ParseInt(v.RecordID, 10, 64)
		if e != nil || id < 1 {
			return nil, telemetry.ErrInvalid
		}
		if _, e = time.Parse(time.RFC3339Nano, v.Time); e != nil {
			return nil, e
		}
		c := v.RecordID + "|" + v.Time
		out = append(out, telemetry.Raw{ID: telemetry.ID(n.Source, c), Source: n.Source, Cursor: c, ObservedAt: time.Now().UTC(), Data: raw})
	}
	return bounded(out)
}
func (n Native) readJournalStream(ctx context.Context, runner Runner, args []string) ([]telemetry.Raw, error) {
	if n.Runner != nil {
		data, e := runner(ctx, "journalctl", args...)
		if e != nil {
			return nil, e
		}
		return parseJournal(data)
	}
	// Stream to a bounded decoder; kill only after a complete page has been decoded.
	cmd := exec.CommandContext(ctx, "journalctl", args...)
	pipe, e := cmd.StdoutPipe()
	if e != nil {
		return nil, e
	}
	var stderr capped
	cmd.Stderr = &stderr
	if e = cmd.Start(); e != nil {
		return nil, e
	}
	d := json.NewDecoder(io.LimitReader(pipe, telemetry.MaxBatchBytes+1))
	out := []telemetry.Raw{}
	for len(out) < telemetry.MaxRecords {
		var raw json.RawMessage
		e = d.Decode(&raw)
		if e == io.EOF {
			e = nil
			break
		}
		if e != nil {
			break
		}
		r, err := journalRecord(raw)
		if err != nil {
			e = err
			break
		}
		out = append(out, r)
	}
	full := len(out) == telemetry.MaxRecords
	if full || e != nil {
		_ = cmd.Process.Kill()
	}
	wait := cmd.Wait()
	if e != nil {
		return nil, e
	}
	if stderr.Len() > 0 {
		return nil, errors.New("journal cursor unavailable or access warning; cursor retained")
	}
	if !full && wait != nil {
		return nil, wait
	}
	return bounded(out)
}
func parseJournal(data []byte) ([]telemetry.Raw, error) {
	d := json.NewDecoder(bytes.NewReader(data))
	out := []telemetry.Raw{}
	for {
		var raw json.RawMessage
		e := d.Decode(&raw)
		if e == io.EOF {
			break
		}
		if e != nil {
			return nil, e
		}
		r, e := journalRecord(raw)
		if e != nil {
			return nil, e
		}
		out = append(out, r)
	}
	return bounded(out)
}
func journalRecord(raw json.RawMessage) (telemetry.Raw, error) {
	var v struct {
		Cursor string `json:"__CURSOR"`
	}
	if json.Unmarshal(raw, &v) != nil || v.Cursor == "" {
		return telemetry.Raw{}, telemetry.ErrInvalid
	}
	return telemetry.Raw{ID: telemetry.ID("journald", v.Cursor), Source: "journald", Cursor: v.Cursor, ObservedAt: time.Now().UTC(), Data: raw}, nil
}
func bounded(out []telemetry.Raw) ([]telemetry.Raw, error) {
	if len(out) > telemetry.MaxRecords {
		return nil, errors.New("native event page overflow; cursor retained")
	}
	return out, nil
}

type Spool interface {
	SourceCursor(context.Context, string, string) (string, error)
	Enqueue(context.Context, telemetry.Batch, string, string, string) error
	NextBatch(context.Context, string) (telemetry.Batch, error)
	Ack(context.Context, telemetry.Batch, telemetry.Receipt) error
}
type Sender interface {
	SendEvents(context.Context, telemetry.Batch) (telemetry.Receipt, error)
}

func Cycle(ctx context.Context, spool Spool, sender Sender, agent string, sources []Source, onError func(error)) telemetry.CollectorHealth {
	result := telemetry.CollectorHealth{Enabled: len(sources) > 0, ObservedAt: time.Now().UTC(), Delivery: "idle", Sources: []telemetry.SourceHealth{}}
	flush := func() {
		for i := 0; i < 20; i++ {
			b, e := spool.NextBatch(ctx, agent)
			if errors.Is(e, telemetry.ErrNotFound) {
				return
			}
			if e != nil {
				result.Delivery = "error"
				onError(e)
				return
			}
			r, e := sender.SendEvents(ctx, b)
			if e == nil {
				e = spool.Ack(ctx, b, r)
			}
			if e != nil {
				result.Delivery = "error"
				onError(e)
				return
			}
			result.Delivery = "ok"
			now := time.Now().UTC()
			result.LastDeliveryAt = &now
		}
	}
	flush()
	for _, source := range sources {
		status := telemetry.SourceHealth{Source: source.Name(), State: "error", Code: "spool_error"}
		collect := func() {
			c, e := spool.SourceCursor(ctx, agent, source.Name())
			if e != nil {
				onError(e)
				return
			}
			records, e := source.Read(ctx, c)
			if e != nil {
				status.Code = "source_read_failed"
				onError(fmt.Errorf("%s: %w", source.Name(), e))
				return
			}
			if len(records) > 0 {
				b := telemetry.Batch{SchemaVersion: 1, AgentID: agent, Records: records}
				var nonce [32]byte
				if _, e = rand.Read(nonce[:]); e != nil {
					onError(e)
					return
				}
				b.ID = hex.EncodeToString(nonce[:])
				if e = spool.Enqueue(ctx, b, source.Name(), c, records[len(records)-1].Cursor); e != nil {
					if errors.Is(e, telemetry.ErrFull) {
						status.State = "blocked"
						status.Code = "spool_full"
					}
					onError(e)
					return
				}
			}
			status.State = "ok"
			status.Code = ""
			now := time.Now().UTC()
			status.LastReadAt = &now
		}
		collect()
		result.Sources = append(result.Sources, status)
	}
	flush()
	if q, ok := spool.(interface {
		EventQueueUsage(context.Context, string) (int64, int64, error)
	}); ok {
		count, size, e := q.EventQueueUsage(ctx, agent)
		if e == nil {
			result.QueueKnown = true
			result.QueueBatches = count
			result.QueueBytes = size
		} else {
			onError(e)
		}
	}
	result.ObservedAt = time.Now().UTC()
	return result
}

// ObservedSource preserves original records and cursor semantics while allowing passive local IOC evaluation.
type ObservedSource struct {
	Source
	Observe func([]telemetry.Raw)
}

func (s ObservedSource) Read(ctx context.Context, cursor string) ([]telemetry.Raw, error) {
	records, e := s.Source.Read(ctx, cursor)
	if e == nil && s.Observe != nil {
		s.Observe(records)
	}
	return records, e
}
