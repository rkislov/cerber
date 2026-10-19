// SPDX-License-Identifier: Apache-2.0
package app

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/rkislov/cerber/internal/domain"
	"github.com/rkislov/cerber/internal/event"
	"github.com/rkislov/cerber/internal/ports"
)

type Service struct {
	Repo    ports.Repository
	Scanner ports.Scanner
}

func (s Service) AddAsset(ctx context.Context, ip, name string) (domain.Asset, error) {
	canonical, err := domain.CanonicalIP(ip)
	if err != nil {
		return domain.Asset{}, err
	}
	if name == "" {
		name = canonical
	}
	if err = domain.ValidateName(name); err != nil {
		return domain.Asset{}, err
	}
	id, err := domain.NewID()
	if err != nil {
		return domain.Asset{}, err
	}
	a := domain.Asset{ID: id, IP: canonical, Name: name, CreatedAt: time.Now().UTC()}
	e, err := event.New("asset.created", id, a)
	if err != nil {
		return a, err
	}
	return a, s.Repo.CreateAsset(ctx, a, e)
}
func (s Service) AddTarget(ctx context.Context, name string, ids []string) (domain.Target, error) {
	if err := domain.ValidateName(name); err != nil {
		return domain.Target{}, err
	}
	if len(ids) < 1 || len(ids) > 256 {
		return domain.Target{}, fmt.Errorf("target requires 1–256 assets")
	}
	seen := map[string]bool{}
	for _, id := range ids {
		if id == "" || seen[id] {
			return domain.Target{}, fmt.Errorf("empty or duplicate asset ID")
		}
		seen[id] = true
	}
	id, err := domain.NewID()
	if err != nil {
		return domain.Target{}, err
	}
	t := domain.Target{ID: id, Name: name, AssetIDs: append([]string{}, ids...), CreatedAt: time.Now().UTC()}
	e, err := event.New("target.created", id, t)
	if err != nil {
		return t, err
	}
	return t, s.Repo.CreateTarget(ctx, t, e)
}
func (s Service) CreateTask(ctx context.Context, targetID string, config domain.ScanConfig) (domain.Task, error) {
	hosts, err := s.Repo.TargetHosts(ctx, targetID)
	if err != nil {
		return domain.Task{}, err
	}
	config, err = config.Normalize(len(hosts))
	if err != nil {
		return domain.Task{}, err
	}
	id, err := domain.NewID()
	if err != nil {
		return domain.Task{}, err
	}
	t := domain.Task{ID: id, TargetID: targetID, Hosts: hosts, Config: config, Status: domain.Queued, CreatedAt: time.Now().UTC()}
	e, err := event.New("task.created", id, t)
	if err != nil {
		return t, err
	}
	return t, s.Repo.CreateTask(ctx, t, e)
}

// Run executes a persisted snapshot. It never silently restarts an old task.
func (s Service) Run(ctx context.Context, id string) error {
	if s.Scanner == nil {
		return fmt.Errorf("scanner is not configured")
	}
	t, err := s.Repo.Task(ctx, id)
	if err != nil {
		return err
	}
	if t.Status != domain.Queued {
		return fmt.Errorf("task is %s: %w", t.Status, domain.ErrConflict)
	}
	e, err := event.New("task.started", id, map[string]any{"task_id": id, "status": domain.Running})
	if err != nil {
		return err
	}
	if err = s.Repo.ClaimTask(ctx, id, e); err != nil {
		return err
	}
	scanErr := s.Scanner.Scan(ctx, t, func(o domain.Observation) error {
		e, err := event.New("scan.port_observed", id, o)
		if err != nil {
			return err
		}
		// Preserve a completed probe during graceful shutdown.
		persist, stop := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer stop()
		return s.Repo.RecordObservation(persist, o, e)
	})
	status, detail := domain.Completed, ""
	if scanErr != nil {
		status, detail = domain.Failed, scanErr.Error()
		if errors.Is(scanErr, context.Canceled) || errors.Is(scanErr, context.DeadlineExceeded) {
			status = domain.Interrupted
		}
	}
	finalCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	e, err = event.New("task.finished", id, map[string]any{"task_id": id, "status": status, "error": detail})
	if err == nil {
		err = s.Repo.FinishTask(finalCtx, id, status, detail, e)
	}
	return errors.Join(scanErr, err)
}
