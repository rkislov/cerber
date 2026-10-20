// SPDX-License-Identifier: Apache-2.0
package agent

import (
	"context"
	"errors"
	"github.com/rkislov/cerber/internal/domain"
	"github.com/rkislov/cerber/internal/inventory"
	"github.com/rkislov/cerber/internal/jobs"
	"strings"
	"time"
)

type JobStore interface {
	Queue
	LocalJob(context.Context, string) (jobs.Journal, error)
	StartLocalJob(context.Context, string, string) error
	SaveLocalJob(context.Context, string, jobs.Result) error
	CompleteLocalJob(context.Context, string, string) error
}
type JobClient interface {
	Sender
	ClaimJob(context.Context) (*jobs.Job, error)
	FinishJob(context.Context, jobs.Result) error
}
type Worker struct {
	Store   JobStore
	Client  JobClient
	AgentID string
	Execute func(context.Context, jobs.Job) jobs.Result
}

// Step runs on the agent collection loop, never concurrently with native collection.
// A durable started marker prevents repeating work after a crash; result retries
// flush the immutable report before acknowledging completion to the server.
func (w Worker) Step(ctx context.Context) error {
	journal, err := w.Store.LocalJob(ctx, w.AgentID)
	if errors.Is(err, domain.ErrNotFound) {
		job, e := w.Client.ClaimJob(ctx)
		if e != nil {
			return e
		}
		if job == nil {
			return nil
		}
		if err = w.Store.StartLocalJob(ctx, w.AgentID, job.ID); err != nil {
			return err
		}
		runCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
		result := w.Execute(runCtx, *job)
		cancel()
		result.JobID = job.ID
		if result.Validate() != nil {
			result = jobs.Result{JobID: job.ID, Status: "failed", Code: "collection_failed"}
		}
		if err = w.Store.SaveLocalJob(ctx, w.AgentID, result); err != nil {
			return err
		}
		journal = jobs.Journal{JobID: job.ID, Result: &result}
	} else if err != nil {
		return err
	}
	if journal.Result == nil {
		result := jobs.Result{JobID: journal.JobID, Status: "failed", Code: "interrupted"}
		if err = w.Store.SaveLocalJob(ctx, w.AgentID, result); err != nil {
			return err
		}
		journal.Result = &result
	}
	if journal.Result.ReportID != "" {
		if _, err = Flush(ctx, w.Store, w.Client, w.AgentID); err != nil {
			return err
		}
	}
	err = w.Client.FinishJob(ctx, *journal.Result)
	if err != nil && !errors.Is(err, jobs.ErrTerminal) {
		return err
	}
	return w.Store.CompleteLocalJob(ctx, w.AgentID, journal.JobID)
}
func JobResult(job jobs.Job, s inventory.Snapshot, reportID string) jobs.Result {
	complete := true
	osOK, componentsOK, updatesOK := false, false, false
	for _, c := range s.Coverage {
		if c.Section == "os" {
			osOK = c.Status == "complete"
		}
		if c.Section == "updates_available" {
			updatesOK = c.Status == "complete"
		}
		if c.Section == "applications" || c.Section == "packages" || c.Section == "components" {
			componentsOK = componentsOK || c.Status == "complete"
		}
		if !strings.HasPrefix(c.Section, "updates_") && (c.Status == "partial" || c.Status == "error") {
			complete = false
		}
	}
	complete = complete && osOK && componentsOK
	if job.Kind == "updates" {
		complete = complete && updatesOK
	}
	result := jobs.Result{JobID: job.ID, Status: "partial", Code: "partial_coverage", ReportID: reportID}
	if complete {
		result.Status = "succeeded"
		result.Code = "complete"
	}
	return result
}
