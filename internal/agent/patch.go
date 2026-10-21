// SPDX-License-Identifier: Apache-2.0
package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/rkislov/cerber/internal/patch"
	"os"
	"path/filepath"
	"time"
)

type PatchClient interface {
	ClaimPatch(context.Context) (*patch.Ticket, error)
	FinishPatch(context.Context, patch.Result) error
}

func PatchStep(ctx context.Context, client PatchClient, inbox, outbox string) error {
	t, e := client.ClaimPatch(ctx)
	if e != nil || t == nil {
		return e
	}
	var q patch.Request
	if json.Unmarshal(t.Payload, &q) != nil || q.Validate() != nil {
		return patch.ErrInvalid
	}
	var r patch.Result
	e = patch.ReadJSON(filepath.Join(outbox, q.ID+".json"), &r)
	if e == nil {
		if r.Validate(q) != nil {
			return patch.ErrInvalid
		}
		return client.FinishPatch(ctx, r)
	}
	if !os.IsNotExist(e) {
		return e
	}
	path := filepath.Join(inbox, q.ID+".json")
	if _, e = os.Stat(path); e == nil {
		return nil
	}
	if !os.IsNotExist(e) {
		return e
	}
	if time.Now().After(q.ExpiresAt) {
		r = patch.Failure(q, "authorization_expired_before_submission")
		return client.FinishPatch(ctx, r)
	}
	if e = patch.WriteJSON(path, t); e != nil {
		return fmt.Errorf("patch spool: %w", e)
	}
	return nil
}
