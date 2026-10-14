package controlplane

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
)

func (c *Client) ExitRouting(ctx context.Context, ips []string) (EgressDocument, error) {
	var document EgressDocument
	if err := c.request(ctx, "POST", "exit-routing/report", map[string]any{"runtimeVersion": 1, "ips": ips}, nil); err != nil {
		return document, err
	}
	if err := c.request(ctx, "GET", "exit-routing", nil, &document); err != nil {
		return document, err
	}
	if document.Revision < 1 || len(document.PlanJSON) > 1<<20 || !json.Valid([]byte(document.PlanJSON)) {
		return document, errors.New("invalid exit document")
	}
	digest := sha256.Sum256([]byte(document.PlanJSON))
	var plan struct {
		Revision int64 `json:"revision"`
	}
	if hex.EncodeToString(digest[:]) != document.Digest || json.Unmarshal([]byte(document.PlanJSON), &plan) != nil || plan.Revision != document.Revision {
		return document, errors.New("exit document digest or revision mismatch")
	}
	return document, nil
}

func (c *Client) ExitRoutingReceipt(ctx context.Context, document EgressDocument, code string) error {
	return c.request(ctx, "POST", "exit-routing/receipt", map[string]any{"revision": document.Revision, "digest": document.Digest, "code": code}, nil)
}
