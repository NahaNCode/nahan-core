package controlplane

import (
	"context"
	"github.com/NahaNCode/nahan-core/utility/connectionpolicy"
)

func (c *Client) ConnectionPolicy(ctx context.Context) (connectionpolicy.Snapshot, error) {
	var p connectionpolicy.Snapshot
	err := c.request(ctx, "GET", "connection-policy", nil, &p)
	if err == nil {
		err = connectionpolicy.Validate(p)
	}
	return p, err
}
func (c *Client) PolicyReceipt(ctx context.Context, revision int64, code string) error {
	return c.request(ctx, "POST", "connection-policy/receipt", map[string]any{"revision": revision, "code": code}, nil)
}
