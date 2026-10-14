package controlplane

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/NahaNCode/nahan-core/utility/egress"
	"path/filepath"
)

type EgressDocument struct {
	Revision int64  `json:"revision"`
	Digest   string `json:"digest"`
	PlanJSON string `json:"planJson"`
}

func (c *Client) ImportedCredentialDirectory() string {
	return filepath.Join(filepath.Dir(c.Config.KeyFile), "egress-credentials")
}
func (c *Client) SyncEgressCredentials(ctx context.Context) error {
	key, public, err := egress.RecipientIdentity(filepath.Join(filepath.Dir(c.Config.KeyFile), "egress-recipient.key"))
	if err != nil {
		return err
	}
	principalRuntime := 0
	if c.PrincipalProvision != nil {
		principalRuntime = 1
		if c.PrincipalDurable {
			principalRuntime = 4
		}
	}
	if err = c.request(ctx, "POST", "egress/identity", map[string]any{"publicKey": public, "principalRuntimeVersion": principalRuntime}, nil); err != nil {
		return err
	}
	var imports []egress.CredentialImport
	if err = c.request(ctx, "GET", "egress/credentials", nil, &imports); err != nil {
		return err
	}
	if len(imports) > 20 {
		return errors.New("oversized credential delivery")
	}
	for _, envelope := range imports {
		switch envelope.Kind {
		case "", "ss":
			err = egress.ImportCredential(c.ImportedCredentialDirectory(), c.Config.CoreID, c.Key, key, envelope)
		case "principal":
			err = egress.ImportPrincipal(c.ImportedCredentialDirectory(), c.Config.CoreID, c.Key, key, envelope)
		default:
			err = errors.New("unsupported credential delivery kind")
		}
		if err != nil {
			return err
		}
	}
	return nil
}

type EgressControl struct {
	CredentialRuntimeVersion int             `json:"credentialRuntimeVersion"`
	Desired                  *EgressDocument `json:"desired"`
	Prepared                 *EgressDocument `json:"prepared"`
}

func (d EgressDocument) Validate() error {
	if d.Revision < 1 || len(d.PlanJSON) > 1<<20 || !json.Valid([]byte(d.PlanJSON)) {
		return errors.New("invalid egress control document")
	}
	digest := sha256.Sum256([]byte(d.PlanJSON))
	if hex.EncodeToString(digest[:]) != d.Digest {
		return errors.New("egress document digest mismatch")
	}
	var plan struct {
		Snapshot struct {
			Revision int64 `json:"revision"`
		} `json:"snapshot"`
	}
	if json.Unmarshal([]byte(d.PlanJSON), &plan) != nil || plan.Snapshot.Revision != d.Revision {
		return errors.New("egress document revision mismatch")
	}
	return nil
}

func (c *Client) Egress(ctx context.Context) (EgressControl, error) {
	var state EgressControl
	err := c.request(ctx, "GET", "egress", nil, &state)
	if err != nil {
		return state, err
	}
	for _, d := range []*EgressDocument{state.Desired, state.Prepared} {
		if d != nil {
			if err = d.Validate(); err != nil {
				return EgressControl{}, err
			}
		}
	}
	return state, nil
}
func (c *Client) EgressReceipt(ctx context.Context, phase string, document EgressDocument, code string) error {
	return c.request(ctx, "POST", "egress/receipt", map[string]any{"phase": phase, "revision": document.Revision, "digest": document.Digest, "code": code}, nil)
}
