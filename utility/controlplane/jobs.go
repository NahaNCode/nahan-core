package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/NahaNCode/nahan-core/utility/egress"
	"github.com/NahaNCode/nahan-core/utility/entryprofile"
	updater "github.com/NahaNCode/nahan-core/utility/update"
	"github.com/xtls/xray-core/core"
	"path/filepath"
)

func (c *Client) SecretDirectory() string {
	return filepath.Join(filepath.Dir(c.Config.KeyFile), "entry-secrets")
}
func (c *Client) ProcessJobs(ctx context.Context) error {
	var jobs []struct {
		ID      string          `json:"id"`
		Kind    string          `json:"kind"`
		Payload json.RawMessage `json:"payload"`
	}
	if err := c.request(ctx, "GET", "jobs", nil, &jobs); err != nil {
		return err
	}
	for _, job := range jobs {
		result := map[string]any{"valid": false, "engineVersion": core.Version(), "code": "job_rejected"}
		if job.Kind == "upgrade-prepare" || job.Kind == "upgrade-apply" || job.Kind == "upgrade-rollback" {
			var request updater.Request
			if json.Unmarshal(job.Payload, &request) != nil || request.JobID != job.ID || !updater.UUIDPattern.MatchString(request.ID) || (job.Kind == "upgrade-prepare" && request.ID != job.ID) {
				result["code"] = "upgrade_rejected"
			} else {
				var state, failure updater.Status
				if updater.Call(ctx, c.Config.CoreID, "GET", "status", nil, &state) != nil {
					result["code"] = "updater_unavailable"
				} else {
					updater.Call(ctx, c.Config.CoreID, "GET", "failure", nil, &failure)
					if failure.ID == request.ID {
						result["code"] = "upgrade_failed"
					} else if state.ID == request.ID && ((job.Kind == "upgrade-prepare" && state.Stage == "prepared") || (job.Kind == "upgrade-apply" && state.Stage == "done") || (job.Kind == "upgrade-rollback" && state.Stage == "rolled_back")) {
						result["valid"], result["code"], result["digest"] = true, "", state.Digest
					} else if state.ID == request.ID && (state.Stage == "rolled_back" || state.Stage == "failed") {
						result["code"] = "upgrade_failed"
					} else {
						action := "prepare"
						if job.Kind == "upgrade-apply" {
							action = "apply"
						}
						if job.Kind == "upgrade-rollback" {
							action = "rollback"
						}
						if state.ID != request.ID || state.Stage == "prepared" || state.Stage == "idle" || (job.Kind == "upgrade-rollback" && state.Stage == "done") {
							updater.Call(ctx, c.Config.CoreID, "POST", action, request, nil)
						}
						continue
					}
				}
			}
		} else if job.Kind == "preflight" {
			profile, err := entryprofile.Resolve(job.Payload, c.SecretDirectory(), c.Config.CoreID)
			if err == nil {
				built := entryprofile.Preflight(profile)
				if built.Valid {
					if code := entryprofile.ProbeReality(ctx, profile); code != "" {
						built.Valid = false
						built.Code = code
					}
				}
				result["valid"] = built.Valid
				result["code"] = built.Code
				result["digest"] = built.Digest
			} else {
				result["code"] = "secret_resolution_failed"
			}
		} else if job.Kind == "egress-external-import" {
			var request egress.ExternalImport
			if json.Unmarshal(job.Payload, &request) == nil && request.Scope.ID == job.ID {
				key, _, err := egress.RecipientIdentity(filepath.Join(filepath.Dir(c.Config.KeyFile), "egress-recipient.key"))
				if err == nil {
					err = egress.ImportExternal(c.ExternalOutboundDirectory(), c.Config.CoreID, c.Key, key, request)
				}
				if err == nil {
					result["valid"], result["code"], result["digest"] = true, "", request.Digest
				}
			}
		} else if job.Kind == "egress-ss-export" {
			var payload struct {
				Profile   json.RawMessage        `json:"profile"`
				PublicKey string                 `json:"publicKey"`
				Scope     egress.CredentialScope `json:"scope"`
			}
			if json.Unmarshal(job.Payload, &payload) == nil {
				sealed, err := egress.ExportCredential(payload.Profile, c.SecretDirectory(), c.Config.CoreID, payload.PublicKey, payload.Scope)
				if err == nil {
					result["valid"] = true
					result["code"] = ""
					result["ciphertext"] = sealed.Ciphertext
					result["wrappedKey"] = sealed.WrappedKey
					result["nonce"] = sealed.Nonce
				}
			}
		} else if job.Kind == "egress-principal" || job.Kind == "egress-principal-staged" {
			payload := job.Payload
			if job.Kind == "egress-principal-staged" {
				var request map[string]json.RawMessage
				if json.Unmarshal(payload, &request) == nil && request != nil {
					request["staged"] = json.RawMessage(`true`)
					payload, _ = json.Marshal(request)
				} else {
					payload = nil
				}
			}
			if c.PrincipalProvision != nil && len(payload) > 0 {
				sealed, err := c.PrincipalProvision(payload, c.Config.CoreID)
				if err == nil {
					result["valid"], result["code"] = true, ""
					result["ciphertext"], result["wrappedKey"], result["nonce"] = sealed.Ciphertext, sealed.WrappedKey, sealed.Nonce
				}
			}
		} else if job.Kind == "ss-test-config" {
			var sealed entryprofile.SealedResult
			var err error
			if c.SSTrial == nil {
				err = errors.New("trial runtime unavailable")
			} else {
				sealed, err = c.SSTrial(job.Payload, c.Config.CoreID, job.ID)
			}
			if err == nil {
				result["valid"] = true
				result["code"] = ""
				result["ciphertext"] = sealed.Ciphertext
				result["wrappedKey"] = sealed.WrappedKey
				result["nonce"] = sealed.Nonce
			}
		} else if job.Kind == "reality-key" || job.Kind == "tls-certificate" || job.Kind == "shadowsocks-password" {
			var payload struct {
				ServerName string `json:"serverName"`
				Method     string `json:"method"`
			}
			if json.Unmarshal(job.Payload, &payload) == nil {
				if job.Kind == "shadowsocks-password" {
					payload.ServerName = payload.Method
				}
				metadata, err := entryprofile.GenerateSecret(c.SecretDirectory(), c.Config.CoreID, job.ID, job.Kind, payload.ServerName)
				if err == nil {
					for key, value := range metadata {
						result[key] = value
					}
					result["valid"] = true
					result["code"] = ""
				}
			}
		}
		if err := c.request(ctx, "POST", "jobs/"+job.ID+"/result", result, nil); err != nil {
			return err
		}
	}
	return nil
}
