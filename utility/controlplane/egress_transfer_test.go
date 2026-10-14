package controlplane

import (
	"context"
	"encoding/json"
	"github.com/NahaNCode/nahan-core/utility/egress"
	"github.com/NahaNCode/nahan-core/utility/entryprofile"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestEgressProductionExportJobDeliveredOnlyToSourceCore(t *testing.T) {
	const sourceID = "11111111-1111-4111-8111-111111111111"
	const targetID = "22222222-2222-4222-8222-222222222222"
	const routeID = "33333333-3333-4333-8333-333333333333"
	const jobID = "44444444-4444-4444-8444-444444444444"
	scope := egress.CredentialScope{RouteID: routeID, SourceCoreID: sourceID, TargetCoreID: targetID, Revision: 2, ExpiresAt: time.Now().Add(time.Minute).Unix()}
	var mu sync.Mutex
	var public string
	var sealed entryprofile.SealedResult
	var productionProfile json.RawMessage
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		path := r.URL.Path
		if strings.Contains(path, sourceID) {
			if r.Header.Get("Authorization") != "Bearer "+strings.Repeat("a", 64) {
				w.WriteHeader(401)
				return
			}
			if strings.HasSuffix(path, "/egress/identity") {
				var identity struct {
					PublicKey string `json:"publicKey"`
				}
				if json.NewDecoder(r.Body).Decode(&identity) != nil {
					w.WriteHeader(400)
					return
				}
				if public != "" && public != identity.PublicKey {
					t.Error("identity changed")
				}
				public = identity.PublicKey
				w.Write([]byte(`{}`))
				return
			}
			if strings.HasSuffix(path, "/egress/credentials") {
				if sealed.Ciphertext == "" {
					w.Write([]byte(`[]`))
					return
				}
				json.NewEncoder(w).Encode([]egress.CredentialImport{{ID: jobID, Scope: scope, Sealed: sealed}})
				return
			}
		}
		if strings.Contains(path, targetID) {
			if r.Header.Get("Authorization") != "Bearer "+strings.Repeat("b", 64) {
				w.WriteHeader(401)
				return
			}
			if strings.HasSuffix(path, "/jobs") {
				json.NewEncoder(w).Encode([]map[string]any{{"id": jobID, "kind": "egress-ss-export", "payload": map[string]any{"scope": scope, "profile": productionProfile, "publicKey": public}}})
				return
			}
			if strings.HasSuffix(path, "/jobs/"+jobID+"/result") {
				var result struct {
					Valid      bool   `json:"valid"`
					Code       string `json:"code"`
					Ciphertext string `json:"ciphertext"`
					WrappedKey string `json:"wrappedKey"`
					Nonce      string `json:"nonce"`
				}
				if json.NewDecoder(r.Body).Decode(&result) != nil || !result.Valid || result.Code != "" {
					t.Error("production export job failed")
				}
				sealed = entryprofile.SealedResult{Ciphertext: result.Ciphertext, WrappedKey: result.WrappedKey, Nonce: result.Nonce}
				w.Write([]byte(`{}`))
				return
			}
		}
		w.WriteHeader(404)
	}))
	defer server.Close()
	newClient := func(id, key string) *Client {
		file := filepath.Join(t.TempDir(), "core.key")
		if err := os.WriteFile(file, []byte(key), 0600); err != nil {
			t.Fatal(err)
		}
		c, err := New(&Config{CoreID: id, KeyFile: file, APIHost: server.URL})
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	source := newClient(sourceID, strings.Repeat("a", 64))
	target := newClient(targetID, strings.Repeat("b", 64))
	metadata, err := entryprofile.GenerateSecret(target.SecretDirectory(), targetID, routeID, "shadowsocks-password", "2022-blake3-aes-128-gcm")
	if err != nil {
		t.Fatal(err)
	}
	productionProfile, _ = json.Marshal(map[string]any{"protocol": "shadowsocks", "settings": map[string]any{"method": "2022-blake3-aes-128-gcm", "password": metadata["reference"]}})
	if err = source.SyncEgressCredentials(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err = target.ProcessJobs(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err = source.SyncEgressCredentials(context.Background()); err != nil {
		t.Fatal(err)
	}
	binding := egress.CredentialBinding{TransferID: jobID, RouteID: routeID, Revision: 2, Method: "2022-blake3-aes-128-gcm"}
	credential, err := egress.ReadCredential(source.ImportedCredentialDirectory(), sourceID, source.Key, binding)
	if err != nil || credential.Password == "" {
		t.Fatal("source cannot load imported production credential", err)
	}
	raw, _ := os.ReadFile(filepath.Join(source.ImportedCredentialDirectory(), jobID+".bin"))
	if strings.Contains(string(raw), credential.Password) {
		t.Fatal("source file contains plaintext password")
	}
	if _, err = egress.ReadCredential(source.ImportedCredentialDirectory(), targetID, target.Key, binding); err == nil {
		t.Fatal("destination identity loaded source credential")
	}
	if err = source.SyncEgressCredentials(context.Background()); err != nil {
		t.Fatal("delivery retry failed", err)
	}
}
