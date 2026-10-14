package manager

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/NahaNCode/nahan-core/utility/egress"
	"github.com/xtls/xray-core/core"
)

func TestEgressPrincipalDurableRestartRetainsIdentityAndRevocation(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	public, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"vless", "vmess", "trojan"} {
		t.Run(kind, func(t *testing.T) {
			store := NewPrincipalStore(filepath.Join(t.TempDir(), "journals"), principalTarget, strings.Repeat("k", 40))
			request := PrincipalRequest{Scope: egress.CredentialScope{RouteID: principalRoute, SourceCoreID: principalSource, TargetCoreID: principalTarget, Revision: 1, ExpiresAt: time.Now().Add(time.Minute).Unix()}, Tag: "qa-principal", Protocol: kind, PublicKey: base64.StdEncoding.EncodeToString(public)}
			first, _, _ := principalFixture(t, kind)
			first.managerConfig.PrincipalStore = store
			sealed, err := first.ProvisionEgressPrincipal(principalTarget, request)
			if err != nil {
				t.Fatal(err)
			}
			credential, err := egress.OpenPrincipal(sealed, key, principalSource, request.Scope)
			if err != nil {
				t.Fatal(err)
			}
			filename, err := store.filename(request)
			if err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(filename)
			if err != nil {
				t.Fatal(err)
			}
			info, err := os.Stat(filename)
			if err != nil {
				t.Fatal(err)
			}
			secret := credential.ID
			if kind == "trojan" {
				secret = credential.Password
			}
			if info.Mode().Perm() != 0600 || bytes.Contains(data, []byte(secret)) {
				t.Fatal("destination credential leaked")
			}
			first.Close()
			second, port, customer := principalFixture(t, kind)
			second.managerConfig.PrincipalStore = store
			if err := second.RestoreEgressPrincipals(); err != nil {
				t.Fatal(err)
			}
			beforeRenewal := principalClient(t, credential, port)
			echoBeforeRenewal := principalEcho(t)
			oldCredentialConn, err := core.Dial(context.Background(), beforeRenewal, echoBeforeRenewal)
			if err != nil {
				t.Fatal(err)
			}
			defer oldCredentialConn.Close()
			if !principalRoundTrip(oldCredentialConn) {
				t.Fatal("restart required a renewal before restoring live authentication")
			}
			request.Scope.ExpiresAt += 30
			sealed, err = second.ProvisionEgressPrincipal(principalTarget, request)
			if err != nil {
				t.Fatal(err)
			}
			restored, err := egress.OpenPrincipal(sealed, key, principalSource, request.Scope)
			if err != nil || restored != credential {
				t.Fatal("restart changed principal identity", err)
			}
			client := principalClient(t, restored, port)
			echo := principalEcho(t)
			conn, err := core.Dial(context.Background(), client, echo)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			if !principalRoundTrip(conn) {
				t.Fatal("restored principal did not authenticate")
			}
			if err := second.RevokeEgressPrincipal(principalRoute, principalSource, 1); err != nil {
				t.Fatal(err)
			}
			second.Close()
			third, newPort, _ := principalFixture(t, kind)
			third.managerConfig.PrincipalStore = store
			if _, err := third.ProvisionEgressPrincipal(principalTarget, request); err == nil {
				t.Fatal("restart revived revoked principal")
			}
			request.Scope.Revision = 2
			sealed, err = third.ProvisionEgressPrincipal(principalTarget, request)
			if err != nil {
				t.Fatal(err)
			}
			rotated, err := egress.OpenPrincipal(sealed, key, principalSource, request.Scope)
			if err != nil || rotated == credential {
				t.Fatal("new revision did not rotate principal", err)
			}
			customerClient := principalClient(t, customer, newPort)
			customerConn, err := core.Dial(context.Background(), customerClient, echo)
			if err != nil {
				t.Fatal(err)
			}
			defer customerConn.Close()
			if !principalRoundTrip(customerConn) {
				t.Fatal("restart principal reconciliation changed customer authentication")
			}
		})
	}
}

func TestEgressPrincipalCompactionPreservesEncryptedReplayFence(t *testing.T) {
	store := NewPrincipalStore(filepath.Join(t.TempDir(), "private"), principalTarget, strings.Repeat("c", 64))
	request := PrincipalRequest{Staged: true, Protocol: "vless", Tag: "qa-principal", Scope: egress.CredentialScope{RouteID: principalRoute, SourceCoreID: principalSource, TargetCoreID: principalTarget, Revision: 2, ExpiresAt: time.Now().Add(-601 * time.Second).Unix()}}
	if err := store.save(principalRecord{Request: request, Revoked: true}); err != nil {
		t.Fatal(err)
	}
	filename, err := store.filename(request)
	if err != nil {
		t.Fatal(err)
	}
	if err = store.compact(); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(filename); !os.IsNotExist(err) {
		t.Fatal("expired credential not removed", err)
	}
	index, err := os.ReadFile(filepath.Join(store.directory, "retired.bin"))
	if err != nil || bytes.Contains(index, []byte(principalRoute)) {
		t.Fatal("retirement index absent or plaintext", err)
	}
	restarted := NewPrincipalStore(store.directory, principalTarget, store.key)
	request.Scope.ExpiresAt = time.Now().Add(time.Minute).Unix()
	if _, err = restarted.load(request); err == nil {
		t.Fatal("compacted revision revived after restart")
	}
	request.Scope.Revision = 3
	if value, err := restarted.load(request); err != nil || value != nil {
		t.Fatal("new revision incorrectly blocked", err)
	}
	if _, err = restarted.records(); err != nil {
		t.Fatal("retirement index prevented normal restore", err)
	}
}

func TestEgressPrincipalJournalRejectsTamperingAndExpiredRenewal(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	public, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	r := PrincipalRequest{Scope: egress.CredentialScope{RouteID: principalRoute, SourceCoreID: principalSource, TargetCoreID: principalTarget, Revision: 7, ExpiresAt: time.Now().Add(-time.Second).Unix()}, Tag: "qa-principal", Protocol: "vless", PublicKey: base64.StdEncoding.EncodeToString(public)}
	p, err := egress.NewPrincipalCredential("vless", "")
	if err != nil {
		t.Fatal(err)
	}
	store := NewPrincipalStore(filepath.Join(t.TempDir(), "journals"), principalTarget, strings.Repeat("k", 40))
	if err := store.save(principalRecord{Request: r, Credential: p}); err != nil {
		t.Fatal(err)
	}
	m, _, _ := principalFixture(t, "vless")
	m.managerConfig.PrincipalStore = store
	r.Scope.ExpiresAt = time.Now().Add(time.Minute).Unix()
	if _, err := m.ProvisionEgressPrincipal(principalTarget, r); err == nil {
		t.Fatal("expired principal revived")
	}
	filename, err := store.filename(r)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	data[len(data)-1] ^= 1
	if err := os.WriteFile(filename, data, 0600); err != nil {
		t.Fatal(err)
	}
	r.Scope.Revision++
	if _, err := m.ProvisionEgressPrincipal(principalTarget, r); err == nil {
		t.Fatal("tampered journal ignored")
	}
}

func TestEgressPrincipalStagingPreservesLiveIdentityAcrossRestart(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	public, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"vless", "vmess", "trojan"} {
		for _, staged := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/staged=%t", kind, staged), func(t *testing.T) {
				store := NewPrincipalStore(filepath.Join(t.TempDir(), "journals"), principalTarget, strings.Repeat("k", 40))
				live := PrincipalRequest{Scope: egress.CredentialScope{RouteID: principalRoute, SourceCoreID: principalSource, TargetCoreID: principalTarget, Revision: 1, ExpiresAt: time.Now().Add(time.Minute).Unix()}, Tag: "qa-principal", Protocol: kind, PublicKey: base64.StdEncoding.EncodeToString(public), Staged: staged}
				m, port, customer := principalFixture(t, kind)
				m.managerConfig.PrincipalStore = store
				sealed, err := m.ProvisionEgressPrincipal(principalTarget, live)
				if err != nil {
					t.Fatal(err)
				}
				credential, err := egress.OpenPrincipal(sealed, key, principalSource, live.Scope)
				if err != nil {
					t.Fatal(err)
				}
				echo := principalEcho(t)
				connect := func(p egress.PrincipalCredential, port int) {
					t.Helper()
					conn, err := core.Dial(context.Background(), principalClient(t, p, port), echo)
					if err != nil {
						t.Fatal(err)
					}
					defer conn.Close()
					if !principalRoundTrip(conn) {
						t.Fatal("principal authentication interrupted by candidate staging")
					}
				}
				active, err := core.Dial(context.Background(), principalClient(t, credential, port), echo)
				if err != nil {
					t.Fatal(err)
				}
				defer active.Close()
				if !principalRoundTrip(active) {
					t.Fatal("live connection unavailable")
				}
				candidate := live
				candidate.Staged = true
				candidate.Scope.Revision = 2
				candidateSealed, err := m.ProvisionEgressPrincipal(principalTarget, candidate)
				if err != nil {
					t.Fatal(err)
				}
				candidateCredential, err := egress.OpenPrincipal(candidateSealed, key, principalSource, candidate.Scope)
				if err != nil || candidateCredential == credential {
					t.Fatal("candidate identity was not independently generated", err)
				}
				if !principalRoundTrip(active) {
					t.Fatal("staging disconnected the existing live stream")
				}
				connect(credential, port)
				connect(candidateCredential, port)
				connect(customer, port)
				live.Scope.ExpiresAt += 30
				if _, err := m.ProvisionEgressPrincipal(principalTarget, live); err != nil {
					t.Fatal("candidate blocked live renewal", err)
				}
				m.Close()
				restored, restoredPort, _ := principalFixture(t, kind)
				restored.managerConfig.PrincipalStore = store
				if err := restored.RestoreEgressPrincipals(); err != nil {
					t.Fatal(err)
				}
				connect(credential, restoredPort)
				connect(candidateCredential, restoredPort)
				if err := restored.RevokeEgressPrincipal(principalRoute, principalSource, 2); err != nil {
					t.Fatal(err)
				}
				connect(credential, restoredPort)
				if _, err := restored.ProvisionEgressPrincipal(principalTarget, candidate); err == nil {
					t.Fatal("revoked candidate revived")
				}
			})
		}
	}
}
