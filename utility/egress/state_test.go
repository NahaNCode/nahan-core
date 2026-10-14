package egress

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestEncryptedStateIdentityTamperingAndExpiredRestore(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state")
	credential := strings.Repeat("a", 64)
	expired := time.Now().Add(-time.Minute).UTC()
	secret := strings.Repeat("qa-secret", 4)
	payload, err := json.Marshal(map[string]string{"password": secret})
	if err != nil {
		t.Fatal(err)
	}
	state := State{CoreID: sourceID, ExpiresAt: expired, Plan: payload}
	if err := SaveState(path, sourceID, credential, state); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte(secret)) {
		t.Fatal("secret persisted in plaintext")
	}
	restored, err := LoadState(path, sourceID, credential)
	if err != nil || !restored.ExpiresAt.Equal(expired) {
		t.Fatal("expired lease was renewed", err)
	}
	if _, err = LoadState(path, targetID, credential); err == nil {
		t.Fatal("other core restored state")
	}
	if _, err = LoadState(path, sourceID, strings.Repeat("b", 64)); err == nil {
		t.Fatal("wrong key restored state")
	}
	data[len(data)-1] ^= 1
	if err = os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = LoadState(path, sourceID, credential); err == nil {
		t.Fatal("tampered state accepted")
	}
}
func TestStateRejectsUnsafeFileAndFutureLease(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state")
	credential := strings.Repeat("a", 64)
	state := State{CoreID: sourceID, ExpiresAt: time.Now().Add(time.Hour), Plan: []byte(`{}`)}
	if SaveState(path, sourceID, credential, state) == nil {
		t.Fatal("unbounded lease persisted")
	}
	state.ExpiresAt = time.Now().Add(time.Minute)
	if err := os.WriteFile(path, []byte("untrusted"), 0644); err != nil {
		t.Fatal(err)
	}
	if SaveState(path, sourceID, credential, state) == nil {
		t.Fatal("publicly readable file replaced")
	}
	if _, err := LoadState(path, sourceID, credential); err == nil {
		t.Fatal("unsafe file loaded")
	}
	link := path + "-link"
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if SaveState(link, sourceID, credential, state) == nil {
		t.Fatal("symlink replaced")
	}
}
func TestRestoredRegistryCannotRenewExpiredLease(t *testing.T) {
	var r Registry
	if err := r.Replace(snapshot(1, "old"), func(string) bool { return true }); err != nil {
		t.Fatal(err)
	}
	r.RestrictLease(time.Now().Add(-time.Second))
	r.RestrictLease(time.Now().Add(time.Hour))
	if _, managed, expired := r.Lookup("entry-1"); !managed || !expired {
		t.Fatal("restart authorization lease renewed")
	}
}
