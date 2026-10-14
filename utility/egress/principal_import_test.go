package egress

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestImportedPrincipalIsEncryptedScopedAndExpiresIndependentlyOfRoute(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	public, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	p, err := NewPrincipalCredential("vless", "")
	if err != nil {
		t.Fatal(err)
	}
	scope := CredentialScope{RouteID: routeID, SourceCoreID: sourceID, TargetCoreID: targetID, Revision: 9, ExpiresAt: time.Now().Add(time.Minute).Unix()}
	sealed, err := SealPrincipal(p, base64.StdEncoding.EncodeToString(public), targetID, scope)
	if err != nil {
		t.Fatal(err)
	}
	envelope := CredentialImport{ID: targetID, Kind: "principal", Scope: scope, Sealed: sealed}
	binding := PrincipalBinding{TransferID: targetID, RouteID: routeID, TargetCoreID: targetID, Revision: 9, Protocol: "vless"}
	directory := t.TempDir()
	localKey := strings.Repeat("k", 40)
	for i := 0; i < 2; i++ {
		if err = ImportPrincipal(directory, sourceID, localKey, key, envelope); err != nil {
			t.Fatal(err)
		}
	}
	opened, err := ReadPrincipal(directory, sourceID, localKey, binding)
	if err != nil || opened != p {
		t.Fatal("principal local read failed", err)
	}
	filename, _ := principalPath(directory, binding)
	data, _ := os.ReadFile(filename)
	info, _ := os.Stat(filename)
	if bytes.Contains(data, []byte(p.ID)) || info.Mode().Perm() != 0600 {
		t.Fatal("principal leaked in local storage")
	}
	if _, err = ReadPrincipal(directory, sourceID, strings.Repeat("x", 40), binding); err == nil {
		t.Fatal("wrong local key accepted")
	}
	changed := binding
	changed.TargetCoreID = routeID
	if _, err = ReadPrincipal(directory, sourceID, localKey, changed); err == nil {
		t.Fatal("wrong destination accepted")
	}
	changed = binding
	changed.Revision++
	if _, err = ReadPrincipal(directory, sourceID, localKey, changed); err == nil {
		t.Fatal("wrong revision accepted")
	}
	state, err := LoadState(filename, sourceID, localKey)
	if err != nil {
		t.Fatal(err)
	}
	state.ExpiresAt = time.Now().Add(-time.Second)
	if err = SaveState(filename, sourceID, localKey, state); err != nil {
		t.Fatal(err)
	}
	if _, err = ReadPrincipal(directory, sourceID, localKey, binding); err == nil {
		t.Fatal("expired principal accepted despite a route lease")
	}
}

func TestImportedPrincipalRenewalIsMonotonicAndCannotReviveExpiredIdentity(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	public, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	p, err := NewPrincipalCredential("vless", "xtls-rprx-vision")
	if err != nil {
		t.Fatal(err)
	}
	scope := CredentialScope{RouteID: routeID, SourceCoreID: sourceID, TargetCoreID: targetID, Revision: 9, ExpiresAt: time.Now().Add(time.Minute).Unix()}
	binding := PrincipalBinding{TransferID: targetID, RouteID: routeID, TargetCoreID: targetID, Revision: 9, Protocol: "vless"}
	directory, localKey := t.TempDir(), strings.Repeat("k", 40)
	envelope := func(credential PrincipalCredential, expires int64) CredentialImport {
		t.Helper()
		s := scope
		s.ExpiresAt = expires
		sealed, err := SealPrincipal(credential, base64.StdEncoding.EncodeToString(public), targetID, s)
		if err != nil {
			t.Fatal(err)
		}
		return CredentialImport{ID: targetID, Kind: "principal", Scope: s, Sealed: sealed}
	}
	initial := envelope(p, scope.ExpiresAt)
	if err := ImportPrincipal(directory, sourceID, localKey, key, initial); err != nil {
		t.Fatal(err)
	}
	renewal := envelope(p, scope.ExpiresAt+60)
	for i := 0; i < 2; i++ {
		if err := ImportPrincipal(directory, sourceID, localKey, key, renewal); err != nil {
			t.Fatal(err)
		}
	}
	filename, _ := principalPath(directory, binding)
	state, err := LoadState(filename, sourceID, localKey)
	if err != nil || state.ExpiresAt.Unix() != scope.ExpiresAt+60 {
		t.Fatal("renewal not persisted", err)
	}
	data, err := os.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte(p.ID)) {
		t.Fatal("renewed identity leaked")
	}
	if err := ImportPrincipal(directory, sourceID, localKey, key, initial); err == nil {
		t.Fatal("stale renewal accepted")
	}
	other, err := NewPrincipalCredential("vless", "xtls-rprx-vision")
	if err != nil {
		t.Fatal(err)
	}
	if err := ImportPrincipal(directory, sourceID, localKey, key, envelope(other, scope.ExpiresAt+90)); err == nil {
		t.Fatal("changed identity accepted")
	}
	tampered := envelope(p, scope.ExpiresAt+90)
	tampered.Scope.ExpiresAt++
	if err := ImportPrincipal(directory, sourceID, localKey, key, tampered); err == nil {
		t.Fatal("unauthenticated deadline accepted")
	}
	unchanged, err := LoadState(filename, sourceID, localKey)
	if err != nil || !unchanged.ExpiresAt.Equal(state.ExpiresAt) {
		t.Fatal("rejected renewal changed deadline", err)
	}
	shorter, longer := envelope(p, scope.ExpiresAt+90), envelope(p, scope.ExpiresAt+120)
	start := make(chan struct{})
	var concurrent sync.WaitGroup
	var longerErr error
	concurrent.Add(2)
	go func() {
		defer concurrent.Done()
		<-start
		_ = ImportPrincipal(directory, sourceID, localKey, key, shorter)
	}()
	go func() {
		defer concurrent.Done()
		<-start
		longerErr = ImportPrincipal(directory, sourceID, localKey, key, longer)
	}()
	close(start)
	concurrent.Wait()
	if longerErr != nil {
		t.Fatal("newest concurrent renewal rejected", longerErr)
	}
	latest, err := LoadState(filename, sourceID, localKey)
	if err != nil || latest.ExpiresAt.Unix() != scope.ExpiresAt+120 {
		t.Fatal("concurrent renewal regressed authorization", err)
	}
	state.ExpiresAt = time.Now().Add(-time.Second)
	if err := SaveState(filename, sourceID, localKey, state); err != nil {
		t.Fatal(err)
	}
	if err := ImportPrincipal(directory, sourceID, localKey, key, envelope(p, scope.ExpiresAt+90)); err == nil {
		t.Fatal("expired identity revived")
	}
}
