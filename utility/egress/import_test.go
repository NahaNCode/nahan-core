package egress

import (
	"encoding/json"
	"github.com/NahaNCode/nahan-core/utility/entryprofile"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestImportedCredentialIsEncryptedPersistentScopedAndIdempotent(t *testing.T) {
	dir := t.TempDir()
	key, public, err := RecipientIdentity(filepath.Join(dir, "key"))
	if err != nil {
		t.Fatal(err)
	}
	credential := SSCredential{Method: "aes-128-gcm", Password: "production-credential-never-plaintext"}
	data, _ := json.Marshal(credential)
	scope := CredentialScope{RouteID: routeID, SourceCoreID: sourceID, TargetCoreID: targetID, Revision: 4, ExpiresAt: time.Now().Add(time.Minute).Unix()}
	label, err := scope.Label()
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := entryprofile.Seal(data, public, label)
	if err != nil {
		t.Fatal(err)
	}
	envelope := CredentialImport{ID: routeID, Scope: scope, Sealed: sealed}
	localKey := strings.Repeat("a", 64)
	if err = ImportCredential(dir, sourceID, localKey, key, envelope); err != nil {
		t.Fatal(err)
	}
	filename := filepath.Join(dir, routeID+".bin")
	bytes, err := os.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(bytes), credential.Password) {
		t.Fatal("plaintext credential persisted")
	}
	if err = ImportCredential(dir, sourceID, localKey, key, envelope); err != nil {
		t.Fatal(err)
	}
	again, _ := os.ReadFile(filename)
	if string(again) != string(bytes) {
		t.Fatal("retry rewrote immutable imported credential")
	}
	binding := CredentialBinding{TransferID: routeID, RouteID: routeID, Revision: 4, Method: credential.Method}
	loaded, err := ReadCredential(dir, sourceID, localKey, binding)
	if err != nil || loaded != credential {
		t.Fatal("credential restore failed", err)
	}
	for _, change := range []func(*CredentialBinding){func(b *CredentialBinding) { b.RouteID = targetID }, func(b *CredentialBinding) { b.Revision = 5 }, func(b *CredentialBinding) { b.Method = "aes-256-gcm" }, func(b *CredentialBinding) { b.TransferID = "../../unsafe" }} {
		bad := binding
		change(&bad)
		if _, err = ReadCredential(dir, sourceID, localKey, bad); err == nil {
			t.Fatal("cross scope reference accepted")
		}
	}
	if _, err = ReadCredential(dir, targetID, localKey, binding); err == nil {
		t.Fatal("cross core credential loaded")
	}
}
