package egress

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/NahaNCode/nahan-core/utility/entryprofile"
)

const sourceID = "11111111-1111-4111-8111-111111111111"
const targetID = "22222222-2222-4222-8222-222222222222"
const routeID = "33333333-3333-4333-8333-333333333333"

func TestCredentialRelayedWithoutPlaintextAndBoundToRecipientRouteRevision(t *testing.T) {
	directory := t.TempDir()
	key, public, err := RecipientIdentity(filepath.Join(directory, "recipient.key"))
	if err != nil {
		t.Fatal(err)
	}
	keyAgain, publicAgain, err := RecipientIdentity(filepath.Join(directory, "recipient.key"))
	if err != nil || publicAgain != public || keyAgain.N.Cmp(key.N) != 0 {
		t.Fatal("identity did not persist")
	}
	metadata, err := entryprofile.GenerateSecret(directory, targetID, routeID, "shadowsocks-password", "2022-blake3-aes-128-gcm")
	if err != nil {
		t.Fatal(err)
	}
	profile, _ := json.Marshal(map[string]any{"protocol": "shadowsocks", "settings": map[string]any{"method": "2022-blake3-aes-128-gcm", "password": metadata["reference"]}})
	scope := CredentialScope{RouteID: routeID, SourceCoreID: sourceID, TargetCoreID: targetID, Revision: 7, ExpiresAt: time.Now().Add(time.Minute).Unix()}
	sealed, err := ExportCredential(profile, directory, targetID, public, scope)
	if err != nil {
		t.Fatal(err)
	}
	credential, err := OpenCredential(sealed, key, sourceID, scope)
	if err != nil || credential.Password == "" {
		t.Fatal("recipient failed", err)
	}
	changed := scope
	changed.Revision++
	if _, err = OpenCredential(sealed, key, sourceID, changed); err == nil {
		t.Fatal("replayed another revision")
	}
	changed = scope
	changed.RouteID = sourceID
	if _, err = OpenCredential(sealed, key, sourceID, changed); err == nil {
		t.Fatal("replayed another route")
	}
	if _, err = OpenCredential(sealed, key, targetID, scope); err == nil {
		t.Fatal("wrong source accepted")
	}
	other, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = OpenCredential(sealed, other, sourceID, scope); err == nil {
		t.Fatal("wrong recipient accepted")
	}
	changed = scope
	changed.ExpiresAt = time.Now().Add(-time.Second).Unix()
	if _, err = OpenCredential(sealed, key, sourceID, changed); err == nil {
		t.Fatal("expired credential accepted")
	}
	sealed.Nonce = ""
	if _, err = OpenCredential(sealed, key, sourceID, scope); err == nil {
		t.Fatal("invalid nonce accepted")
	}
}
func TestExportRejectsInlineAndCrossCoreCredentials(t *testing.T) {
	directory := t.TempDir()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	public, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	scope := CredentialScope{RouteID: routeID, SourceCoreID: sourceID, TargetCoreID: targetID, Revision: 1, ExpiresAt: time.Now().Add(time.Minute).Unix()}
	for _, password := range []string{"inline-password", "secret://core/" + sourceID + "/" + routeID, "secret://core/" + targetID + "/../../etc/passwd"} {
		profile, _ := json.Marshal(map[string]any{"protocol": "shadowsocks", "settings": map[string]any{"method": "aes-128-gcm", "password": password}})
		if _, err = ExportCredential(profile, directory, targetID, base64.StdEncoding.EncodeToString(public), scope); err == nil {
			t.Fatal("unowned key exported")
		}
	}
}
func TestRecipientRejectsSymlinksAndPubliclyReadableFiles(t *testing.T) {
	dir := t.TempDir()
	filename := filepath.Join(dir, "key")
	if err := os.WriteFile(filename, []byte("invalid"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := RecipientIdentity(filename); err == nil {
		t.Fatal("unsafe key accepted")
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(filename, link); err != nil {
		t.Fatal(err)
	}
	if _, _, err := RecipientIdentity(link); err == nil {
		t.Fatal("symlink accepted")
	}
}
