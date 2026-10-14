package egress

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"testing"
	"time"
)

func TestPrincipalCredentialsAreIndependentScopedAndDomainSeparated(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	public, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	recipient := base64.StdEncoding.EncodeToString(public)
	scope := CredentialScope{RouteID: routeID, SourceCoreID: sourceID, TargetCoreID: targetID, Revision: 3, ExpiresAt: time.Now().Add(time.Minute).Unix()}
	for _, kind := range []string{"vless", "vmess", "trojan"} {
		t.Run(kind, func(t *testing.T) {
			first, err := NewPrincipalCredential(kind, "")
			if err != nil {
				t.Fatal(err)
			}
			second, err := NewPrincipalCredential(kind, "")
			if err != nil || first == second {
				t.Fatal("principal credential reused")
			}
			sealed, err := SealPrincipal(first, recipient, targetID, scope)
			if err != nil {
				t.Fatal(err)
			}
			opened, err := OpenPrincipal(sealed, key, sourceID, scope)
			if err != nil || opened != first {
				t.Fatal("principal recipient failed", err)
			}
			if _, err = OpenCredential(sealed, key, sourceID, scope); err == nil {
				t.Fatal("principal confused with SS credential")
			}
			changed := scope
			changed.Revision++
			if _, err = OpenPrincipal(sealed, key, sourceID, changed); err == nil {
				t.Fatal("another revision accepted")
			}
			if _, err = OpenPrincipal(sealed, key, targetID, scope); err == nil {
				t.Fatal("another core accepted")
			}
			if _, err = SealPrincipal(first, recipient, sourceID, scope); err == nil {
				t.Fatal("another destination exported")
			}
		})
	}
	for _, kind := range []string{"shadowsocks", "freedom", "unknown", ""} {
		if _, err := NewPrincipalCredential(kind, ""); err == nil {
			t.Fatal("unsupported principal accepted")
		}
	}
	if _, err := NewPrincipalCredential("vmess", "xtls-rprx-vision"); err == nil {
		t.Fatal("invalid flow accepted")
	}
	if _, err := NewPrincipalCredential("vless", "xtls-rprx-vision"); err != nil {
		t.Fatal(err)
	}
}
