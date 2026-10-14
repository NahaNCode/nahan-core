package egress

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/NahaNCode/nahan-core/utility/entryprofile"
)

// PrincipalCredential belongs to a core-to-core route, never a customer identity.
type PrincipalCredential struct {
	Protocol string `json:"protocol"`
	ID       string `json:"id,omitempty"`
	Password string `json:"password,omitempty"`
	Flow     string `json:"flow,omitempty"`
}

func (p PrincipalCredential) Validate() error {
	switch p.Protocol {
	case "vless", "vmess":
		if !uuid.MatchString(p.ID) || p.Password != "" || (p.Flow != "" && (p.Protocol != "vless" || p.Flow != "xtls-rprx-vision")) {
			return errors.New("invalid infrastructure principal")
		}
	case "trojan":
		data, err := base64.RawURLEncoding.DecodeString(p.Password)
		if err != nil || len(data) != 32 || p.ID != "" || p.Flow != "" {
			return errors.New("invalid infrastructure principal")
		}
	default:
		return errors.New("unsupported infrastructure principal protocol")
	}
	return nil
}

func NewPrincipalCredential(protocol, flow string) (PrincipalCredential, error) {
	p := PrincipalCredential{Protocol: protocol, Flow: flow}
	var random [32]byte
	if _, err := rand.Read(random[:]); err != nil {
		return p, err
	}
	if protocol == "trojan" {
		p.Password = base64.RawURLEncoding.EncodeToString(random[:])
	} else {
		random[6] = random[6]&15 | 64
		random[8] = random[8]&63 | 128
		p.ID = fmt.Sprintf("%x-%x-%x-%x-%x", random[:4], random[4:6], random[6:8], random[8:10], random[10:16])
	}
	return p, p.Validate()
}

func SealPrincipal(p PrincipalCredential, recipient, targetCoreID string, scope CredentialScope) (entryprofile.SealedResult, error) {
	label, err := scope.Label()
	if err != nil || targetCoreID != scope.TargetCoreID || p.Validate() != nil {
		return entryprofile.SealedResult{}, errors.New("principal export scope rejected")
	}
	data, _ := json.Marshal(p)
	return entryprofile.Seal(data, recipient, label+":principal-v1")
}

func OpenPrincipal(sealed entryprofile.SealedResult, key *rsa.PrivateKey, sourceCoreID string, scope CredentialScope) (PrincipalCredential, error) {
	var p PrincipalCredential
	plain, err := openEnvelope(sealed, key, sourceCoreID, scope, ":principal-v1")
	if err != nil {
		return p, err
	}
	if json.Unmarshal(plain, &p) != nil || p.Validate() != nil {
		return PrincipalCredential{}, errors.New("invalid infrastructure principal")
	}
	return p, nil
}
