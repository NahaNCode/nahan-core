package egress

import (
	"crypto/rsa"
	"encoding/json"
	"errors"
	"github.com/NahaNCode/nahan-core/utility/entryprofile"
	"os"
	"path/filepath"
	"time"
)

type CredentialBinding struct {
	TransferID string `json:"transferId"`
	RouteID    string `json:"routeId"`
	Revision   int64  `json:"revision"`
	Method     string `json:"method"`
}
type CredentialImport struct {
	Kind   string                    `json:"kind,omitempty"`
	ID     string                    `json:"id"`
	Scope  CredentialScope           `json:"scope"`
	Sealed entryprofile.SealedResult `json:"sealed"`
}
type importedCredential struct {
	Binding    CredentialBinding `json:"binding"`
	Credential SSCredential      `json:"credential"`
}

func credentialPath(directory string, b CredentialBinding) (string, error) {
	if !uuid.MatchString(b.TransferID) || !uuid.MatchString(b.RouteID) || b.Revision < 1 {
		return "", errors.New("invalid imported credential binding")
	}
	return filepath.Join(directory, b.TransferID+".bin"), nil
}

func ImportCredential(directory, coreID, credential string, key *rsa.PrivateKey, envelope CredentialImport) error {
	plain, err := OpenCredential(envelope.Sealed, key, coreID, envelope.Scope)
	if err != nil {
		return err
	}
	binding := CredentialBinding{TransferID: envelope.ID, RouteID: envelope.Scope.RouteID, Revision: envelope.Scope.Revision, Method: plain.Method}
	filename, err := credentialPath(directory, binding)
	if err != nil {
		return err
	}
	if _, err = os.Lstat(filename); err == nil {
		previous, err := ReadCredential(directory, coreID, credential, binding)
		if err != nil || previous != plain {
			return errors.New("imported credential identity conflict")
		}
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err = os.MkdirAll(directory, 0700); err != nil {
		return err
	}
	data, _ := json.Marshal(importedCredential{Binding: binding, Credential: plain})
	return SaveState(filename, coreID, credential, State{CoreID: coreID, ExpiresAt: time.Now().Add(300 * time.Second), Plan: data})
}

// Transfer expiry limits delivery. Use of an already-delivered local credential
// is separately authorized by the live route lease, not by extending delivery.
func ReadCredential(directory, coreID, credential string, b CredentialBinding) (SSCredential, error) {
	var result importedCredential
	filename, err := credentialPath(directory, b)
	if err != nil {
		return SSCredential{}, err
	}
	state, err := LoadState(filename, coreID, credential)
	if err != nil {
		return SSCredential{}, err
	}
	if json.Unmarshal(state.Plan, &result) != nil || result.Binding != b || !validCredential(result.Credential) || result.Credential.Method != b.Method {
		return SSCredential{}, errors.New("imported credential scope mismatch")
	}
	return result.Credential, nil
}
