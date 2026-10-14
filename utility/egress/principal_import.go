package egress

import (
	"crypto/rsa"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"
)

var principalImportMu sync.Mutex

type PrincipalBinding struct {
	TransferID   string `json:"transferId"`
	RouteID      string `json:"routeId"`
	TargetCoreID string `json:"targetCoreId"`
	Revision     int64  `json:"revision"`
	Protocol     string `json:"protocol"`
}

type importedPrincipal struct {
	Binding    PrincipalBinding    `json:"binding"`
	Credential PrincipalCredential `json:"credential"`
}

func principalPath(directory string, b PrincipalBinding) (string, error) {
	if !uuid.MatchString(b.TransferID) || !uuid.MatchString(b.RouteID) || !uuid.MatchString(b.TargetCoreID) || b.Revision < 1 || (b.Protocol != "vless" && b.Protocol != "vmess" && b.Protocol != "trojan") {
		return "", errors.New("invalid principal binding")
	}
	return filepath.Join(directory, b.TransferID+".principal.bin"), nil
}

func ImportPrincipal(directory, coreID, localKey string, key *rsa.PrivateKey, envelope CredentialImport) error {
	p, err := OpenPrincipal(envelope.Sealed, key, coreID, envelope.Scope)
	if err != nil {
		return err
	}
	binding := PrincipalBinding{TransferID: envelope.ID, RouteID: envelope.Scope.RouteID, TargetCoreID: envelope.Scope.TargetCoreID, Revision: envelope.Scope.Revision, Protocol: p.Protocol}
	filename, err := principalPath(directory, binding)
	if err != nil {
		return err
	}
	deadline := time.Unix(envelope.Scope.ExpiresAt, 0)
	// A delivered principal has its own authorization deadline, not just a route lease.
	if deadline.After(time.Now().Add(300 * time.Second)) {
		return errors.New("principal authorization exceeds local lifetime")
	}
	principalImportMu.Lock()
	defer principalImportMu.Unlock()
	if _, err = os.Lstat(filename); err == nil {
		previous, err := ReadPrincipal(directory, coreID, localKey, binding)
		if err != nil || previous != p {
			return errors.New("principal import identity conflict")
		}
		state, err := LoadState(filename, coreID, localKey)
		if err != nil || deadline.Before(state.ExpiresAt) {
			return errors.New("principal authorization deadline conflict")
		}
		if state.ExpiresAt.Equal(deadline) {
			return nil
		}
		// Only an authenticated renewal of the same live identity may extend
		// its deadline. The existing read above prevents reviving expired state.
		state.ExpiresAt = deadline
		return SaveState(filename, coreID, localKey, state)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err = os.MkdirAll(directory, 0700); err != nil {
		return err
	}
	data, _ := json.Marshal(importedPrincipal{Binding: binding, Credential: p})
	return SaveState(filename, coreID, localKey, State{CoreID: coreID, ExpiresAt: deadline, Plan: data})
}

func ReadPrincipal(directory, coreID, localKey string, b PrincipalBinding) (PrincipalCredential, error) {
	var result importedPrincipal
	filename, err := principalPath(directory, b)
	if err != nil {
		return result.Credential, err
	}
	state, err := LoadState(filename, coreID, localKey)
	if err != nil {
		return result.Credential, err
	}
	if !time.Now().Before(state.ExpiresAt) || json.Unmarshal(state.Plan, &result) != nil || result.Binding != b || result.Credential.Protocol != b.Protocol || result.Credential.Validate() != nil {
		return PrincipalCredential{}, errors.New("principal authorization unavailable")
	}
	return result.Credential, nil
}
