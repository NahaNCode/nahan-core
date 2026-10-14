package manager

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/NahaNCode/nahan-core/utility/egress"
)

type PrincipalStore struct {
	directory, coreID, key string
}

type principalRecord struct {
	Request    PrincipalRequest           `json:"request"`
	Credential egress.PrincipalCredential `json:"credential"`
	Revoked    bool                       `json:"revoked"`
}

func NewPrincipalStore(directory, coreID, key string) *PrincipalStore {
	return &PrincipalStore{directory: directory, coreID: coreID, key: key}
}

func (s *PrincipalStore) filename(r PrincipalRequest) (string, error) {
	scope := r.Scope
	// Expired records still carry a revision tombstone; only validate structure.
	scope.ExpiresAt = time.Now().Add(time.Minute).Unix()
	if _, err := scope.Label(); err != nil || scope.TargetCoreID != s.coreID {
		return "", errors.New("invalid destination principal state scope")
	}
	hash := sha256.Sum256([]byte(principalKey(r)))
	return filepath.Join(s.directory, hex.EncodeToString(hash[:])+".bin"), nil
}

func (s *PrincipalStore) save(record principalRecord) error {
	filename, err := s.filename(record.Request)
	if err != nil {
		return err
	}
	if !record.Revoked && (record.Credential.Validate() != nil || record.Credential.Protocol != record.Request.Protocol || record.Credential.Flow != record.Request.Flow) {
		return errors.New("invalid destination principal identity")
	}
	if err = os.MkdirAll(s.directory, 0700); err != nil {
		return err
	}
	if err = s.safeDirectory(); err != nil {
		return err
	}
	if _, err = os.Lstat(filename); errors.Is(err, os.ErrNotExist) {
		entries, listErr := os.ReadDir(s.directory)
		if listErr != nil {
			return listErr
		}
		if len(entries) >= 512 {
			return errors.New("destination principal journal capacity reached")
		}
	} else if err != nil {
		return err
	}
	data, err := json.Marshal(record)
	if err != nil {
		return err
	}
	return egress.SaveState(filename, s.coreID, s.key, egress.State{CoreID: s.coreID, ExpiresAt: time.Unix(record.Request.Scope.ExpiresAt, 0), Plan: data})
}

func (s *PrincipalStore) load(r PrincipalRequest) (*principalRecord, error) {
	if err := s.safeDirectory(); errors.Is(err, os.ErrNotExist) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	filename, err := s.filename(r)
	if err != nil {
		return nil, err
	}
	state, err := egress.LoadState(filename, s.coreID, s.key)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, errors.New("destination principal journal unavailable")
	}
	var record principalRecord
	if len(state.Plan) > 16384 || json.Unmarshal(state.Plan, &record) != nil {
		return nil, errors.New("invalid destination principal journal")
	}
	stored, err := s.filename(record.Request)
	if err != nil || stored != filename || record.Request.Scope.TargetCoreID != r.Scope.TargetCoreID || state.ExpiresAt.Unix() != record.Request.Scope.ExpiresAt {
		return nil, errors.New("destination principal journal scope mismatch")
	}
	if !record.Revoked && (record.Credential.Validate() != nil || record.Credential.Protocol != record.Request.Protocol || record.Credential.Flow != record.Request.Flow) {
		return nil, errors.New("invalid journaled principal identity")
	}
	return &record, nil
}

func (s *PrincipalStore) records() ([]principalRecord, error) {
	if err := s.safeDirectory(); errors.Is(err, os.ErrNotExist) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	files, err := os.ReadDir(s.directory)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if len(files) > 512 {
		return nil, errors.New("destination principal journal capacity exceeded")
	}
	var records []principalRecord
	for _, file := range files {
		name := file.Name()
		if strings.HasPrefix(name, ".egress-state-") {
			continue
		}
		if len(name) != 68 || filepath.Ext(name) != ".bin" {
			return nil, errors.New("unexpected destination principal journal file")
		}
		if _, err := hex.DecodeString(name[:64]); err != nil {
			return nil, errors.New("unexpected destination principal journal filename")
		}
		state, err := egress.LoadState(filepath.Join(s.directory, name), s.coreID, s.key)
		if err != nil {
			return nil, err
		}
		var record principalRecord
		if len(state.Plan) > 16384 || json.Unmarshal(state.Plan, &record) != nil {
			return nil, errors.New("invalid destination principal journal")
		}
		validated, err := s.load(record.Request)
		filename, scopeErr := s.filename(record.Request)
		if err != nil || validated == nil || scopeErr != nil || filepath.Base(filename) != name {
			return nil, errors.New("destination principal journal identity mismatch")
		}
		if !validated.Revoked && time.Now().Unix() < validated.Request.Scope.ExpiresAt {
			records = append(records, *validated)
		}
	}
	return records, nil
}

func (s *PrincipalStore) safeDirectory() error {
	info, err := os.Lstat(s.directory)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return errors.New("unsafe destination principal journal directory")
	}
	return nil
}

// Reinstall only still-live journaled identities on compatible existing handlers.
// Restoring a journal never creates a listener or extends its authorization.
func (m *Manager) RestoreEgressPrincipals() error {
	store := m.managerConfig.PrincipalStore
	if store == nil {
		return nil
	}
	records, err := store.records()
	if err != nil {
		return err
	}
	for _, record := range records {
		if time.Now().Unix() >= record.Request.Scope.ExpiresAt {
			continue
		}
		if _, err := m.principalTarget(record.Request.Tag, record.Request.Protocol); err != nil {
			continue
		}
		if _, err := m.ProvisionEgressPrincipal(store.coreID, record.Request); err != nil {
			if time.Now().Unix() >= record.Request.Scope.ExpiresAt {
				continue
			}
			return err
		}
	}
	return nil
}
