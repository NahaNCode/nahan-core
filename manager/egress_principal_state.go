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
		count := 0
		for _, entry := range entries {
			if entry.Name() != "retired.bin" {
				count++
			}
		}
		if count >= 512 {
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
		floors, floorErr := s.floors()
		if floorErr != nil {
			return nil, floorErr
		}
		if floors[r.Scope.RouteID+"/"+r.Scope.SourceCoreID] >= r.Scope.Revision {
			return nil, errors.New("retired journaled principal revision")
		}
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
	if len(files) > 513 {
		return nil, errors.New("destination principal journal capacity exceeded")
	}
	var records []principalRecord
	for _, file := range files {
		name := file.Name()
		if name == "retired.bin" {
			if _, err := s.floors(); err != nil {
				return nil, err
			}
			continue
		}
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

func (s *PrincipalStore) floors() (map[string]int64, error) {
	state, err := egress.LoadState(filepath.Join(s.directory, "retired.bin"), s.coreID, s.key)
	if errors.Is(err, os.ErrNotExist) {
		return make(map[string]int64), nil
	}
	if err != nil {
		return nil, err
	}
	var values map[string]int64
	if json.Unmarshal(state.Plan, &values) != nil || values == nil || len(values) > 512 {
		return nil, errors.New("invalid principal retirement index")
	}
	for key, revision := range values {
		parts := strings.Split(key, "/")
		if len(parts) != 2 || revision < 1 {
			return nil, errors.New("invalid principal retirement scope")
		}
		r := PrincipalRequest{Scope: egress.CredentialScope{RouteID: parts[0], SourceCoreID: parts[1], TargetCoreID: s.coreID, Revision: revision, ExpiresAt: time.Now().Add(time.Minute).Unix()}}
		if _, err := s.filename(r); err != nil {
			return nil, err
		}
	}
	return values, nil
}

// Compact expired credentials only after the entire job replay window, keeping
// an encrypted high-water mark so removing a file cannot resurrect its revision.
func (s *PrincipalStore) compact() error {
	if err := s.safeDirectory(); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	floors, err := s.floors()
	if err != nil {
		return err
	}
	files, err := os.ReadDir(s.directory)
	if err != nil {
		return err
	}
	var remove []string
	for _, file := range files {
		if file.Name() == "retired.bin" || strings.HasPrefix(file.Name(), ".egress-state-") {
			continue
		}
		state, err := egress.LoadState(filepath.Join(s.directory, file.Name()), s.coreID, s.key)
		if err != nil {
			return err
		}
		var record principalRecord
		if json.Unmarshal(state.Plan, &record) != nil {
			return errors.New("invalid principal journal during compaction")
		}
		filename, err := s.filename(record.Request)
		if err != nil || filepath.Base(filename) != file.Name() || state.ExpiresAt.Unix() != record.Request.Scope.ExpiresAt {
			return errors.New("principal compaction scope mismatch")
		}
		if time.Now().Unix() <= record.Request.Scope.ExpiresAt+600 {
			continue
		}
		identity := record.Request.Scope.RouteID + "/" + record.Request.Scope.SourceCoreID
		if floors[identity] < record.Request.Scope.Revision {
			floors[identity] = record.Request.Scope.Revision
		}
		if len(floors) > 512 {
			return errors.New("principal tombstone capacity reached")
		}
		remove = append(remove, filename)
	}
	if len(remove) == 0 {
		return nil
	}
	data, err := json.Marshal(floors)
	if err != nil {
		return err
	}
	if err = egress.SaveState(filepath.Join(s.directory, "retired.bin"), s.coreID, s.key, egress.State{CoreID: s.coreID, ExpiresAt: time.Now(), Plan: data}); err != nil {
		return err
	}
	for _, filename := range remove {
		if err = os.Remove(filename); err != nil {
			return err
		}
	}
	directory, err := os.Open(s.directory)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
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
