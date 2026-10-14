package egress

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"time"
)

const maxStateBytes = 4 << 20

type State struct {
	CoreID    string          `json:"coreId"`
	ExpiresAt time.Time       `json:"expiresAt"`
	Plan      json.RawMessage `json:"plan"`
}

func stateCipher(coreID, credential string) (cipher.AEAD, error) {
	if !uuid.MatchString(coreID) || len(credential) < 32 || len(credential) > 256 {
		return nil, errors.New("invalid egress state identity")
	}
	key := sha256.Sum256([]byte("nahan-egress-state-v1\x00" + coreID + "\x00" + credential))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func SaveState(filename, coreID, credential string, state State) error {
	if state.CoreID != coreID || len(state.Plan) == 0 || len(state.Plan) > maxStateBytes/2 || !json.Valid(state.Plan) || state.ExpiresAt.IsZero() || state.ExpiresAt.After(time.Now().Add(300*time.Second)) {
		return errors.New("invalid egress state")
	}
	aead, err := stateCipher(coreID, credential)
	if err != nil {
		return err
	}
	data, err := json.Marshal(state)
	if err != nil {
		return err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return err
	}
	sealed := append(nonce, aead.Seal(nil, nonce, data, []byte(coreID))...)
	if info, err := os.Lstat(filename); err == nil {
		if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
			return errors.New("unsafe egress state file")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	file, err := os.CreateTemp(filepath.Dir(filename), ".egress-state-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	if err = file.Chmod(0600); err == nil {
		_, err = file.Write(sealed)
	}
	if err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err = os.Rename(file.Name(), filename); err != nil {
		return err
	}
	directory, err := os.Open(filepath.Dir(filename))
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func LoadState(filename, coreID, credential string) (State, error) {
	var state State
	info, err := os.Lstat(filename)
	if err != nil {
		return state, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > maxStateBytes {
		return state, errors.New("unsafe egress state file")
	}
	file, err := os.Open(filename)
	if err != nil {
		return state, err
	}
	defer file.Close()
	sealed, err := io.ReadAll(io.LimitReader(file, maxStateBytes+1))
	if err != nil || len(sealed) > maxStateBytes {
		return state, errors.New("invalid egress state size")
	}
	aead, err := stateCipher(coreID, credential)
	if err != nil {
		return state, err
	}
	if len(sealed) < aead.NonceSize()+aead.Overhead() {
		return state, errors.New("invalid egress state envelope")
	}
	plain, err := aead.Open(nil, sealed[:aead.NonceSize()], sealed[aead.NonceSize():], []byte(coreID))
	if err != nil {
		return state, errors.New("egress state authentication failed")
	}
	if json.Unmarshal(plain, &state) != nil || state.CoreID != coreID || len(state.Plan) == 0 || !json.Valid(state.Plan) || state.ExpiresAt.IsZero() || state.ExpiresAt.After(time.Now().Add(300*time.Second)) {
		return State{}, errors.New("invalid egress state")
	}
	return state, nil
}
