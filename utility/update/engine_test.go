package update

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestCatalogRequiresPinnedSignatureAndFreshCompleteAssets(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	release := Release{Version: "v1.6.0", Commit: strings.Repeat("a", 40), PublishedAt: time.Now().Unix(), ExpiresAt: time.Now().Add(time.Hour).Unix(), Assets: map[string]Asset{"linux-amd64": {URL: "https://github.com/NahaNCode/nahan-core/releases/download/v1.6.0/NahaN-linux-amd64", SHA256: strings.Repeat("b", 64), Size: 1024}}}
	payload, _ := json.Marshal(release)
	data, _ := json.Marshal(Envelope{Payload: base64.StdEncoding.EncodeToString(payload), Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(private, payload))})
	key := base64.StdEncoding.EncodeToString(public)
	if _, err := Verify(data, key, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(data, base64.StdEncoding.EncodeToString(make([]byte, 32)), time.Now()); err == nil {
		t.Fatal("untrusted signer accepted")
	}
	if _, err := Verify(data, key, time.Now().Add(2*time.Hour)); err == nil {
		t.Fatal("expired release accepted")
	}
	payload[0] = 'x'
	tampered, _ := json.Marshal(Envelope{Payload: base64.StdEncoding.EncodeToString(payload), Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(private, []byte("different")))})
	if _, err := Verify(tampered, key, time.Now()); err == nil {
		t.Fatal("altered catalog accepted")
	}
	for _, url := range []string{"http://github.com/NahaNCode/nahan-core/releases/download/v1.6.0/NahaN-linux-amd64", "https://github.com/other/core/releases/download/v1.6.0/NahaN-linux-amd64", "https://evil.example/file"} {
		if allowedURL(url) {
			t.Fatal("unsafe download source accepted")
		}
	}
}
func fixture(t *testing.T) (*Engine, Request, *int) {
	t.Helper()
	dir := t.TempDir()
	binary := filepath.Join(dir, "NahaN")
	os.WriteFile(binary, []byte("old"), 0755)
	heartbeat := filepath.Join(dir, "heartbeat.json")
	os.WriteFile(filepath.Join(dir, "config.json"), []byte("{}"), 0600)
	current, _ := Hash(binary)
	Atomic(heartbeat, Receipt{CoreID: "11111111-1111-4111-8111-111111111111", Digest: current, Version: "v1.5.0", SeenAt: time.Now().Unix()})
	candidate := []byte("new")
	sum := sha256.Sum256(candidate)
	hash := hex.EncodeToString(sum[:])
	calls := 0
	profile := Profile{CoreID: "11111111-1111-4111-8111-111111111111", Unit: "nahan-test.service", Binary: binary, Config: filepath.Join(dir, "config.json"), HeartbeatFile: heartbeat, StateDir: filepath.Join(dir, "state"), Mode: "native"}
	engine := &Engine{Profile: profile, Fetch: func(context.Context) (Release, error) {
		return Release{Version: "v1.6.0", ExpiresAt: time.Now().Add(time.Hour).Unix(), Assets: map[string]Asset{runtime.GOOS + "-" + runtime.GOARCH: {SHA256: hash, Size: 3}}}, nil
	}, Download: func(_ context.Context, _ Asset, path string) error { return os.WriteFile(path, candidate, 0755) }, Run: func(_ context.Context, name string, args ...string) error {
		if name == "systemctl" {
			calls++
		}
		return nil
	}, Healthy: func(_ context.Context, digest string) bool { return digest == hash }}
	request := Request{ID: "22222222-2222-4222-8222-222222222222", Version: "v1.6.0", ExpectedDigest: current, Acknowledged: true}
	return engine, request, &calls
}
func TestUpgradeChecksCandidateAndExactBuildThenRollback(t *testing.T) {
	e, r, calls := fixture(t)
	s, err := e.Prepare(context.Background(), r)
	if err != nil || s.Stage != "prepared" {
		t.Fatal(s, err)
	}
	if *calls != 0 {
		t.Fatal("preflight restarted service")
	}
	bad := r
	bad.ExpectedDigest = strings.Repeat("f", 64)
	if _, err = e.Apply(context.Background(), bad); err == nil {
		t.Fatal("stale source build accepted")
	}
	bad = r
	bad.Acknowledged = false
	if _, err = e.Apply(context.Background(), bad); err == nil {
		t.Fatal("silent restart accepted")
	}
	s, err = e.Apply(context.Background(), r)
	if err != nil || s.Stage != "done" {
		t.Fatal(s, err)
	}
	if *calls != 1 {
		t.Fatal("unexpected restart count")
	}
	r.ExpectedDigest = s.Digest
	s, err = e.Rollback(context.Background(), r)
	if err != nil || s.Stage != "rolled_back" {
		t.Fatal(s, err)
	}
	data, _ := os.ReadFile(e.Profile.Binary)
	if string(data) != "old" {
		t.Fatal("previous binary not restored")
	}
}
func TestCorruptionNeverRestartsAndFailedHealthRestores(t *testing.T) {
	e, r, calls := fixture(t)
	if _, err := e.Prepare(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(e.Profile.StateDir, "candidate"), []byte("tampered"), 0755)
	if _, err := e.Apply(context.Background(), r); err == nil {
		t.Fatal("corrupt candidate applied")
	}
	if *calls != 0 {
		t.Fatal("restarted on corrupt candidate")
	}
	e, r, calls = fixture(t)
	e.Prepare(context.Background(), r)
	e.Healthy = func(context.Context, string) bool { return false }
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	baseRun := e.Run
	e.Run = func(ctx context.Context, name string, args ...string) error {
		err := baseRun(ctx, name, args...)
		if name == "systemctl" && *calls == 1 {
			cancel()
		}
		return err
	}
	state, err := e.Apply(ctx, r)
	if err == nil || state.Stage != "rolled_back" {
		t.Fatal(state, err)
	}
	data, _ := os.ReadFile(e.Profile.Binary)
	if string(data) != "old" || *calls != 2 {
		t.Fatal("health failure did not restore and restart previous runtime")
	}
}
func TestInterruptedSwapRecoversBeforeNewOperations(t *testing.T) {
	e, r, _ := fixture(t)
	e.Prepare(context.Background(), r)
	state, _ := e.State()
	old, _ := os.ReadFile(e.Profile.Binary)
	AtomicBytes(backupPath(e.Profile.Binary, state.ID), old, 0755)
	AtomicBytes(e.Profile.Binary, []byte("new"), 0755)
	e.save(&state, "applying")
	if err := e.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(e.Profile.Binary)
	if string(data) != "old" {
		t.Fatal("interrupted update not restored")
	}
}

func TestConfigurationAndExpiryChangesRefuseRestart(t *testing.T) {
	for _, change := range []string{"configuration", "expiry"} {
		t.Run(change, func(t *testing.T) {
			e, r, calls := fixture(t)
			if _, err := e.Prepare(context.Background(), r); err != nil {
				t.Fatal(err)
			}
			if change == "configuration" {
				os.WriteFile(e.Profile.Config, []byte("changed"), 0600)
			} else {
				state, _ := e.State()
				state.ReleaseExpiresAt = time.Now().Add(-time.Second).Unix()
				e.save(&state, "prepared")
			}
			if _, err := e.Apply(context.Background(), r); err == nil {
				t.Fatal("changed preparation accepted")
			}
			if *calls != 0 {
				t.Fatal("refused preparation restarted the core")
			}
		})
	}
}

func TestFailedNextPreparationPreservesInstalledRollback(t *testing.T) {
	e, r, _ := fixture(t)
	if _, err := e.Prepare(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	installed, err := e.Apply(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	next := r
	next.ID = "33333333-3333-4333-8333-333333333333"
	next.ExpectedDigest = installed.Digest
	e.Download = func(context.Context, Asset, string) error { return os.ErrPermission }
	e.Fetch = func(context.Context) (Release, error) {
		return Release{Version: "v1.7.0", ExpiresAt: time.Now().Add(time.Hour).Unix(), Assets: map[string]Asset{runtime.GOOS + "-" + runtime.GOARCH: {SHA256: strings.Repeat("a", 64), Size: 4}}}, nil
	}
	next.Version = "v1.7.0"
	if _, err = e.Prepare(context.Background(), next); err == nil {
		t.Fatal("failed download succeeded")
	}
	r.ExpectedDigest = installed.Digest
	if _, err = e.Rollback(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(e.Profile.Binary)
	if string(data) != "old" {
		t.Fatal("installed checkpoint was lost")
	}
}

func TestOlderCatalogCannotReplayAfterRollback(t *testing.T) {
	e, r, _ := fixture(t)
	e.setup()
	Atomic(filepath.Join(e.Profile.StateDir, "release-watermark.json"), map[string]string{"version": "v1.7.0"})
	if _, err := e.Prepare(context.Background(), r); err == nil {
		t.Fatal("older signed release replay accepted")
	}
}

func TestWritableAncestorCannotProtectInstallation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "protected")
	os.WriteFile(path, []byte("test"), 0600)
	if err := ProtectedPath(path); err == nil {
		t.Fatal("non-root or writable parent accepted")
	}
}
