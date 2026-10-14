package update

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/mod/semver"
)

type Profile struct {
	CoreUID         int    `json:"coreUid"`
	PanelURL        string `json:"panelUrl,omitempty"`
	KeyFile         string `json:"keyFile,omitempty"`
	CAFile          string `json:"caFile,omitempty"`
	ServerName      string `json:"serverName,omitempty"`
	CoreID          string `json:"coreId"`
	Unit            string `json:"unit"`
	Binary          string `json:"binary"`
	Config          string `json:"config"`
	HeartbeatFile   string `json:"heartbeatFile"`
	StateDir        string `json:"stateDir"`
	Mode            string `json:"mode"`
	ComposeFile     string `json:"composeFile,omitempty"`
	ComposeService  string `json:"composeService,omitempty"`
	ImageFile       string `json:"imageFile,omitempty"`
	ImageRepository string `json:"imageRepository,omitempty"`
}
type Status struct {
	ReleaseExpiresAt int64  `json:"releaseExpiresAt"`
	Commit           string `json:"commit"`
	ExpectedRevision int64  `json:"expectedRevision"`
	ConfigDigest     string `json:"configDigest"`
	ID               string `json:"id"`
	Stage            string `json:"stage"`
	Version          string `json:"version"`
	Digest           string `json:"digest"`
	PreviousDigest   string `json:"previousDigest"`
	PreviousVersion  string `json:"previousVersion"`
	UpdatedAt        int64  `json:"updatedAt"`
	Error            string `json:"error,omitempty"`
}
type Receipt struct {
	CoreID   string `json:"coreId"`
	Revision int64  `json:"revision"`
	Digest   string `json:"digest"`
	Version  string `json:"version"`
	SeenAt   int64  `json:"seenAt"`
}
type Request struct {
	ExpectedRevision int64  `json:"expectedRevision,omitempty"`
	JobID            string `json:"jobId,omitempty"`
	ID               string `json:"id"`
	Version          string `json:"version"`
	ExpectedDigest   string `json:"expectedDigest"`
	Acknowledged     bool   `json:"acknowledged"`
}
type Engine struct {
	Profile  Profile
	mu       sync.Mutex
	Fetch    func(context.Context) (Release, error)
	Download func(context.Context, Asset, string) error
	Run      func(context.Context, string, ...string) error
	Healthy  func(context.Context, string) bool
}

var UUIDPattern = regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`)

func (p Profile) Validate() error {
	if !UUIDPattern.MatchString(p.CoreID) || !regexp.MustCompile(`^[a-zA-Z0-9@_.-]+\.service$`).MatchString(p.Unit) || !filepath.IsAbs(p.Config) || !filepath.IsAbs(p.StateDir) || !filepath.IsAbs(p.HeartbeatFile) {
		return errors.New("invalid registered update profile")
	}
	if p.Mode == "native" {
		if !filepath.IsAbs(p.Binary) {
			return errors.New("invalid registered binary")
		}
	} else if p.Mode == "docker" {
		if !filepath.IsAbs(p.ComposeFile) || !filepath.IsAbs(p.ImageFile) || !regexp.MustCompile(`^[a-zA-Z0-9_-]+$`).MatchString(p.ComposeService) || p.ImageRepository != "ghcr.io/nahancode/nahan-core" {
			return errors.New("invalid registered container")
		}
	} else {
		return errors.New("unsupported installation")
	}
	return nil
}
func LoadProfile(path string) (Profile, error) {
	var p Profile
	if err := ProtectedPath(path); err != nil {
		return p, err
	}
	info, e := os.Lstat(path)
	if e != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 {
		return p, errors.New("unsafe update profile")
	}
	if s, ok := info.Sys().(*syscall.Stat_t); !ok || s.Uid != 0 {
		return p, errors.New("update profile must be root-owned")
	}
	b, e := os.ReadFile(path)
	if e != nil || len(b) > 8192 || json.Unmarshal(b, &p) != nil {
		return p, errors.New("invalid update profile")
	}
	return p, p.Validate()
}

// Every ancestor is checked: a protected leaf under a writable directory is not protected.
func ProtectedPath(path string) error {
	return protectedOwnerPath(path, 0)
}

func ProtectedDataPath(path string, uid int) error {
	return protectedOwnerPath(path, uint32(uid))
}

func protectedOwnerPath(path string, owner uint32) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("protected path must be absolute and canonical")
	}
	for current := path; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0022 != 0 {
			return errors.New("unsafe installation path")
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || (stat.Uid != 0 && stat.Uid != owner) {
			return errors.New("installation path has an unexpected owner")
		}
		if current == "/" {
			return nil
		}
	}
}
func Atomic(path string, value any) error {
	b, e := json.Marshal(value)
	if e != nil {
		return e
	}
	return AtomicBytes(path, b, 0600)
}
func AtomicBytes(path string, b []byte, mode os.FileMode) error {
	f, e := os.CreateTemp(filepath.Dir(path), ".update-")
	if e != nil {
		return e
	}
	name := f.Name()
	defer os.Remove(name)
	if e = f.Chmod(mode); e == nil {
		_, e = f.Write(b)
	}
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e != nil {
		return e
	}
	if ce != nil {
		return ce
	}
	if e = os.Rename(name, path); e != nil {
		return e
	}
	dir, e := os.Open(filepath.Dir(path))
	if e != nil {
		return e
	}
	defer dir.Close()
	return dir.Sync()
}
func (e *Engine) State() (Status, error) {
	var s Status
	b, err := os.ReadFile(filepath.Join(e.Profile.StateDir, "status.json"))
	if os.IsNotExist(err) {
		return Status{Stage: "idle"}, nil
	}
	if err != nil || json.Unmarshal(b, &s) != nil {
		return s, errors.New("update journal unavailable")
	}
	return s, nil
}
func (e *Engine) save(s *Status, stage string) error {
	s.Stage = stage
	s.UpdatedAt = time.Now().Unix()
	return Atomic(filepath.Join(e.Profile.StateDir, "status.json"), s)
}
func (e *Engine) setup() error {
	if err := e.Profile.Validate(); err != nil {
		return err
	}
	if e.Run == nil {
		if e.Profile.Mode != "native" {
			return errors.New("container upgrades require a verified deployment adapter")
		}
		if err := ProtectedPath(e.Profile.Binary); err != nil {
			return err
		}
		if err := ProtectedDataPath(e.Profile.Config, e.Profile.CoreUID); err != nil {
			return err
		}
	}
	if err := os.MkdirAll(e.Profile.StateDir, 0700); err != nil {
		return err
	}
	i, err := os.Lstat(e.Profile.StateDir)
	if err != nil || !i.IsDir() || i.Mode().Perm()&0077 != 0 {
		return errors.New("unsafe update state directory")
	}
	if os.Geteuid() == 0 {
		if stat, ok := i.Sys().(*syscall.Stat_t); !ok || stat.Uid != 0 {
			return errors.New("update state must be root-owned")
		}
	}
	if e.Run == nil {
		return ProtectedPath(e.Profile.StateDir)
	}
	return nil
}
func Space(path string, required int64) error {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err != nil {
		return errors.New("cannot verify update disk space")
	}
	if uint64(required) > stat.Bavail*uint64(stat.Bsize) {
		return errors.New("insufficient disk space for verified upgrade and recovery")
	}
	return nil
}
func (e *Engine) command(ctx context.Context, name string, args ...string) error {
	if e.Run != nil {
		return e.Run(ctx, name, args...)
	}
	return exec.CommandContext(ctx, name, args...).Run()
}
func (e *Engine) fetch(ctx context.Context) (Release, error) {
	if e.Fetch != nil {
		return e.Fetch(ctx)
	}
	return Catalog(ctx)
}
func (e *Engine) download(ctx context.Context, a Asset, path string) error {
	if e.Download != nil {
		return e.Download(ctx, a, path)
	}
	return Download(ctx, a, path)
}
func (e *Engine) current() (Receipt, error) {
	var receipt Receipt
	b, err := os.ReadFile(e.Profile.HeartbeatFile)
	if err == nil {
		err = json.Unmarshal(b, &receipt)
	}
	if e.Profile.Mode == "native" {
		var digest string
		digest, err = Hash(e.Profile.Binary)
		if receipt.CoreID != e.Profile.CoreID || receipt.Digest != digest {
			receipt = Receipt{CoreID: e.Profile.CoreID}
		}
		receipt.Digest = digest
		if e.Run == nil && err == nil {
			worker, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			actual, actualErr := e.running(worker)
			cancel()
			if actualErr != nil || actual != digest {
				return receipt, errors.New("running unit differs from registered binary")
			}
			if receipt.Version == "" {
				worker, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				data, versionErr := exec.CommandContext(worker, e.Profile.Binary, "version").Output()
				cancel()
				if versionErr != nil || len(data) > 4096 {
					return receipt, errors.New("installed version unavailable")
				}
				var metadata struct {
					Version string `json:"version"`
				}
				if json.Unmarshal(data, &metadata) == nil {
					receipt.Version = metadata.Version
				}
				if receipt.Version == "" {
					for _, field := range strings.Fields(string(data)) {
						if VersionPattern.MatchString(field) {
							receipt.Version = field
						}
					}
				}
				if receipt.Version == "" {
					return receipt, errors.New("installed version unavailable")
				}
			}
		}
	}
	if e.Profile.Mode == "docker" && err != nil {
		worker, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		receipt.Digest, err = e.running(worker)
	}
	if err != nil || !DigestPattern.MatchString(receipt.Digest) {
		return receipt, errors.New("running build unavailable")
	}
	return receipt, nil
}
func (e *Engine) Current() (Receipt, error) { return e.current() }
func (e *Engine) Prepare(ctx context.Context, r Request) (Status, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if err := e.setup(); err != nil {
		return Status{}, err
	}
	lock, err := os.OpenFile(filepath.Join(e.Profile.StateDir, "lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return Status{}, err
	}
	defer lock.Close()
	if syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		return Status{}, errors.New("another updater is running")
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	if !UUIDPattern.MatchString(r.ID) || !VersionPattern.MatchString(r.Version) || !DigestPattern.MatchString(r.ExpectedDigest) {
		return Status{}, errors.New("invalid update request")
	}
	old, err := e.State()
	if err != nil {
		return old, err
	}
	if old.ID == r.ID && old.Stage == "prepared" {
		return old, nil
	}
	if old.Stage == "applying" || old.Stage == "verifying" || old.Stage == "rolling_back" {
		return old, errors.New("recover interrupted update first")
	}
	current, err := e.current()
	if err != nil {
		return old, err
	}
	if current.Digest != r.ExpectedDigest {
		return old, errors.New("running build changed")
	}
	release, err := e.fetch(ctx)
	if err != nil {
		return old, err
	}
	if release.Version != r.Version {
		return old, errors.New("release candidate changed")
	}
	if VersionPattern.MatchString(current.Version) && semver.Compare(release.Version, current.Version) <= 0 {
		return old, errors.New("only a newer stable release can be prepared")
	}
	var watermark struct {
		Version string `json:"version"`
	}
	if data, err := os.ReadFile(filepath.Join(e.Profile.StateDir, "release-watermark.json")); err == nil {
		if json.Unmarshal(data, &watermark) != nil || !VersionPattern.MatchString(watermark.Version) {
			return old, errors.New("release watermark unavailable")
		}
		if semver.Compare(release.Version, watermark.Version) < 0 {
			return old, errors.New("older release catalog replay refused")
		}
	} else if !os.IsNotExist(err) {
		return old, err
	}
	if err = Atomic(filepath.Join(e.Profile.StateDir, "release-watermark.json"), map[string]string{"version": release.Version}); err != nil {
		return old, err
	}
	asset, ok := release.Assets[runtime.GOOS+"-"+runtime.GOARCH]
	if !ok {
		return old, errors.New("unsupported release architecture")
	}
	if asset.SHA256 == current.Digest {
		return old, errors.New("this build is already installed")
	}
	if err = Space(e.Profile.StateDir, asset.Size+(16<<20)); err != nil {
		return old, err
	}
	if e.Profile.Mode == "native" {
		info, statErr := os.Stat(e.Profile.Binary)
		if statErr != nil {
			return old, statErr
		}
		if err = Space(filepath.Dir(e.Profile.Binary), asset.Size*2+info.Size()*2+(16<<20)); err != nil {
			return old, err
		}
	}
	state := Status{ID: r.ID, Version: release.Version, Commit: release.Commit, ReleaseExpiresAt: release.ExpiresAt, Digest: asset.SHA256, PreviousDigest: current.Digest, PreviousVersion: current.Version}
	state.ConfigDigest, err = Hash(e.Profile.Config)
	if err != nil {
		return state, errors.New("registered configuration unavailable")
	}
	if err = e.save(&state, "downloading"); err != nil {
		return state, err
	}
	staged := filepath.Join(e.Profile.StateDir, "candidate")
	os.Remove(staged)
	if err = e.download(ctx, asset, staged); err != nil {
		return state, err
	}
	if err = e.command(ctx, staged, "update-validate", "--config", e.Profile.Config, "--core-id", e.Profile.CoreID, "--release-version", state.Version, "--release-commit", state.Commit); err != nil {
		return state, errors.New("candidate configuration validation failed")
	}
	state.ExpectedRevision, err = e.controlRevision(ctx, r.ExpectedRevision)
	if err != nil {
		return state, err
	}
	if e.Profile.Mode == "docker" {
		if !strings.HasPrefix(asset.Image, e.Profile.ImageRepository+"@sha256:") || !DigestPattern.MatchString(strings.TrimPrefix(asset.Image, e.Profile.ImageRepository+"@sha256:")) {
			return state, errors.New("signed container image unavailable")
		}
		if err = e.command(ctx, "docker", "pull", asset.Image); err != nil {
			return state, errors.New("candidate container unavailable")
		}
		if err = Atomic(filepath.Join(e.Profile.StateDir, "image.json"), asset.Image); err != nil {
			return state, err
		}
	}
	return state, e.save(&state, "prepared")
}
func (e *Engine) healthy(ctx context.Context, digest string) bool {
	if e.Healthy != nil {
		return e.Healthy(ctx, digest)
	}
	if e.command(ctx, "systemctl", "is-active", "--quiet", e.Profile.Unit) != nil && e.Profile.Mode == "native" {
		return false
	}
	b, err := os.ReadFile(e.Profile.HeartbeatFile)
	var r Receipt
	actual, actualErr := e.running(ctx)
	return actualErr == nil && actual == digest && err == nil && json.Unmarshal(b, &r) == nil && r.CoreID == e.Profile.CoreID && r.Digest == digest && r.SeenAt > time.Now().Unix()-30
}
func (e *Engine) running(ctx context.Context) (string, error) {
	var data []byte
	var err error
	if e.Profile.Mode == "native" {
		data, err = exec.CommandContext(ctx, "systemctl", "show", e.Profile.Unit, "--property=MainPID", "--value").Output()
	} else {
		container, ce := exec.CommandContext(ctx, "docker", "compose", "--env-file", e.Profile.ImageFile, "-f", e.Profile.ComposeFile, "ps", "-q", e.Profile.ComposeService).Output()
		if ce != nil || !regexp.MustCompile(`^[a-f0-9]{12,64}$`).MatchString(strings.TrimSpace(string(container))) {
			return "", errors.New("registered container unavailable")
		}
		data, err = exec.CommandContext(ctx, "docker", "inspect", "--format", "{{.State.Pid}}", strings.TrimSpace(string(container))).Output()
	}
	pid := strings.TrimSpace(string(data))
	if err != nil || !regexp.MustCompile(`^[1-9][0-9]{0,9}$`).MatchString(pid) {
		return "", errors.New("registered runtime unavailable")
	}
	return Hash(filepath.Join("/proc", pid, "exe"))
}
func (e *Engine) restart(ctx context.Context) error {
	if e.Profile.Mode == "native" {
		return e.command(ctx, "systemctl", "restart", e.Profile.Unit)
	}
	return e.command(ctx, "docker", "compose", "--env-file", e.Profile.ImageFile, "-f", e.Profile.ComposeFile, "up", "-d", "--no-deps", e.Profile.ComposeService)
}
func (e *Engine) Apply(ctx context.Context, r Request) (Status, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if !r.Acknowledged {
		return Status{}, errors.New("restart interruption acknowledgement required")
	}
	if err := e.setup(); err != nil {
		return Status{}, err
	}
	lock, err := os.OpenFile(filepath.Join(e.Profile.StateDir, "lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return Status{}, err
	}
	defer lock.Close()
	if syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		return Status{}, errors.New("another updater is running")
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	s, err := e.State()
	if err != nil {
		return s, err
	}
	if s.ID != r.ID || s.Version != r.Version || s.PreviousDigest != r.ExpectedDigest || s.Stage != "prepared" {
		return s, errors.New("prepared update changed")
	}
	if s.UpdatedAt < time.Now().Unix()-600 || s.ReleaseExpiresAt <= time.Now().Unix() {
		return s, errors.New("prepared upgrade expired")
	}
	current, err := e.current()
	if err != nil || current.Digest != s.PreviousDigest {
		return s, errors.New("running build changed")
	}
	staged := filepath.Join(e.Profile.StateDir, "candidate")
	if hash, err := Hash(staged); err != nil || hash != s.Digest {
		return s, errors.New("candidate checksum changed")
	}
	if hash, err := Hash(e.Profile.Config); err != nil || hash != s.ConfigDigest {
		return s, errors.New("registered configuration changed after preflight")
	}
	if err = e.command(ctx, staged, "update-validate", "--config", e.Profile.Config, "--core-id", e.Profile.CoreID, "--release-version", s.Version, "--release-commit", s.Commit); err != nil {
		return s, errors.New("candidate configuration changed")
	}
	if r.ExpectedRevision > 0 && r.ExpectedRevision != s.ExpectedRevision {
		return s, errors.New("prepared manifest revision changed")
	}
	if _, err = e.controlRevision(ctx, s.ExpectedRevision); err != nil {
		return s, err
	}
	target := e.Profile.Binary
	mode := os.FileMode(0755)
	var replacement []byte
	if e.Profile.Mode == "docker" {
		target = e.Profile.ImageFile
		mode = 0600
		data, err := os.ReadFile(filepath.Join(e.Profile.StateDir, "image.json"))
		var image string
		if err != nil || json.Unmarshal(data, &image) != nil {
			return s, errors.New("prepared image missing")
		}
		replacement = []byte("NAHAN_CORE_IMAGE=" + image + "\n")
	} else {
		replacement, err = os.ReadFile(staged)
		if err != nil {
			return s, err
		}
	}
	original, err := os.ReadFile(target)
	if err != nil {
		return s, err
	}
	if ctx.Err() != nil {
		return s, ctx.Err()
	}
	if err = AtomicBytes(backupPath(target, s.ID), original, mode); err != nil {
		return s, err
	}
	if err = e.save(&s, "applying"); err != nil {
		return s, err
	}
	if err = AtomicBytes(target, replacement, mode); err != nil {
		return s, err
	}
	restartErr := e.restart(ctx)
	if err = e.save(&s, "verifying"); err != nil {
		return s, err
	}
	deadline := time.Now().Add(90 * time.Second)
	for restartErr == nil && time.Now().Before(deadline) && ctx.Err() == nil {
		if e.healthy(ctx, s.Digest) {
			if err := e.save(&s, "done"); err != nil {
				return s, err
			}
			return s, Atomic(filepath.Join(e.Profile.StateDir, "installed.json"), s)
		}
		select {
		case <-ctx.Done():
		case <-time.After(time.Second):
		}
	}
	restoreCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err = AtomicBytes(target, original, mode); err != nil {
		s.Error = "restore_failed"
		e.save(&s, "failed")
		return s, errors.New("previous binary restore failed")
	}
	if err = e.restart(restoreCtx); err != nil {
		s.Error = "restore_start_failed"
		e.save(&s, "failed")
		return s, errors.New("previous runtime failed to restart")
	}
	s.Error = "candidate_health_failed"
	e.save(&s, "rolled_back")
	return s, errors.New("candidate failed health verification; previous runtime restored")
}
func (e *Engine) Rollback(ctx context.Context, r Request) (Status, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if err := e.setup(); err != nil {
		return Status{}, err
	}
	lock, err := os.OpenFile(filepath.Join(e.Profile.StateDir, "lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return Status{}, err
	}
	defer lock.Close()
	if syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		return Status{}, errors.New("another updater is running")
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	s, err := e.State()
	if err == nil && s.Stage != "done" && s.Stage != "applying" && s.Stage != "verifying" && s.Stage != "rolling_back" {
		data, readErr := os.ReadFile(filepath.Join(e.Profile.StateDir, "installed.json"))
		if readErr == nil {
			err = json.Unmarshal(data, &s)
		}
	}
	if err != nil || s.Stage != "done" || s.ID != r.ID || s.Version != r.Version || !r.Acknowledged {
		return s, errors.New("no completed upgrade to roll back")
	}
	current, err := e.current()
	if err != nil || current.Digest != r.ExpectedDigest || current.Digest != s.Digest {
		return s, errors.New("running build changed")
	}
	if err = e.canRollback(ctx, s.PreviousVersion); err != nil {
		return s, err
	}
	target := e.Profile.Binary
	mode := os.FileMode(0755)
	if e.Profile.Mode == "docker" {
		target = e.Profile.ImageFile
		mode = 0600
	}
	data, err := os.ReadFile(backupPath(target, s.ID))
	if err != nil {
		return s, errors.New("previous installation unavailable")
	}
	if e.Profile.Mode == "native" {
		hash, err := Hash(backupPath(target, s.ID))
		if err != nil || hash != s.PreviousDigest {
			return s, errors.New("previous binary checksum changed")
		}
	}
	if err = e.save(&s, "rolling_back"); err != nil {
		return s, err
	}
	if err = AtomicBytes(target, data, mode); err != nil {
		return s, err
	}
	if err = e.restart(ctx); err != nil {
		return s, err
	}
	s.Error = ""
	s.Digest = s.PreviousDigest
	s.Version = s.PreviousVersion
	return s, e.save(&s, "rolled_back")
}
func Socket(coreID string) string {
	return filepath.Join("/run/nahan-core-updater", coreID, "control.sock")
}
func (e *Engine) Recover(ctx context.Context) error {
	s, err := e.State()
	if err != nil {
		return err
	}
	if s.Stage != "applying" && s.Stage != "verifying" && s.Stage != "rolling_back" {
		return nil
	}
	target := e.Profile.Binary
	mode := os.FileMode(0755)
	if e.Profile.Mode == "docker" {
		target = e.Profile.ImageFile
		mode = 0600
	}
	data, err := os.ReadFile(backupPath(target, s.ID))
	if err != nil {
		return errors.New("recovery backup unavailable")
	}
	if e.Profile.Mode == "native" {
		if digest, err := Hash(backupPath(target, s.ID)); err != nil || digest != s.PreviousDigest {
			return errors.New("recovery backup checksum changed")
		}
	}
	if err = AtomicBytes(target, data, mode); err != nil {
		return err
	}
	if err = e.restart(ctx); err != nil {
		return err
	}
	s.Error = "interrupted_upgrade"
	return e.save(&s, "rolled_back")
}
func (s Status) String() string           { return fmt.Sprintf("%s: %s (%s)", s.ID, s.Stage, s.Version) }
func backupPath(target, id string) string { return target + ".previous-" + id }

func (e *Engine) Installed() (Status, error) {
	var state Status
	data, err := os.ReadFile(filepath.Join(e.Profile.StateDir, "installed.json"))
	if err != nil || json.Unmarshal(data, &state) != nil || !UUIDPattern.MatchString(state.ID) {
		return state, errors.New("installed rollback checkpoint unavailable")
	}
	return state, nil
}
