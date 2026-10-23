// Build-time, version-pinned lifecycle fixes without modifying the module cache.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

const pinnedXray = "v1.260327.1-0.20261021115930-1b1647cd9ddf"

type change struct{ file, old, replacement string }

func main() {
	if err := generate(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func generate() error {
	if !supportedToolchain(runtime.Version()) {
		return fmt.Errorf("review Xray TLS layouts and security fixes for toolchain %s; use Go 1.27.3", runtime.Version())
	}
	data, err := exec.Command("go", "list", "-m", "-json", "github.com/xtls/xray-core").Output()
	if err != nil {
		return err
	}
	var module struct{ Dir, Version string }
	if err = json.Unmarshal(data, &module); err != nil {
		return err
	}
	if module.Version != pinnedXray {
		return fmt.Errorf("review lifecycle fixes for new Xray version %s", module.Version)
	}
	if module.Dir == "" {
		data, err = exec.Command("go", "mod", "download", "-json", "github.com/xtls/xray-core@"+module.Version).Output()
		if err != nil {
			return err
		}
		if err = json.Unmarshal(data, &module); err != nil {
			return err
		}
		if module.Dir == "" {
			return fmt.Errorf("pinned Xray source unavailable")
		}
	}
	dir, err := os.MkdirTemp("", "nahan-xray-patch-")
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		if !ok {
			os.RemoveAll(dir)
		}
	}()
	patched := filepath.Join(dir, "xray")
	err = filepath.WalkDir(module.Dir, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(module.Dir, path)
		if err != nil {
			return err
		}
		target := filepath.Join(patched, rel)
		if entry.IsDir() {
			return os.MkdirAll(target, 0700)
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(target, content, 0600)
	})
	if err != nil {
		return err
	}
	// Native SS2022 replaced singbridge. Preserve cleanup on every return.
	changes := []change{
		{"proxy/shadowsocks_2022/outbound.go", "\tctx, cancel := context.WithCancel(ctx)\n", "\tctx, cancel := context.WithCancel(ctx)\n\tdefer cancel()\n\tdefer common.Interrupt(link.Reader)\n\tdefer common.Interrupt(link.Writer)\n\tif newCancel != nil { defer newCancel() }\n"},
		{"proxy/shadowsocks_2022/outbound.go", "\tctx = policy.ContextWithBufferPolicy(ctx, sessionPolicy.Buffer)", "\tdefer timer.SetTimeout(0)\n\tctx = policy.ContextWithBufferPolicy(ctx, sessionPolicy.Buffer)"},
		{"proxy/shadowsocks_2022/stream.go", "\tctx, cancel := context.WithCancel(ctx)\n", "\tctx, cancel := context.WithCancel(ctx)\n\tdefer cancel()\n"},
	}
	for _, c := range changes {
		path := filepath.Join(patched, c.file)
		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if strings.Count(string(content), c.old) != 1 {
			return fmt.Errorf("patch anchor mismatch: %s", c.file)
		}
		if err = os.WriteFile(path, []byte(strings.Replace(string(content), c.old, c.replacement, 1)), 0600); err != nil {
			return err
		}
	}
	modfile := filepath.Join(dir, "build.mod")
	for source, target := range map[string]string{"go.mod": modfile, "go.sum": filepath.Join(dir, "build.sum")} {
		content, err := os.ReadFile(source)
		if err != nil {
			return err
		}
		if err = os.WriteFile(target, content, 0600); err != nil {
			return err
		}
	}
	if output, err := exec.Command("go", "mod", "edit", "-modfile="+modfile, "-replace=github.com/xtls/xray-core="+patched).CombinedOutput(); err != nil {
		return fmt.Errorf("prepare patched module: %w: %s", err, output)
	}
	ok = true
	fmt.Println(modfile)
	return nil
}

func supportedToolchain(version string) bool { return version == "go1.27.3" }
