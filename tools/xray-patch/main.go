// Build-time, version-pinned lifecycle fixes without modifying the module cache.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func main() {
	if err := generate(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func generate() error {
	data, err := exec.Command("go", "list", "-m", "-json", "github.com/xtls/xray-core").Output()
	if err != nil {
		return err
	}
	var module struct{ Dir, Version string }
	if err := json.Unmarshal(data, &module); err != nil {
		return err
	}
	if module.Version != "v1.260327.1-0.20260728075948-5ca6f4b7d4dc" {
		return fmt.Errorf("review lifecycle fixes for new Xray version %s", module.Version)
	}
	if module.Dir == "" {
		download, err := exec.Command("go", "mod", "download", "-json", "github.com/xtls/xray-core@"+module.Version).Output()
		if err != nil {
			return fmt.Errorf("download pinned Xray: %w", err)
		}
		var fetched struct {
			Dir   string
			Error string
		}
		if err = json.Unmarshal(download, &fetched); err != nil {
			return err
		}
		if fetched.Dir == "" || fetched.Error != "" {
			return fmt.Errorf("pinned Xray source unavailable")
		}
		module.Dir = fetched.Dir
	}
	dir, err := os.MkdirTemp("", "nahan-xray-patch-")
	if err != nil {
		return err
	}
	changes := []struct{ file, old, replacement string }{
		{"common/singbridge/packet.go", "func (w *PacketConnWrapper) Close() error {", "func (w *PacketConnWrapper) Close() error {\n\tif w.T != nil { w.T.SetTimeout(0) }"},
		{"proxy/shadowsocks_2022/inbound.go", "return bufio.CopyPacketConn(ctx, conn, outConn)", "defer outConn.T.SetTimeout(0)\n\treturn bufio.CopyPacketConn(ctx, conn, outConn)"},
		{"common/singbridge/packet.go", "return M.Socksaddr{}, nil", "return M.Socksaddr{}, err"},
		{"common/singbridge/pipe.go", "func (w *PipeConnWrapper) Close() error {\n\treturn nil", "func (w *PipeConnWrapper) Close() error {\n\tw.T.SetTimeout(0)\n\treturn nil"},
		{"common/singbridge/pipe.go", "conn.T = signal.CancelAfterInactivity(ctx, cancel, 300*time.Second)", "conn.T = signal.CancelAfterInactivity(ctx, cancel, 300*time.Second)\n\tdefer conn.T.SetTimeout(0)"},
		{"proxy/shadowsocks_2022/outbound.go", "if session.TimeoutOnlyFromContext(ctx) {", "defer connection.Close()\n\n\tif session.TimeoutOnlyFromContext(ctx) {"},
		{"proxy/shadowsocks_2022/outbound.go", "serverConn := o.method.DialPacketConn(connection)", "if wrapper, ok := packetConn.(*singbridge.PacketConnWrapper); ok {\n\t\t\tdefer wrapper.T.SetTimeout(0)\n\t\t}\n\n\t\tserverConn := o.method.DialPacketConn(connection)"},
	}
	patchedModule := filepath.Join(dir, "xray")
	err = filepath.WalkDir(module.Dir, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(module.Dir, path)
		if err != nil {
			return err
		}
		target := filepath.Join(patchedModule, relative)
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
	for _, change := range changes {
		input := filepath.Join(patchedModule, change.file)
		content, err := os.ReadFile(input)
		if err != nil {
			return err
		}
		if strings.Count(string(content), change.old) != 1 {
			return fmt.Errorf("patch anchor mismatch: %s", change.file)
		}
		if err := os.WriteFile(input, []byte(strings.Replace(string(content), change.old, change.replacement, 1)), 0600); err != nil {
			return err
		}
	}
	regression, err := os.ReadFile("internal/regression/udp_test.go")
	if err != nil {
		return err
	}
	testDir := filepath.Join(patchedModule, "internal", "nahanregression")
	if err := os.MkdirAll(testDir, 0700); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(testDir, "udp_test.go"), regression, 0600); err != nil {
		return err
	}
	modfile := filepath.Join(dir, "build.mod")
	for source, target := range map[string]string{"go.mod": modfile, "go.sum": filepath.Join(dir, "build.sum")} {
		content, err := os.ReadFile(source)
		if err != nil {
			return err
		}
		if err := os.WriteFile(target, content, 0600); err != nil {
			return err
		}
	}
	command := exec.Command("go", "mod", "edit", "-modfile="+modfile, "-replace=github.com/xtls/xray-core="+patchedModule)
	if output, err := command.CombinedOutput(); err != nil {
		return fmt.Errorf("prepare patched module: %w: %s", err, output)
	}
	fmt.Println(modfile)
	return nil
}
