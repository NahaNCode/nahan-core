package cmd

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/NahaNCode/nahan-core/manager"
	updater "github.com/NahaNCode/nahan-core/utility/update"
	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	var profilePath, unit, binary, mode, compose, composeService, imageFile, selected string
	var yes bool
	command := &cobra.Command{Use: "update", Short: "Verified core upgrades with local recovery", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, args []string) error {
		return cliUpdate(cmd, profilePath, selected, "apply", yes)
	}}
	command.PersistentFlags().StringVar(&profilePath, "profile", "", "Root-owned updater profile")
	command.PersistentFlags().StringVar(&selected, "core", "", "Registered core UUID")
	command.PersistentFlags().BoolVarP(&yes, "yes", "y", false, "Acknowledge that restart interrupts connections")
	command.AddCommand(&cobra.Command{Use: "check", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, args []string) error {
		return cliUpdate(cmd, profilePath, selected, "check", false)
	}})
	command.AddCommand(&cobra.Command{Use: "status", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, args []string) error {
		return cliUpdate(cmd, profilePath, selected, "status", false)
	}})
	command.AddCommand(&cobra.Command{Use: "rollback", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, args []string) error {
		return cliUpdate(cmd, profilePath, selected, "rollback", yes)
	}})
	command.AddCommand(&cobra.Command{Use: "serve", Hidden: true, Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, args []string) error {
		p, err := updater.LoadProfile(profilePath)
		if err != nil {
			return err
		}
		ctx, cancel := signal.NotifyContext(cmd.Context(), syscall.SIGTERM, syscall.SIGINT)
		defer cancel()
		return updater.Serve(ctx, &updater.Engine{Profile: p})
	}})
	register := &cobra.Command{Use: "register", Short: "Register an existing local installation; does not restart the core", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, args []string) error {
		if os.Geteuid() != 0 {
			return errors.New("registration requires root")
		}
		if mode != "native" {
			return errors.New("container registration requires a verified deployment adapter")
		}
		if mode == "native" {
			discoveredBinary, discoveredConfig, err := discoverCore(cmd.Context(), unit)
			if err != nil {
				return err
			}
			if binary != "" && binary != discoveredBinary {
				return errors.New("registered binary differs from the running unit")
			}
			if cfgFile != "" && cfgFile != discoveredConfig {
				return errors.New("registered configuration differs from the running unit")
			}
			binary, cfgFile = discoveredBinary, discoveredConfig
		}
		config := viper.New()
		config.SetConfigFile(cfgFile)
		if err := config.ReadInConfig(); err != nil {
			return errors.New("core configuration unavailable")
		}
		id := config.GetString("ControlPlane.CoreID")
		keyFile := config.GetString("ControlPlane.KeyFile")
		if err := updater.ProtectedPath(binary); err != nil {
			return err
		}
		if err := exclusiveBinary(binary); err != nil {
			return err
		}
		p := updater.Profile{PanelURL: config.GetString("ControlPlane.ApiHost"), KeyFile: keyFile, CAFile: config.GetString("ControlPlane.CAFile"), ServerName: config.GetString("ControlPlane.ServerName"), CoreID: id, Unit: unit, Binary: binary, Config: cfgFile, HeartbeatFile: filepath.Join(filepath.Dir(keyFile), "update-heartbeat-"+id+".json"), StateDir: filepath.Join("/var/lib/nahan-core-updater", id), Mode: mode, ComposeFile: compose, ComposeService: composeService, ImageFile: imageFile, ImageRepository: "ghcr.io/nahancode/nahan-core"}
		proxy, err := discoverPanelProxy(cmd.Context(), unit)
		if err != nil {
			return err
		}
		p.PanelProxy = proxy
		if mode == "docker" {
			p.CoreUID = 10001
		} else {
			data, err := exec.CommandContext(cmd.Context(), "systemctl", "show", unit, "--property=User", "--value").Output()
			if err != nil {
				return errors.New("registered unit unavailable")
			}
			name := strings.TrimSpace(string(data))
			if name != "" && name != "root" {
				account, err := user.Lookup(name)
				if err != nil {
					return errors.New("registered service user unavailable")
				}
				p.CoreUID, err = strconv.Atoi(account.Uid)
				if err != nil {
					return err
				}
			}
		}
		if err := p.Validate(); err != nil {
			return err
		}
		for _, path := range []string{cfgFile, keyFile} {
			if err := updater.ProtectedDataPath(path, p.CoreUID); err != nil {
				return err
			}
		}
		if !filepath.IsAbs(keyFile) {
			return errors.New("registered credential path must be absolute")
		}
		if p.PanelURL == "" {
			return errors.New("registered core must use a panel control endpoint")
		}
		if mode == "native" {
			info, err := os.Lstat(binary)
			if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 {
				return errors.New("registered binary must be a protected regular file")
			}
		}
		if err := os.MkdirAll("/etc/nahan-core/updater", 0700); err != nil {
			return err
		}
		profile := filepath.Join("/etc/nahan-core/updater", id+".json")
		if _, err := os.Stat(profile); err == nil {
			previous, err := updater.LoadProfile(profile)
			if err != nil || previous.Unit != p.Unit || previous.Binary != p.Binary || previous.Config != p.Config || previous.CoreUID != p.CoreUID {
				return errors.New("existing updater registration differs")
			}
			state, err := (&updater.Engine{Profile: previous}).State()
			if err != nil || state.Stage == "downloading" || state.Stage == "applying" || state.Stage == "verifying" || state.Stage == "rolling_back" {
				return errors.New("updater must be idle before registration refresh")
			}
		}
		profiles, _ := filepath.Glob("/etc/nahan-core/updater/*.json")
		for _, other := range profiles {
			if other == profile {
				continue
			}
			registered, err := updater.LoadProfile(other)
			if err != nil {
				return err
			}
			if registered.Unit == p.Unit || registered.Binary == p.Binary {
				return errors.New("service or binary already belongs to another updater")
			}
		}
		if err := updater.Atomic(profile, p); err != nil {
			return err
		}
		exe, err := os.Executable()
		if err != nil {
			return err
		}
		data, err := os.ReadFile(exe)
		if err != nil {
			return err
		}
		if err = os.MkdirAll("/usr/local/libexec", 0755); err != nil {
			return err
		}
		helper := "/usr/local/libexec/nahan-core-updater"
		if err = updater.AtomicBytes(helper, data, 0755); err != nil {
			return err
		}
		service := "nahan-core-updater-" + id + ".service"
		definition := "[Unit]\nDescription=NahaN restricted core updater\nAfter=network-online.target\n[Service]\nExecStart=" + strconv.Quote(helper) + " update serve --profile " + strconv.Quote(profile) + "\nUser=root\nUMask=0077\nRuntimeDirectory=nahan-core-updater\nRuntimeDirectoryMode=0711\nRuntimeDirectoryPreserve=yes\nRestart=on-failure\nRestartSec=5\nNoNewPrivileges=yes\nProtectSystem=strict\nProtectHome=yes\nPrivateTmp=yes\nRestrictAddressFamilies=AF_UNIX AF_INET AF_INET6\nReadWritePaths=" + strconv.Quote(filepath.Dir(p.Binary)) + " /var/lib/nahan-core-updater /run/nahan-core-updater\n[Install]\nWantedBy=multi-user.target\n"
		for _, directory := range []string{p.StateDir, "/run/nahan-core-updater"} {
			if err = os.MkdirAll(directory, 0700); err != nil {
				return err
			}
		}
		if err = os.Chmod("/run/nahan-core-updater", 0711); err != nil {
			return err
		}
		if err = updater.AtomicBytes(filepath.Join("/etc/systemd/system", service), []byte(definition), 0644); err != nil {
			return err
		}
		if err = engineCommand(cmd.Context(), "systemctl", "daemon-reload"); err != nil {
			return err
		}
		if err = engineCommand(cmd.Context(), "systemctl", "enable", "--now", service); err != nil {
			return err
		}
		if err = engineCommand(cmd.Context(), "systemctl", "restart", service); err != nil {
			return err
		}
		alias := "/usr/local/bin/nahan-core"
		if _, err := os.Lstat(alias); os.IsNotExist(err) {
			if err := os.Symlink(helper, alias); err != nil {
				return err
			}
		}
		fmt.Fprintln(cmd.OutOrStdout(), "Registered "+id+"; existing core was not restarted.")
		return nil
	}}
	register.Flags().StringVar(&unit, "service", "", "Existing core systemd unit")
	register.Flags().StringVar(&binary, "binary", "", "Existing native binary path")
	register.Flags().StringVar(&mode, "mode", "native", "native or docker")
	register.Flags().StringVar(&compose, "compose-file", "", "Root-owned compose file")
	register.Flags().StringVar(&composeService, "compose-service", "core", "Whitelisted compose service")
	register.Flags().StringVar(&imageFile, "image-file", "", "Root-owned image environment file")
	command.AddCommand(register)
	rootCmd.AddCommand(command)
	validate := &cobra.Command{Use: "update-validate", Hidden: true, Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, args []string) error {
		releaseVersion, _ := cmd.Flags().GetString("release-version")
		releaseCommit, _ := cmd.Flags().GetString("release-commit")
		if releaseVersion != "" && releaseVersion != version {
			return errors.New("candidate version differs from signed release")
		}
		if releaseCommit != "" && releaseCommit != buildCommit {
			return errors.New("candidate commit differs from signed release")
		}
		expected, _ := cmd.Flags().GetString("core-id")
		configuration := viper.New()
		configuration.SetConfigFile(cfgFile)
		if err := configuration.ReadInConfig(); err != nil {
			return errors.New("invalid candidate configuration")
		}
		var parsed manager.Config
		if err := configuration.Unmarshal(&parsed); err != nil || configuration.GetString("ControlPlane.CoreID") != expected {
			return errors.New("candidate core identity changed")
		}
		return nil
	}}
	validate.Flags().String("core-id", "", "Expected registered core UUID")
	validate.Flags().String("release-version", "", "Expected signed release version")
	validate.Flags().String("release-commit", "", "Expected signed source commit")
	rootCmd.AddCommand(validate)
}
func exclusiveBinary(binary string) error {
	entries, err := filepath.Glob("/proc/[0-9]*/exe")
	if err != nil {
		return err
	}
	count := 0
	self := filepath.Join("/proc", strconv.Itoa(os.Getpid()), "exe")
	for _, entry := range entries {
		// Registration may be invoked through the core binary itself, not just the helper.
		if entry == self {
			continue
		}
		path, err := os.Readlink(entry)
		if err == nil && path == binary {
			count++
		}
	}
	if count != 1 {
		return errors.New("registered binary must belong to exactly one running service")
	}
	return nil
}

func discoverPanelProxy(ctx context.Context, unit string) (string, error) {
	data, err := exec.CommandContext(ctx, "systemctl", "show", unit, "--property=MainPID", "--value").Output()
	pid := strings.TrimSpace(string(data))
	if err != nil || !regexp.MustCompile(`^[1-9][0-9]{0,9}$`).MatchString(pid) {
		return "", errors.New("core process unavailable")
	}
	environment, err := os.ReadFile(filepath.Join("/proc", pid, "environ"))
	if err != nil {
		return "", errors.New("core environment unavailable")
	}
	for _, variable := range strings.Split(string(environment), "\x00") {
		key, value, ok := strings.Cut(variable, "=")
		if ok && (key == "HTTPS_PROXY" || key == "https_proxy") && value != "" {
			if _, err := updater.LocalPanelProxy(value); err != nil {
				return "", err
			}
			return value, nil
		}
	}
	return "", nil
}
func discoverCore(ctx context.Context, unit string) (string, string, error) {
	if !regexp.MustCompile(`^[a-zA-Z0-9@_.-]+\.service$`).MatchString(unit) {
		return "", "", errors.New("select a single core service with --service")
	}
	data, err := exec.CommandContext(ctx, "systemctl", "show", unit, "--property=MainPID", "--value").Output()
	pid := strings.TrimSpace(string(data))
	if err != nil || !regexp.MustCompile(`^[1-9][0-9]{0,9}$`).MatchString(pid) {
		return "", "", errors.New("registered core unit must be running")
	}
	binary, err := os.Readlink(filepath.Join("/proc", pid, "exe"))
	if err != nil || strings.HasSuffix(binary, " (deleted)") {
		return "", "", errors.New("running core binary unavailable")
	}
	args, err := os.ReadFile(filepath.Join("/proc", pid, "cmdline"))
	if err != nil {
		return "", "", err
	}
	parts := strings.Split(string(args), "\x00")
	config := ""
	for i, arg := range parts {
		if (arg == "--config" || arg == "-c") && i+1 < len(parts) {
			config = parts[i+1]
			break
		}
		if strings.HasPrefix(arg, "--config=") {
			config = strings.TrimPrefix(arg, "--config=")
			break
		}
	}
	cwd, err := os.Readlink(filepath.Join("/proc", pid, "cwd"))
	if err != nil {
		return "", "", err
	}
	if config == "" {
		config = filepath.Join(cwd, "config.yml")
	}
	if !filepath.IsAbs(config) {
		config = filepath.Join(cwd, config)
	}
	return binary, filepath.Clean(config), nil
}
func engineCommand(ctx context.Context, name string, args ...string) error {
	return exec.CommandContext(ctx, name, args...).Run()
}
func chooseProfile(cmd *cobra.Command, path, core string) (updater.Profile, error) {
	if path != "" {
		return updater.LoadProfile(path)
	}
	files, err := filepath.Glob("/etc/nahan-core/updater/*.json")
	if err != nil {
		return updater.Profile{}, err
	}
	var profiles []updater.Profile
	for _, file := range files {
		p, err := updater.LoadProfile(file)
		if err != nil {
			return p, err
		}
		if core != "" && p.CoreID != core {
			continue
		}
		profiles = append(profiles, p)
	}
	if len(profiles) == 0 {
		return updater.Profile{}, errors.New("no registered updater; run update register once")
	}
	if len(profiles) == 1 {
		return profiles[0], nil
	}
	for i, p := range profiles {
		fmt.Fprintf(cmd.OutOrStdout(), "%d. %s (%s)\n", i+1, p.Unit, p.CoreID)
	}
	fmt.Fprint(cmd.OutOrStdout(), "Select core: ")
	var number int
	if _, err = fmt.Fscan(cmd.InOrStdin(), &number); err != nil || number < 1 || number > len(profiles) {
		return updater.Profile{}, errors.New("a single registered core must be selected")
	}
	return profiles[number-1], nil
}
func cliUpdate(cmd *cobra.Command, path, core, action string, yes bool) error {
	p, err := chooseProfile(cmd, path, core)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(cmd.Context(), 5*time.Minute)
	defer cancel()
	if action == "status" {
		var s updater.Status
		if err = updater.Call(ctx, p.CoreID, "GET", "status", nil, &s); err != nil {
			return err
		}
		return json.NewEncoder(cmd.OutOrStdout()).Encode(s)
	}
	var release updater.Release
	if action != "rollback" {
		release, err = updater.Catalog(ctx)
		if err != nil {
			return err
		}
	}
	receipt, err := (&updater.Engine{Profile: p}).Current()
	if err != nil {
		return err
	}
	if action == "check" {
		return json.NewEncoder(cmd.OutOrStdout()).Encode(map[string]any{"coreId": p.CoreID, "currentVersion": receipt.Version, "currentDigest": receipt.Digest, "release": release})
	}
	if action != "rollback" {
		if asset, ok := release.Assets["linux-"+runtime.GOARCH]; ok && asset.SHA256 == receipt.Digest {
			fmt.Fprintln(cmd.OutOrStdout(), "Already at "+release.Version+"; no restart required.")
			return nil
		}
	}
	if os.Geteuid() != 0 {
		return errors.New("upgrade requires root")
	}
	if !yes {
		fmt.Fprintf(cmd.OutOrStdout(), "%s: %s. Restart interrupts active connections. Continue? [y/N] ", p.Unit, release.Version)
		answer, err := bufio.NewReader(cmd.InOrStdin()).ReadString('\n')
		if err != nil || strings.ToLower(strings.TrimSpace(answer)) != "y" {
			return errors.New("upgrade cancelled")
		}
	}
	id, err := uuid.NewRandom()
	if err != nil {
		return err
	}
	request := updater.Request{ID: id.String(), Version: release.Version, ExpectedDigest: receipt.Digest, Acknowledged: true}
	if action == "rollback" {
		var state updater.Status
		if err = updater.Call(ctx, p.CoreID, "GET", "installed", nil, &state); err != nil {
			return err
		}
		request.ID = state.ID
		request.Version = state.Version
		if err = updater.Call(ctx, p.CoreID, "POST", "rollback", request, nil); err != nil {
			return err
		}
		return waitUpdate(cmd, ctx, p.CoreID, request.ID, "rolled_back")
	}
	if err = updater.Call(ctx, p.CoreID, "POST", "prepare", request, nil); err != nil {
		return err
	}
	if err = waitUpdate(cmd, ctx, p.CoreID, request.ID, "prepared"); err != nil {
		return err
	}
	if err = updater.Call(ctx, p.CoreID, "POST", "apply", request, nil); err != nil {
		return err
	}
	return waitUpdate(cmd, ctx, p.CoreID, request.ID, "done")
}
func waitUpdate(cmd *cobra.Command, ctx context.Context, core, id, stage string) error {
	previous := ""
	for ctx.Err() == nil {
		var s updater.Status
		if err := updater.Call(ctx, core, "GET", "status", nil, &s); err != nil {
			return err
		}
		if s.ID == id {
			if previous != s.Stage {
				fmt.Fprintln(cmd.OutOrStdout(), s.String())
				previous = s.Stage
			}
			if s.Stage == stage {
				return nil
			}
			if s.Stage == "failed" || s.Stage == "rolled_back" {
				return errors.New("update did not pass verification")
			}
		}
		var failure updater.Status
		updater.Call(ctx, core, "GET", "failure", nil, &failure)
		if failure.ID == id {
			return errors.New("update failed")
		}
		select {
		case <-ctx.Done():
		case <-time.After(time.Second):
		}
	}
	return ctx.Err()
}
