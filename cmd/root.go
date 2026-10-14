package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/fsnotify/fsnotify"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"context"
	"errors"
	"github.com/NahaNCode/nahan-core/api"
	"github.com/NahaNCode/nahan-core/api/nahan"
	"github.com/NahaNCode/nahan-core/manager"
	"github.com/NahaNCode/nahan-core/service/controller"
	"github.com/NahaNCode/nahan-core/utility/controlplane"
	"github.com/NahaNCode/nahan-core/utility/entryprofile"
)

var (
	cfgFile string
	rootCmd = &cobra.Command{
		Use: "nahan-core",
		Run: func(cmd *cobra.Command, args []string) {
			if err := run(); err != nil {
				log.Fatal(err)
			}
		},
	}
)

func init() {
	rootCmd.PersistentFlags().StringVarP(&cfgFile, "config", "c", "", "Config file for NahaN Core.")
}

func getConfig() *viper.Viper {
	config := viper.New()

	// Set custom path and name
	if cfgFile != "" {
		configName := path.Base(cfgFile)
		configFileExt := path.Ext(cfgFile)
		configNameOnly := strings.TrimSuffix(configName, configFileExt)
		configPath := path.Dir(cfgFile)
		config.SetConfigName(configNameOnly)
		config.SetConfigType(strings.TrimPrefix(configFileExt, "."))
		config.AddConfigPath(configPath)
		// Set the engine asset and configuration paths.
		os.Setenv("XRAY_LOCATION_ASSET", configPath)
		os.Setenv("XRAY_LOCATION_CONFIG", configPath)
	} else {
		// Set default config path
		config.SetConfigName("config")
		config.SetConfigType("yml")
		config.AddConfigPath(".")

	}

	if err := config.ReadInConfig(); err != nil {
		log.Panicf("Config file error: %s \n", err)
	}

	config.WatchConfig() // Watch the config

	return config
}

func run() error {
	showVersion()
	stopDiagnostics, err := startDiagnostics(os.Getenv("NAHAN_DIAGNOSTICS_SOCKET"))
	if err != nil {
		return fmt.Errorf("start local diagnostics: %w", err)
	}
	defer stopDiagnostics()

	config := getConfig()
	managerConfig := &manager.Config{}
	if err := config.Unmarshal(managerConfig); err != nil {
		return fmt.Errorf("Parse config file %v failed: %s \n", cfgFile, err)
	}

	if managerConfig.LogConfig == nil {
		managerConfig.LogConfig = &manager.LogConfig{Level: "info"}
	}
	if managerConfig.LogConfig.Level == "debug" {
		log.SetReportCaller(true)
	}

	m := manager.New(managerConfig)
	var panel *controlplane.Client
	var manifest *controlplane.Manifest
	var template *controller.Config
	startupError := ""
	if managerConfig.ControlPlane != nil {
		if len(managerConfig.NodesConfig) > 0 {
			template = managerConfig.NodesConfig[0].ControllerConfig
		}
		managerConfig.ControlPlane.HasCustomRouting = incompatibleManagedRouting(managerConfig)
		panel, err = controlplane.New(managerConfig.ControlPlane)
		if err != nil {
			return err
		}
		panel.SSTrial = m.SSTrial
		managerConfig.PrincipalStore = manager.NewPrincipalStore(filepath.Join(filepath.Dir(panel.Config.KeyFile), "egress-destination-principals"), panel.Config.CoreID, panel.Key)
		panel.PrincipalDurable = true
		panel.PrincipalProvision = func(input json.RawMessage, coreID string) (entryprofile.SealedResult, error) {
			var request manager.PrincipalRequest
			if len(input) > 65536 || json.Unmarshal(input, &request) != nil {
				return entryprofile.SealedResult{}, errors.New("invalid principal request")
			}
			return m.ProvisionEgressPrincipal(coreID, request)
		}
		if err = restoreEgress(panel, managerConfig); err != nil {
			return fmt.Errorf("egress state restore failed")
		}
		managerConfig.ConnectionPolicy, err = restorePolicy(panel)
		if err != nil {
			return fmt.Errorf("connection policy restore failed")
		}
		manifest, err = panel.Manifest(context.Background())
		if err != nil {
			return err
		}
		managerConfig.NodesConfig, err = prepareManagedNodes(panel, manifest, template)
		if err != nil {
			manifest, managerConfig.NodesConfig, err = restoreManagedSnapshot(panel, template)
			if err != nil {
				return err
			}
			startupError = "configuration restored"
		}
	}
	lastTime := time.Now()
	config.OnConfigChange(func(e fsnotify.Event) {
		if panel != nil {
			log.Warn("Managed core configuration changes require a local restart")
			return
		}
		// Discarding event received within a short period of time after receiving an event.
		if time.Now().After(lastTime.Add(3 * time.Second)) {
			// Hot reload function
			fmt.Println("Config file changed:", e.Name)
			m.Close()
			// Delete old instance and trigger GC
			runtime.GC()
			if err := config.Unmarshal(managerConfig); err != nil {
				log.Panicf("Parse config file %v failed: %s \n", cfgFile, err)
			}

			if managerConfig.LogConfig.Level == "debug" {
				log.SetReportCaller(true)
			}

			m.Start()
			lastTime = time.Now()
		}
	})

	if panel != nil {
		if err = m.StartChecked(); err != nil {
			manifest, managerConfig.NodesConfig, err = restoreManagedSnapshot(panel, template)
			if err != nil {
				return err
			}
			m = manager.New(managerConfig)
			if err = m.StartChecked(); err != nil {
				return fmt.Errorf("managed startup restore failed")
			}
			startupError = "configuration restored"
		}
		if err := saveManagedSnapshot(panel, manifest, managerConfig.NodesConfig); err != nil {
			m.Close()
			return fmt.Errorf("persist managed snapshot failed")
		}
	} else {
		m.Start()
	}
	defer func() {
		if panel != nil {
			panel.CloseEgressPreflight()
		}
		m.Close()
	}()
	if panel != nil {
		if err := syncEgress(panel, m, managerConfig); err != nil {
			log.Warn("Egress synchronization unavailable")
		}
		if err := panel.Heartbeat(context.Background(), version, manifest, startupError); err != nil {
			log.Warn(err)
		}
	}

	// Explicitly triggering GC to remove garbage from config loading.
	runtime.GC()
	// Running backend
	osSignals := make(chan os.Signal, 1)
	signal.Notify(osSignals, os.Interrupt, os.Kill, syscall.SIGTERM)
	ticker := time.NewTicker(10 * time.Second)
	var rejectedRevision int64
	lastApplyError := startupError
	defer ticker.Stop()
	for {
		select {
		case <-osSignals:
			return nil
		case <-ticker.C:
			if panel == nil {
				continue
			}
			if err := panel.ProcessJobs(context.Background()); err != nil {
				log.Warn("Core job polling failed")
			}
			next, err := panel.Manifest(context.Background())
			if err != nil {
				if errors.Is(err, controlplane.ErrUnauthorized) {
					return err
				}
				log.Warn(err)
				continue
			}
			if next.Revision != manifest.Revision && next.Revision != rejectedRevision {
				candidate, prepareError := prepareManagedNodes(panel, next, template)
				if prepareError != nil {
					rejectedRevision = next.Revision
					lastApplyError = "configuration preflight failed"
				} else {
					previous := managerConfig.NodesConfig
					panel.CloseEgressPreflight()
					m.Close()
					managerConfig.NodesConfig = candidate
					m = manager.New(managerConfig)
					if err := m.StartChecked(); err != nil {
						rejectedRevision = next.Revision
						lastApplyError = "configuration rolled back"
						for _, node := range previous {
							if prepared, ok := node.PreparedAPI.(*nahan.PreparedClient); ok {
								prepared.Reset()
							}
						}
						managerConfig.NodesConfig = previous
						m = manager.New(managerConfig)
						if err := m.StartChecked(); err != nil {
							return fmt.Errorf("managed rollback failed")
						}
					} else {
						manifest = next
						rejectedRevision = 0
						lastApplyError = ""
						if err := saveManagedSnapshot(panel, manifest, managerConfig.NodesConfig); err != nil {
							lastApplyError = "snapshot persistence failed"
						}
					}
				}
			}
			if err := panel.Heartbeat(context.Background(), version, manifest, lastApplyError); err != nil {
				log.Warn(err)
			}
			if err := syncPolicy(panel, m, managerConfig); err != nil {
				log.Warn("Connection policy synchronization unavailable")
			}
			if err := syncEgress(panel, m, managerConfig); err != nil {
				log.Warn("Egress synchronization unavailable")
			}
		}
	}
}

func managedNodes(panel *controlplane.Client, manifest *controlplane.Manifest, template *controller.Config) []*manager.NodesConfig {
	nodes := make([]*manager.NodesConfig, 0, len(manifest.Nodes))
	for _, node := range manifest.Nodes {
		nodes = append(nodes, &manager.NodesConfig{ApiConfig: &api.Config{Protocol: "nahan-v1", APIHost: panel.Config.APIHost, NodeID: node.ID, Key: panel.Key, CAFile: panel.Config.CAFile, ServerName: panel.Config.ServerName, TrafficOutboxDir: "./traffic-outbox", CoreID: panel.Config.CoreID, SecretsDir: panel.SecretDirectory()}, ControllerConfig: template})
	}
	return nodes
}

func prepareManagedNodes(panel *controlplane.Client, manifest *controlplane.Manifest, template *controller.Config) (nodes []*manager.NodesConfig, err error) {
	defer func() {
		if recover() != nil {
			err = fmt.Errorf("managed preflight failed")
		}
	}()
	nodes = managedNodes(panel, manifest, template)
	for _, node := range nodes {
		client := nahan.New(node.ApiConfig)
		info, err := client.GetNodeInfo()
		if err != nil {
			return nil, fmt.Errorf("managed node fetch failed")
		}
		subscriptions, err := client.GetSubscriptionList()
		if err != nil {
			return nil, fmt.Errorf("managed subscriptions fetch failed")
		}
		config := template
		if config == nil {
			config = &controller.Config{}
		}
		if _, err := controller.InboundBuilder(config, info, "preflight"); err != nil {
			return nil, fmt.Errorf("managed inbound build failed")
		}
		if _, err := controller.OutboundBuilder(config, info, "preflight"); err != nil {
			return nil, fmt.Errorf("managed outbound build failed")
		}
		node.PreparedAPI = &nahan.PreparedClient{APIClient: client, Node: info, Subscriptions: subscriptions}
	}
	return nodes, nil
}

func Execute() error {
	return rootCmd.Execute()
}
