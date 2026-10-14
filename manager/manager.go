package manager

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sync"

	"dario.cat/mergo"
	"github.com/r3labs/diff/v2"
	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/app/stats"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/infra/conf"

	"github.com/NahaNCode/nahan-core/api"
	"github.com/NahaNCode/nahan-core/api/nahan"
	"github.com/NahaNCode/nahan-core/app/xdispatcher"
	_ "github.com/NahaNCode/nahan-core/cmd/distro/all"
	"github.com/NahaNCode/nahan-core/service"
	"github.com/NahaNCode/nahan-core/service/controller"
)

// Manager Structure
type Manager struct {
	egress            egressRuntime
	principals        map[string]*principalLease
	principalInstalls int
	retiredPrincipals map[string]int64
	statusLock        sync.Mutex
	managerConfig     *Config
	Server            *core.Instance
	Service           []service.Service
	Running           bool
}

func New(managerConfig *Config) *Manager {
	m := &Manager{managerConfig: managerConfig}
	return m
}

func (m *Manager) loadCore(managerConfig *Config) *core.Instance {
	// Log Config
	coreLogConfig := &conf.LogConfig{}
	logConfig := getDefaultLogConfig()
	if managerConfig.LogConfig != nil {
		if _, err := diff.Merge(logConfig, managerConfig.LogConfig, logConfig); err != nil {
			log.Panicf("Read Log config failed: %s", err)
		}
	}
	coreLogConfig.LogLevel = logConfig.Level
	coreLogConfig.AccessLog = logConfig.AccessPath
	coreLogConfig.ErrorLog = logConfig.ErrorPath
	coreLogConfig.DNSLog = logConfig.DNSLog
	coreLogConfig.MaskAddress = logConfig.MaskAddress

	// DNS config
	coreDnsConfig := &conf.DNSConfig{}
	if managerConfig.DnsConfigPath != "" {
		if data, err := os.ReadFile(managerConfig.DnsConfigPath); err != nil {
			log.Panicf("Failed to read DNS config file at: %s", managerConfig.DnsConfigPath)
		} else {
			if err = json.Unmarshal(data, coreDnsConfig); err != nil {
				log.Panicf("Failed to unmarshal DNS config: %s", managerConfig.DnsConfigPath)
			}
		}
	}

	dnsConfig, err := coreDnsConfig.Build()
	if err != nil {
		log.Panicf("Failed to understand DNS config, Please check: https://xtls.github.io/config/dns.html for help: %s", err)
	}

	// Routing config
	coreRouterConfig := &conf.RouterConfig{}
	if managerConfig.RouteConfigPath != "" {
		if data, err := os.ReadFile(managerConfig.RouteConfigPath); err != nil {
			log.Panicf("Failed to read Routing config file at: %s", managerConfig.RouteConfigPath)
		} else {
			if err = json.Unmarshal(data, coreRouterConfig); err != nil {
				log.Panicf("Failed to unmarshal Routing config: %s", managerConfig.RouteConfigPath)
			}
		}
	}
	routeConfig, err := coreRouterConfig.Build()
	if err != nil {
		log.Panicf("Failed to understand Routing config  Please check: https://xtls.github.io/config/routing.html for help: %s", err)
	}

	// Custom Inbound config
	var coreCustomInboundConfig []conf.InboundDetourConfig
	if managerConfig.InboundConfigPath != "" {
		if data, err := os.ReadFile(managerConfig.InboundConfigPath); err != nil {
			log.Panicf("Failed to read Custom Inbound config file at: %s", managerConfig.OutboundConfigPath)
		} else {
			if err = json.Unmarshal(data, &coreCustomInboundConfig); err != nil {
				log.Panicf("Failed to unmarshal Custom Inbound config: %s", managerConfig.OutboundConfigPath)
			}
		}
	}
	var inBoundConfig []*core.InboundHandlerConfig
	for _, config := range coreCustomInboundConfig {
		oc, err := config.Build()
		if err != nil {
			log.Panicf("Failed to understand Inbound config, Please check: https://xtls.github.io/config/inbound.html for help: %s", err)
		}
		inBoundConfig = append(inBoundConfig, oc)
	}

	// Custom Outbound config
	var coreCustomOutboundConfig []conf.OutboundDetourConfig
	if managerConfig.OutboundConfigPath != "" {
		if data, err := os.ReadFile(managerConfig.OutboundConfigPath); err != nil {
			log.Panicf("Failed to read Custom Outbound config file at: %s", managerConfig.OutboundConfigPath)
		} else {
			if err = json.Unmarshal(data, &coreCustomOutboundConfig); err != nil {
				log.Panicf("Failed to unmarshal Custom Outbound config: %s", managerConfig.OutboundConfigPath)
			}
		}
	}
	var outBoundConfig []*core.OutboundHandlerConfig
	for _, config := range coreCustomOutboundConfig {
		oc, err := config.Build()
		if err != nil {
			log.Panicf("Failed to understand Outbound config, Please check: https://xtls.github.io/config/outbound.html for help: %s", err)
		}
		outBoundConfig = append(outBoundConfig, oc)
	}

	// Policy config
	levelPolicyConfig := parseConnectionConfig(managerConfig.ConnectionConfig)
	corePolicyConfig := &conf.PolicyConfig{}
	corePolicyConfig.Levels = map[uint32]*conf.Policy{0: levelPolicyConfig}
	policyConfig, _ := corePolicyConfig.Build()

	// Build Core Config
	config := &core.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(coreLogConfig.Build()),
			serial.ToTypedMessage(&xdispatcher.Config{}),
			serial.ToTypedMessage(&stats.Config{}),
			serial.ToTypedMessage(&proxyman.InboundConfig{}),
			serial.ToTypedMessage(&proxyman.OutboundConfig{}),
			serial.ToTypedMessage(policyConfig),
			serial.ToTypedMessage(dnsConfig),
			serial.ToTypedMessage(routeConfig),
		},
		Inbound:  inBoundConfig,
		Outbound: outBoundConfig,
	}

	server, err := core.New(config)
	if err != nil {
		log.Panicf("failed to create instance: %s", err)
	}

	//log.Printf("Core Version: %s", core.Version())
	if err := server.GetFeature(routing.DispatcherType()).(*xdispatcher.DefaultDispatcher).ConnectionPolicy.Replace(managerConfig.ConnectionPolicy); err != nil {
		server.Close()
		log.Panic("invalid connection policy")
	}

	return server
}

// Start the manager
func (m *Manager) Start() {
	m.statusLock.Lock()
	defer m.statusLock.Unlock()
	// Load Core
	server := m.loadCore(m.managerConfig)
	m.Server = server
	if err := server.Start(); err != nil {
		log.Panicf("Failed to start instance: %s", err)
	}
	m.Server = server

	// Restore managed routes before any customer inbound is started.
	if m.managerConfig.RestoredEgress != nil {
		if err := m.ApplyEgress(*m.managerConfig.RestoredEgress); err != nil {
			log.Panic("egress restore failed")
		}
		server.GetFeature(routing.DispatcherType()).(*xdispatcher.DefaultDispatcher).Egress.RestrictLease(m.managerConfig.EgressExpiresAt)
	}
	// Load Nodes config
	for _, nodeConfig := range m.managerConfig.NodesConfig {
		var apiClient api.API
		apiClient = nodeConfig.PreparedAPI
		if apiClient == nil {
			apiClient = nahan.New(nodeConfig.ApiConfig)
		}

		var controllerService service.Service
		// Register controller service
		controllerConfig := getDefaultControllerConfig()
		if nodeConfig.ControllerConfig != nil {
			if err := mergo.Merge(controllerConfig, nodeConfig.ControllerConfig, mergo.WithOverride); err != nil {
				log.Panicf("Read Controller Config Failed")
			}
		}
		controllerService = controller.New(server, apiClient, controllerConfig)
		m.Service = append(m.Service, controllerService)

	}

	// Start all the service
	for _, s := range m.Service {
		err := s.Start()
		if err != nil {
			log.Panicf("NahaN fialed to start: %s", err)
		}
	}
	m.Running = true
	return
}

// Close the manager
func (m *Manager) Close() {
	m.statusLock.Lock()
	defer m.statusLock.Unlock()
	for _, lease := range m.principals {
		m.removePrincipal(lease)
	}
	m.principals = nil
	m.principalInstalls = 0
	for _, s := range m.Service {
		err := s.Close()
		if err != nil {
			log.Panicf("NahaN fialed to close: %s", err)
		}
	}
	m.Service = nil
	if m.Server != nil {
		m.Server.Close()
	}
	m.Running = false
	return
}

// Managed mode must return a failure to its rollback controller instead of
// terminating the process on a failed bind or handler creation.
func (m *Manager) StartChecked() (err error) {
	defer func() {
		if recover() != nil {
			err = fmt.Errorf("managed engine start failed")
		}
		if err != nil {
			m.Close()
		}
	}()
	m.Start()
	return m.RestoreEgressPrincipals()
}

func parseConnectionConfig(c *ConnectionConfig) (policy *conf.Policy) {
	connectionConfig := getDefaultConnectionConfig()
	if c != nil {
		if _, err := diff.Merge(connectionConfig, c, connectionConfig); err != nil {
			log.Panicf("Read ConnectionConfig failed: %s", err)
		}
	}
	policy = &conf.Policy{
		StatsUserUplink:   true,
		StatsUserDownlink: true,
		Handshake:         &connectionConfig.Handshake,
		ConnectionIdle:    &connectionConfig.ConnIdle,
		UplinkOnly:        &connectionConfig.UplinkOnly,
		DownlinkOnly:      &connectionConfig.DownlinkOnly,
		BufferSize:        &connectionConfig.BufferSize,
	}

	return
}
