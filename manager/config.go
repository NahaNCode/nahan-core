package manager

import (
	"encoding/json"
	"github.com/NahaNCode/nahan-core/api"
	"github.com/NahaNCode/nahan-core/service/controller"
	"github.com/NahaNCode/nahan-core/utility/connectionpolicy"
	"github.com/NahaNCode/nahan-core/utility/controlplane"
	"github.com/NahaNCode/nahan-core/utility/egress"
	"github.com/NahaNCode/nahan-core/utility/exitroute"
	"time"
)

type Config struct {
	PersistentEgress        bool                                                              `mapstructure:"-"`
	PersistentExitRoutes    bool                                                              `mapstructure:"-"`
	ResolveExternalOutbound func(egress.ExternalBinding) (json.RawMessage, error)             `mapstructure:"-"`
	PrincipalStore          *PrincipalStore                                                   `mapstructure:"-"`
	ResolveEgressPrincipal  func(egress.PrincipalBinding) (egress.PrincipalCredential, error) `mapstructure:"-"`
	ResolveEgressCredential func(egress.CredentialBinding) (egress.SSCredential, error)       `mapstructure:"-"`
	RestoredEgress          *EgressPlan                                                       `mapstructure:"-"`
	RestoredExitRoutes      *exitroute.Snapshot                                               `mapstructure:"-"`
	ExitRoutesExpiresAt     time.Time                                                         `mapstructure:"-"`
	EgressExpiresAt         time.Time                                                         `mapstructure:"-"`
	ConnectionPolicy        connectionpolicy.Snapshot                                         `mapstructure:"-"`
	ControlPlane            *controlplane.Config                                              `mapstructure:"ControlPlane"`
	LogConfig               *LogConfig                                                        `mapstructure:"Log"`
	DnsConfigPath           string                                                            `mapstructure:"DnsConfigPath"`
	InboundConfigPath       string                                                            `mapstructure:"InboundConfigPath"`
	OutboundConfigPath      string                                                            `mapstructure:"OutboundConfigPath"`
	RouteConfigPath         string                                                            `mapstructure:"RouteConfigPath"`
	ConnectionConfig        *ConnectionConfig                                                 `mapstructure:"ConnectionConfig"`
	NodesConfig             []*NodesConfig                                                    `mapstructure:"Nodes"`
}

type NodesConfig struct {
	PreparedAPI      api.API            `mapstructure:"-"`
	ApiConfig        *api.Config        `mapstructure:"ApiConfig"`
	ControllerConfig *controller.Config `mapstructure:"ControllerConfig"`
}

type LogConfig struct {
	Level       string `mapstructure:"Level"`
	AccessPath  string `mapstructure:"AccessPath"`
	ErrorPath   string `mapstructure:"ErrorPath"`
	DNSLog      bool   `mapstructure:"DNSLog"`
	MaskAddress string `mapstructure:"MaskAddress"`
}

type ConnectionConfig struct {
	Handshake    uint32 `mapstructure:"handshake"`
	ConnIdle     uint32 `mapstructure:"connIdle"`
	UplinkOnly   uint32 `mapstructure:"uplinkOnly"`
	DownlinkOnly uint32 `mapstructure:"downlinkOnly"`
	BufferSize   int32  `mapstructure:"bufferSize"`
}
