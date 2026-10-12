package controller

import (
	"github.com/NahaNCode/nahan-core/utility/limiter"
	"github.com/NahaNCode/nahan-core/utility/mylego"
)

type Config struct {
	CertConfig      *mylego.CertConfig `mapstructure:"CertConfig"`
	EnableFallback  bool               `mapstructure:"EnableFallback"`
	FallBackConfigs []*FallBackConfig  `mapstructure:"FallBackConfigs"`
	EnableDNS       bool               `mapstructure:"EnableDNS"`
	DNSStrategy     string             `mapstructure:"DNSStrategy"`
	IPLimit         *limiter.IPLimit   `mapstructure:"IPLimit"`
}

type FallBackConfig struct {
	SNI              string `mapstructure:"SNI"`
	Alpn             string `mapstructure:"Alpn"`
	Path             string `mapstructure:"Path"`
	Dest             string `mapstructure:"Dest"`
	ProxyProtocolVer uint64 `mapstructure:"ProxyProtocolVer"`
}
