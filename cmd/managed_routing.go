package cmd

import "github.com/NahaNCode/nahan-core/manager"

// Custom outbounds remain fallback handlers; they do not override scoped managed bindings.
func incompatibleManagedRouting(config *manager.Config) bool {
	acknowledged := config.ControlPlane != nil && config.ControlPlane.AllowManagedEgress
	return (config.RouteConfigPath != "" && !acknowledged) || config.DnsConfigPath != "" || config.InboundConfigPath != ""
}
