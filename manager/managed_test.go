package manager

import (
	"github.com/NahaNCode/nahan-core/api"
	"net"
	"strconv"
	"testing"
)

type stubAPI struct{ node *api.NodeInfo }

func (s *stubAPI) GetNodeInfo() (*api.NodeInfo, error)           { return s.node, nil }
func (s *stubAPI) GetRelayNodeInfo() (*api.RelayNodeInfo, error) { return nil, nil }
func (s *stubAPI) GetSubscriptionList() (*[]api.SubscriptionInfo, error) {
	empty := []api.SubscriptionInfo{}
	return &empty, nil
}
func (s *stubAPI) ReportNodeOnlineIPs(*[]api.OnlineIP) error                  { return nil }
func (s *stubAPI) ReportSubscriptionTraffic(*[]api.SubscriptionTraffic) error { return nil }
func (s *stubAPI) Describe() api.ClientInfo                                   { return api.ClientInfo{NodeID: 1} }
func (s *stubAPI) GetNodeRule() (*[]api.DetectRule, error) {
	empty := []api.DetectRule{}
	return &empty, nil
}
func (s *stubAPI) Debug() {}
func TestCheckedStartupReturnsBindFailureAndAllowsRestore(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	cfg := &Config{LogConfig: &LogConfig{Level: "none"}, NodesConfig: []*NodesConfig{{PreparedAPI: &stubAPI{node: &api.NodeInfo{NodeType: "Vless", NodeID: 1, ListenIP: "127.0.0.1", Port: strconv.Itoa(port), Transport: "raw"}}}}}
	candidate := New(cfg)
	if candidate.StartChecked() == nil {
		candidate.Close()
		t.Fatal("occupied port accepted")
	}
	listener.Close()
	restored := New(cfg)
	if err := restored.StartChecked(); err != nil {
		t.Fatalf("restore failed: %v", err)
	}
	restored.Close()
}
