package nahan

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestManagedInfrastructureShadowsocksProfile(t *testing.T) {
	coreID := "11111111-1111-4111-8111-111111111111"
	secretID := "22222222-2222-4222-8222-222222222222"
	dir := t.TempDir()
	password := "AAAAAAAAAAAAAAAAAAAAAA=="
	if err := os.WriteFile(filepath.Join(dir, secretID+".json"), []byte(`{"kind":"shadowsocks-password","password":"`+password+`"}`), 0600); err != nil {
		t.Fatal(err)
	}
	c := &APIClient{protocol: "nahan-v1", coreID: coreID, secretsDir: dir, NodeID: 20000015}
	s := &serverConfig{}
	s.Address = "10.0.0.2"
	s.InboundProfile = json.RawMessage(`{"protocol":"shadowsocks","listen":"10.0.0.2","port":31003,"settings":{"method":"2022-blake3-aes-128-gcm","password":"secret://core/` + coreID + `/` + secretID + `","network":"tcp,udp"}}`)
	node, err := c.parseEntryProfile(s)
	if err != nil {
		t.Fatal(err)
	}
	if node.NodeType != "Shadowsocks" || node.ServerKey != password || node.CypherMethod != "2022-blake3-aes-128-gcm" || node.ListenIP != "10.0.0.2" {
		t.Fatal("SS endpoint changed")
	}
	s.EntryRole = "transit"
	if _, err = c.parseEntryProfile(s); err == nil {
		t.Fatal("customer input accepted as transit")
	}
	s.Infrastructure = true
	node, err = c.parseEntryProfile(s)
	if err != nil || !node.Transit {
		t.Fatal("explicit transit role was lost", err)
	}
	s.EntryRole = "exit"
	node, err = c.parseEntryProfile(s)
	if err != nil || node.Transit {
		t.Fatal("exit role became transit", err)
	}
	s.EntryRole = "unknown"
	if _, err = c.parseEntryProfile(s); err == nil {
		t.Fatal("unsupported role accepted")
	}
	s.EntryRole = "customer"
	if _, err = c.parseEntryProfile(s); err == nil {
		t.Fatal("infrastructure input claimed customer role")
	}
	s.EntryRole = "transit"
	s.InboundProfile = nil
	if _, err = c.parseNodeResponse(s); err == nil {
		t.Fatal("legacy adapter bypassed transit role")
	}
}
