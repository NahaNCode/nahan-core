package cmd

import (
	"github.com/NahaNCode/nahan-core/utility/connectionpolicy"
	"github.com/NahaNCode/nahan-core/utility/controlplane"
	"os"
	"path/filepath"
	"testing"
)

func TestPolicyPersistsAndRestores(t *testing.T) {
	c := &controlplane.Client{Config: &controlplane.Config{CoreID: "qa", KeyFile: filepath.Join(t.TempDir(), "key")}}
	p := connectionpolicy.Snapshot{Revision: 3, Rules: []connectionpolicy.Rule{{ID: "deny", Action: "block", Domains: []string{"example.com"}}}}
	if err := persistPolicy(c, p); err != nil {
		t.Fatal(err)
	}
	restored, err := restorePolicy(c)
	if err != nil || restored.Revision != 3 || len(restored.Rules) != 1 {
		t.Fatal("restore failed", err)
	}
	info, _ := os.Stat(policyPath(c))
	if info.Mode().Perm() != 0600 {
		t.Fatal("unsafe permissions")
	}
	os.WriteFile(policyPath(c), []byte(`{"revision":3,"rules":[{"id":"a","action":"shell"}]}`), 0600)
	if _, err := restorePolicy(c); err == nil {
		t.Fatal("invalid durable policy accepted")
	}
}
