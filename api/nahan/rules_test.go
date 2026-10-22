package nahan

import (
	"github.com/NahaNCode/nahan-core/api"
	"regexp"
	"testing"
)

func TestUnavailableNodeRulesReturnErrorWithoutPanic(t *testing.T) {
	c := &APIClient{}
	if _, err := c.GetNodeRule(); err == nil {
		t.Fatal("uninitialized rule cache accepted")
	}
	c.resp.Store(&serverConfig{})
	if rules, err := c.GetNodeRule(); err != nil || len(*rules) != 0 {
		t.Fatal("explicit empty rules rejected", err)
	}
}

func TestPreparedRulesDoNotRequireLiveServerCache(t *testing.T) {
	rules := []api.DetectRule{{ID: 7, Pattern: regexp.MustCompile("blocked[.]example")}}
	c := &PreparedClient{APIClient: &APIClient{}, Rules: &rules}
	got, err := c.GetNodeRule()
	if err != nil || len(*got) != 1 || !(*got)[0].Pattern.MatchString("blocked.example") {
		t.Fatal("prepared rule enforcement lost", err)
	}
}
