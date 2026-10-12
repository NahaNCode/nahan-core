package cmd

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestEntryPreflightCLIReadsStdinAndRejectsWithoutSecrets(t *testing.T) {
	command, _, err := rootCmd.Find([]string{"entry-preflight"})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { command.SetIn(nil); command.SetOut(nil) }()
	for _, test := range []struct {
		input string
		valid bool
	}{
		{`{"protocol":"vless","listen":"127.0.0.1","port":11245,"settings":{"decryption":"none"}}`, true},
		{`{"protocol":"vless","listen":"127.0.0.1","port":11245,"settings":{"decryption":"secret://sensitive/reference"}}`, false},
	} {
		var output bytes.Buffer
		command.SetIn(strings.NewReader(test.input))
		command.SetOut(&output)
		err := command.RunE(command, nil)
		if (err == nil) != test.valid {
			t.Fatalf("unexpected command result: %v", err)
		}
		var result struct {
			Valid bool   `json:"valid"`
			Code  string `json:"code"`
		}
		if err := json.Unmarshal(output.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		if result.Valid != test.valid || strings.Contains(output.String(), "sensitive/reference") {
			t.Fatal("unsafe command output")
		}
	}
}
