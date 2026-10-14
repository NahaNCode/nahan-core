package routingpolicy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

const coreID = "75667842-8144-45a1-b68d-b25d7c617b4a"
const jobID = "7780f5ce-6e8d-44c7-8830-40d7570bc17b"

func fixture(t *testing.T) Config {
	t.Helper()
	dir := t.TempDir()
	dns := filepath.Join(dir, "dns.json")
	if err := os.WriteFile(dns, []byte(`{"servers":[{"address":"1.1.1.1"}],"queryStrategy":"UseIPv4","disableFallback":true}`), 0600); err != nil {
		t.Fatal(err)
	}
	return Config{CoreID: coreID, Key: "0123456789012345678901234567890123456789", Directory: dir, DNSPath: dns}
}
func request(r Report, enabled bool) json.RawMessage {
	b, _ := json.Marshal(Request{CoreID: coreID, ExpectedDigest: r.Digest, ExpectedGeneration: r.Generation, Enabled: enabled, Acknowledged: true})
	return b
}
func TestConsentDurableScopedAndIdempotent(t *testing.T) {
	c := fixture(t)
	p, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	r := p.Inspect()
	if r.Enabled || !r.DNSCompatible || r.Generation != 1 {
		t.Fatalf("unexpected report: %+v", r)
	}
	input := request(r, true)
	active, err := p.Apply(input, jobID)
	if err != nil || !active.Enabled || active.Generation != 2 {
		t.Fatalf("apply: %+v %v", active, err)
	}
	if _, err = p.Apply(input, jobID); err != nil {
		t.Fatal("same-job retry rejected")
	}
	p, err = New(c)
	if err != nil || !p.Inspect().Enabled {
		t.Fatal("approval not durable", err)
	}
	if _, err = p.Apply(input, "82d7893a-9423-4d6f-b8eb-5198f25c798e"); err == nil {
		t.Fatal("stale approval accepted")
	}
	r = p.Inspect()
	r, err = p.Apply(request(r, false), "82d7893a-9423-4d6f-b8eb-5198f25c798e")
	if err != nil || r.Enabled {
		t.Fatal("disable failed", err)
	}
	if _, err = p.Apply(input, jobID); err == nil {
		t.Fatal("old job replay enabled policy")
	}
	if b, err := os.ReadFile(c.DNSPath); err != nil || string(b) != `{"servers":[{"address":"1.1.1.1"}],"queryStrategy":"UseIPv4","disableFallback":true}` {
		t.Fatal("DNS changed")
	}
}
func TestChangeInvalidatesAndRequiresRestart(t *testing.T) {
	c := fixture(t)
	p, _ := New(c)
	r := p.Inspect()
	p.Apply(request(r, true), jobID)
	os.WriteFile(c.DNSPath, []byte(`{"servers":["8.8.8.8"]}`), 0600)
	r = p.Inspect()
	if r.Enabled || r.Generation != 3 || len(r.Blockers) == 0 {
		t.Fatalf("change not blocked: %+v", r)
	}
	if _, err := p.Apply(request(r, true), jobID); err == nil {
		t.Fatal("changed runtime approved without restart")
	}
	p, _ = New(c)
	r = p.Inspect()
	if r.Enabled || len(r.Blockers) != 0 {
		t.Fatalf("restart: %+v", r)
	}
	if _, err := p.Apply(request(r, true), "82d7893a-9423-4d6f-b8eb-5198f25c798e"); err != nil {
		t.Fatal(err)
	}
}
func TestUnsafeDNSAndInboundRejected(t *testing.T) {
	for _, dns := range []string{`{"servers":["fakedns"]}`, `{"servers":[{"address":"fakedns+local"}]}`, `{"hosts":{"example.org":"1.1.1.1"}}`, `null`, `{"unknown":true}`, `{"servers":false}`} {
		t.Run(dns, func(t *testing.T) {
			c := fixture(t)
			os.WriteFile(c.DNSPath, []byte(dns), 0600)
			p, _ := New(c)
			r := p.Inspect()
			if r.DNSCompatible || r.Enabled {
				t.Fatal("unsafe DNS accepted")
			}
			if _, err := p.Apply(request(r, true), jobID); err == nil {
				t.Fatal("unsafe approval accepted")
			}
		})
	}
	c := fixture(t)
	c.InboundPath = c.DNSPath
	p, _ := New(c)
	r := p.Inspect()
	if _, err := p.Apply(request(r, true), jobID); err == nil {
		t.Fatal("custom inbound accepted")
	}
}
func TestJournalTamperAndScopeFailClosed(t *testing.T) {
	c := fixture(t)
	p, _ := New(c)
	p.Inspect()
	os.WriteFile(p.path(), []byte(`{"enabled":true}`), 0600)
	if p.Inspect().Enabled {
		t.Fatal("live tampering accepted")
	}
	p, _ = New(c)
	r := p.Inspect()
	if r.Enabled || len(r.Blockers) == 0 {
		t.Fatal("tampered journal accepted")
	}
	c = fixture(t)
	p, _ = New(c)
	r = p.Inspect()
	p.Apply(request(r, true), jobID)
	c.CoreID = "2670d54c-ab87-4805-9e24-d9545fc2e630"
	p, _ = New(c)
	if p.Inspect().Enabled {
		t.Fatal("foreign core journal accepted")
	}
}
func TestExplicitAcknowledgmentAndStrictPayload(t *testing.T) {
	c := fixture(t)
	p, _ := New(c)
	r := p.Inspect()
	for _, input := range []string{`{}`, `{"acknowledged":false}`, string(request(r, true)) + ` {}`, `{"unexpected":true}`} {
		if _, err := p.Apply([]byte(input), jobID); err == nil {
			t.Fatal("invalid request accepted")
		}
	}
	if _, err := p.Apply(request(r, true), "not-a-job"); err == nil {
		t.Fatal("invalid job accepted")
	}
}
