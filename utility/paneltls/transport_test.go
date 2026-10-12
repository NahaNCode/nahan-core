package paneltls

import "testing"

func TestRemoteTLSRequired(t *testing.T) {
	for _, address := range []string{"http://example.com", "http://192.168.1.1", "https://user:pass@example.com", "file:///etc/passwd"} {
		if _, err := Transport(address, "", ""); err == nil {
			t.Fatalf("accepted unsafe address %s", address)
		}
	}
	for _, address := range []string{"http://127.0.0.1:8080", "http://[::1]:8080", "https://192.0.2.1:443"} {
		tr, err := Transport(address, "", "panel.example.com")
		if err != nil {
			t.Fatal(err)
		}
		if tr.TLSClientConfig.InsecureSkipVerify {
			t.Fatal("TLS bypass")
		}
		if tr.TLSClientConfig.ServerName != "panel.example.com" {
			t.Fatal("missing IP TLS identity")
		}
	}
}
