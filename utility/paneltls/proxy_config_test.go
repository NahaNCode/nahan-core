package paneltls

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

func TestPrivateProxyAllowlist(t *testing.T) {
	for _, file := range []string{"nginx.conf", "apache.conf"} {
		data, e := os.ReadFile("../../deploy/private-control/" + file)
		if e != nil {
			t.Fatal(e)
		}
		var expression string
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, `location ~ "`) {
				expression = strings.TrimSuffix(strings.TrimPrefix(line, `location ~ "`), `" {`)
			}
			if strings.HasPrefix(line, `RewriteCond %{REQUEST_URI} !`) {
				expression = strings.TrimPrefix(line, `RewriteCond %{REQUEST_URI} !`)
			}
		}
		allow, e := regexp.Compile(expression)
		if e != nil || expression == "" {
			t.Fatalf("invalid %s allowlist", file)
		}
		for _, p := range []string{healthPath, "/api/core/v1/hosts/11111111-1111-4111-8111-111111111111/manifest", "/api/core/v1/nodes/20000012/server", "/api/core/v1/nodes/20000012/device-leases", "/api/core/v1/cores/11111111-1111-4111-8111-111111111111/egress/credentials"} {
			if !allow.MatchString(p) {
				t.Errorf("%s refuses %s", file, p)
			}
		}
		for _, p := range []string{"/api/core/admin/cores", "/api/auth/email-login", "/api/core/v1/nodes/1/server/extra", "/api/core/v1/cores/invalid/manifest", "/api/core/v1/nodes/1/rotate-token", "/api/core/subscriptions/secret/devices", "/api/core/v1/cores/11111111-1111-4111-8111-111111111111/../../admin"} {
			if allow.MatchString(p) {
				t.Errorf("%s exposed %s", file, p)
			}
		}
	}
}
