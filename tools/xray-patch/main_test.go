package main

import "testing"

func TestToolchainIsReviewed(t *testing.T) {
	for _, version := range []string{"go1.27.1", "go1.27.2", "go1.28.0", "devel go1.28"} {
		if supportedToolchain(version) {
			t.Fatalf("accepted unreviewed toolchain %s", version)
		}
	}
	if !supportedToolchain("go1.27.3") {
		t.Fatal("rejected reviewed security toolchain")
	}
}
