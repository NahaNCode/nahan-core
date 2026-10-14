package main

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	updater "github.com/NahaNCode/nahan-core/utility/update"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func main() {
	keyPath := flag.String("key", "", "Owner-only PKCS8 Ed25519 signing key")
	version := flag.String("version", "", "Stable release version")
	commit := flag.String("commit", "", "Source commit")
	directory := flag.String("directory", "artifacts", "Release binary directory")
	output := flag.String("output", "artifacts/updates.json", "Signed catalog path")
	flag.Parse()
	if !updater.VersionPattern.MatchString(*version) || len(*commit) != 40 {
		fail("invalid release identity")
	}
	info, err := os.Lstat(*keyPath)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 4096 {
		fail("signing key must be a protected regular file")
	}
	data, err := os.ReadFile(*keyPath)
	if err != nil {
		fail("signing key unavailable")
	}
	block, _ := pem.Decode(data)
	if block == nil {
		fail("invalid signing key")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		fail("invalid signing key")
	}
	key, ok := parsed.(ed25519.PrivateKey)
	if !ok || base64.StdEncoding.EncodeToString(key.Public().(ed25519.PublicKey)) != updater.PublicKey {
		fail("signer does not match the updater trust root")
	}
	release := updater.Release{Version: *version, Commit: *commit, PublishedAt: time.Now().Unix(), ExpiresAt: time.Now().Add(120 * 24 * time.Hour).Unix(), Assets: map[string]updater.Asset{}}
	for _, arch := range []string{"amd64", "arm64"} {
		name := "NahaN-linux-" + arch
		path := filepath.Join(*directory, name)
		info, err := os.Stat(path)
		if err != nil {
			continue
		}
		digest, err := updater.Hash(path)
		if err != nil {
			fail("release binary unavailable")
		}
		imageData, err := os.ReadFile(path + ".image")
		if err != nil {
			fail("signed image digest unavailable")
		}
		image := strings.TrimSpace(string(imageData))
		if !strings.HasPrefix(image, "ghcr.io/nahancode/nahan-core@sha256:") || !updater.DigestPattern.MatchString(strings.TrimPrefix(image, "ghcr.io/nahancode/nahan-core@sha256:")) {
			fail("invalid image identity")
		}
		release.Assets["linux-"+arch] = updater.Asset{URL: "https://github.com/NahaNCode/nahan-core/releases/download/" + *version + "/" + name, SHA256: digest, Size: info.Size(), Image: image}
	}
	if len(release.Assets) != 2 {
		fail("both supported release architectures must be present")
	}
	payload, err := json.Marshal(release)
	if err != nil {
		fail("release encoding failed")
	}
	envelope := updater.Envelope{Payload: base64.StdEncoding.EncodeToString(payload), Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(key, payload))}
	encoded, _ := json.Marshal(envelope)
	if _, err = updater.Verify(encoded, updater.PublicKey, time.Now()); err != nil {
		fail("generated catalog did not verify")
	}
	if err = updater.AtomicBytes(*output, encoded, 0644); err != nil {
		fail("catalog output unavailable")
	}
	fmt.Println("Verified signed catalog created; signing key was not exported.")
}
func fail(message string) { fmt.Fprintln(os.Stderr, message); os.Exit(1) }
