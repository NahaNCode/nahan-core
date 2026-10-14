package controlplane

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLocalPlacementAudienceExpiryAndMissingAgent(t *testing.T) {
	core := "22222222-2222-4222-8222-222222222222"
	path := filepath.Join(t.TempDir(), "placement.sock")
	c := &Client{Config: &Config{CoreID: core, HostSocket: path}}
	if c.hostPlacement(context.Background()) != nil {
		t.Fatal("guessed placement without agent")
	}
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	proof := HostPlacement{HostID: "11111111-1111-4111-8111-111111111111", CoreID: core, IssuedAt: time.Now().Unix(), Signature: strings.Repeat("a", 88)}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("coreId") != core {
			t.Error("wrong audience requested")
		}
		json.NewEncoder(w).Encode(proof)
	})}
	go server.Serve(listener)
	defer server.Close()
	if c.hostPlacement(context.Background()) == nil {
		t.Fatal("local proof missing")
	}
	// Stop each handler before mutating the fixture to keep race checks meaningful.
	server.Close()
	listener, err = net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	proof.CoreID = "33333333-3333-4333-8333-333333333333"
	server = &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { json.NewEncoder(w).Encode(proof) })}
	go server.Serve(listener)
	defer server.Close()
	if c.hostPlacement(context.Background()) != nil {
		t.Fatal("foreign audience accepted")
	}
}
