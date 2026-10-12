// Package entryprofile validates advanced entries before they reach a live engine.
package entryprofile

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"

	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf"
)

const MaxBytes = 60000

type Result struct {
	Valid         bool   `json:"valid"`
	EngineVersion string `json:"engineVersion"`
	Digest        string `json:"digest"`
	Protocol      string `json:"protocol"`
	Stage         string `json:"stage"`
	Code          string `json:"code,omitempty"`
}

// Preflight never starts an engine or binds a socket. Engine error text is not
// exposed because it can contain credentials or certificate material.
func Preflight(input []byte) Result {
	result := Result{EngineVersion: core.Version(), Stage: "document"}
	fail := func(code string) Result { result.Code = code; return result }
	if len(input) == 0 || len(input) > MaxBytes {
		return fail("invalid_size")
	}
	if err := uniqueKeys(json.NewDecoder(bytes.NewReader(input)), 0); err != nil {
		return fail("invalid_or_duplicate_json")
	}
	var document map[string]json.RawMessage
	if err := json.Unmarshal(input, &document); err != nil || document == nil {
		return fail("invalid_json")
	}
	raw := input
	if inbound, ok := document["inbound"]; ok {
		for key := range document {
			switch key {
			case "schemaVersion", "engineVersion", "name", "coreId", "address", "inbound":
			default:
				return fail("unknown_envelope_field")
			}
		}
		var schema int
		var engine string
		if json.Unmarshal(document["schemaVersion"], &schema) != nil || schema != 2 {
			return fail("unsupported_schema")
		}
		if json.Unmarshal(document["engineVersion"], &engine) != nil || engine != core.Version() {
			return fail("engine_mismatch")
		}
		raw = inbound
	}
	var values map[string]json.RawMessage
	if json.Unmarshal(raw, &values) != nil || values == nil {
		return fail("invalid_inbound")
	}
	allowed := map[string]bool{"protocol": true, "listen": true, "port": true, "settings": true, "streamSettings": true, "sniffing": true, "tag": true}
	for key := range values {
		if !allowed[key] {
			return fail("unknown_inbound_field")
		}
	}
	if json.Unmarshal(values["protocol"], &result.Protocol) != nil || result.Protocol == "" {
		return fail("missing_protocol")
	}
	var payload any
	reader := json.NewDecoder(bytes.NewReader(raw))
	reader.UseNumber()
	if reader.Decode(&payload) != nil {
		return fail("invalid_inbound")
	}
	if err := checkReferences(payload, 0); err != nil {
		return fail(err.Error())
	}
	if schemaCatalog.Version != core.Version() {
		return fail("catalog_engine_mismatch")
	}
	if !validProfile(payload, result.Protocol) {
		return fail("invalid_field")
	}
	var inbound conf.InboundDetourConfig
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&inbound) != nil {
		return fail("invalid_field")
	}
	var trailing any
	if decoder.Decode(&trailing) != io.EOF {
		return fail("invalid_json")
	}
	result.Stage = "engine_build"
	if _, err := inbound.Build(); err != nil {
		return fail("engine_rejected")
	}
	canonical, err := json.Marshal(payload)
	if err != nil {
		return fail("invalid_inbound")
	}
	digest := sha256.Sum256(canonical)
	result.Digest = hex.EncodeToString(digest[:])
	result.Valid = true
	result.Stage = "built"
	return result
}

func checkReferences(value any, depth int) error {
	if depth > 24 {
		return errors.New("excessive_nesting")
	}
	switch node := value.(type) {
	case map[string]any:
		for key, item := range node {
			if key == "__proto__" || key == "prototype" || key == "constructor" {
				return errors.New("unsafe_field")
			}
			if text, ok := item.(string); ok && len(text) >= 9 && text[:9] == "secret://" {
				return errors.New("unresolved_secret")
			}
			if err := checkReferences(item, depth+1); err != nil {
				return err
			}
		}
	case []any:
		for _, item := range node {
			if err := checkReferences(item, depth+1); err != nil {
				return err
			}
		}
	}
	return nil
}
