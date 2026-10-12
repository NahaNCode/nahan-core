package entryprofile

import (
	_ "embed"
	"encoding/json"
	"strconv"
	"strings"
)

//go:embed xray-fields.json
var catalogData []byte

type field struct {
	Name   string `json:"name"`
	Schema shape  `json:"schema"`
}
type shape struct {
	Kind    string  `json:"kind"`
	Ref     string  `json:"ref"`
	Item    *shape  `json:"item"`
	Fields  []field `json:"fields"`
	Integer bool    `json:"integer"`
}
type catalog struct {
	Version     string            `json:"version"`
	Protocols   map[string]string `json:"protocols"`
	Definitions map[string]shape  `json:"definitions"`
}

var schemaCatalog = func() catalog {
	var c catalog
	if err := json.Unmarshal(catalogData, &c); err != nil {
		panic("invalid embedded entry schema")
	}
	return c
}()

func validShape(value any, s shape, depth int) bool {
	if depth > 24 {
		return false
	}
	if value == nil {
		return true
	}
	switch s.Kind {
	case "ref":
		definition, ok := schemaCatalog.Definitions[s.Ref]
		return !ok || validShape(value, definition, depth+1)
	case "object":
		data, ok := value.(map[string]any)
		if !ok {
			return false
		}
		fields := map[string]shape{}
		for _, f := range s.Fields {
			fields[f.Name] = f.Schema
		}
		for key, item := range data {
			child, exists := fields[key]
			if !exists || !validShape(item, child, depth+1) {
				return false
			}
		}
	case "array":
		rows, ok := value.([]any)
		if !ok {
			return false
		}
		for _, item := range rows {
			if s.Item != nil && !validShape(item, *s.Item, depth+1) {
				return false
			}
		}
	case "string-list":
		if _, ok := value.(string); ok {
			return true
		}
		rows, ok := value.([]any)
		if !ok {
			return false
		}
		for _, item := range rows {
			if _, ok := item.(string); !ok {
				return false
			}
		}
	case "map":
		values, ok := value.(map[string]any)
		if !ok {
			return false
		}
		for _, item := range values {
			if s.Item != nil && !validShape(item, *s.Item, depth+1) {
				return false
			}
		}
	case "string":
		_, ok := value.(string)
		return ok
	case "number":
		number, ok := value.(json.Number)
		if !ok {
			return false
		}
		_, err := strconv.ParseFloat(string(number), 64)
		return err == nil && (!s.Integer || !strings.ContainsAny(string(number), ".eE"))
	case "boolean":
		_, ok := value.(bool)
		return ok
	case "range":
		switch value.(type) {
		case string, json.Number:
			return true
		default:
			return false
		}
	}
	return true
}

func validProfile(value any, protocol string) bool {
	data, ok := value.(map[string]any)
	if !ok {
		return false
	}
	definition, ok := schemaCatalog.Protocols[protocol]
	if !ok {
		return false
	}
	return validShape(data, schemaCatalog.Definitions["InboundDetourConfig"], 0) && validShape(data["settings"], schemaCatalog.Definitions[definition], 0)
}
