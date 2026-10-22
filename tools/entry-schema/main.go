// Generate the entry catalog from the reviewed engine's Go JSON contracts.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

type Schema struct {
	Kind    string  `json:"kind"`
	Ref     string  `json:"ref,omitempty"`
	Item    *Schema `json:"item,omitempty"`
	Fields  []Field `json:"fields,omitempty"`
	Integer bool    `json:"integer,omitempty"`
}
type Field struct {
	Name   string `json:"name"`
	Schema Schema `json:"schema"`
}

func schema(expr ast.Expr) Schema {
	switch t := expr.(type) {
	case *ast.StarExpr:
		return schema(t.X)
	case *ast.Ident:
		switch t.Name {
		case "bool":
			return Schema{Kind: "boolean"}
		case "string", "Address", "TransportProtocol":
			return Schema{Kind: "string"}
		case "PortList", "Int32Range", "Int64Range":
			return Schema{Kind: "range"}
		case "StringList", "NetworkList":
			s := Schema{Kind: "string"}
			return Schema{Kind: "string-list", Item: &s}
		case "any", "interface{}":
			return Schema{Kind: "json"}
		}
		if strings.HasPrefix(t.Name, "int") || strings.HasPrefix(t.Name, "uint") || strings.HasPrefix(t.Name, "float") {
			return Schema{Kind: "number", Integer: !strings.HasPrefix(t.Name, "float")}
		}
		return Schema{Kind: "ref", Ref: t.Name}
	case *ast.ArrayType:
		s := schema(t.Elt)
		return Schema{Kind: "array", Item: &s}
	case *ast.MapType:
		s := schema(t.Value)
		return Schema{Kind: "map", Item: &s}
	case *ast.StructType:
		return Schema{Kind: "object", Fields: fields(t)}
	default:
		return Schema{Kind: "json"}
	}
}
func fields(t *ast.StructType) []Field {
	result := []Field{}
	for _, f := range t.Fields.List {
		if len(f.Names) == 0 || !ast.IsExported(f.Names[0].Name) {
			continue
		}
		name := strings.ToLower(f.Names[0].Name[:1]) + f.Names[0].Name[1:]
		if f.Tag != nil {
			tag, _ := strconv.Unquote(f.Tag.Value)
			for _, part := range strings.Fields(tag) {
				if strings.HasPrefix(part, "json:") {
					value, _ := strconv.Unquote(strings.TrimPrefix(part, "json:"))
					name = strings.Split(value, ",")[0]
				}
			}
		}
		if name == "-" {
			continue
		}
		if name == "" {
			name = f.Names[0].Name
		}
		result = append(result, Field{name, schema(f.Type)})
	}
	return result
}
func main() {
	source := flag.String("source", "", "pinned infra/conf directory")
	output := flag.String("output", "", "output JSON")
	version := flag.String("version", "26.10.21", "pinned Xray version")
	flag.Parse()
	paths, err := filepath.Glob(filepath.Join(*source, "*.go"))
	if err != nil {
		panic(err)
	}
	sort.Strings(paths)
	defs := map[string]Schema{}
	protocols := map[string]string{}
	hash := sha256.New()
	for _, p := range paths {
		if strings.HasSuffix(p, "_test.go") {
			continue
		}
		data, err := os.ReadFile(p)
		if err != nil {
			panic(err)
		}
		hash.Write([]byte(filepath.Base(p)))
		hash.Write(data)
		file, err := parser.ParseFile(token.NewFileSet(), p, data, 0)
		if err != nil {
			panic(err)
		}
		ast.Inspect(file, func(n ast.Node) bool {
			if t, ok := n.(*ast.TypeSpec); ok {
				defs[t.Name.Name] = schema(t.Type)
			}
			if v, ok := n.(*ast.ValueSpec); ok && len(v.Names) > 0 && v.Names[0].Name == "inboundConfigLoader" {
				call := v.Values[0].(*ast.CallExpr)
				table := call.Args[0].(*ast.CompositeLit)
				for _, e := range table.Elts {
					kv := e.(*ast.KeyValueExpr)
					key, _ := strconv.Unquote(kv.Key.(*ast.BasicLit).Value)
					fn := kv.Value.(*ast.FuncLit)
					ret := fn.Body.List[0].(*ast.ReturnStmt).Results[0]
					var typ string
					switch r := ret.(type) {
					case *ast.CallExpr:
						typ = r.Args[0].(*ast.Ident).Name
					case *ast.UnaryExpr:
						typ = r.X.(*ast.CompositeLit).Type.(*ast.Ident).Name
					}
					protocols[key] = typ
				}
			}
			return true
		})
	}
	if len(protocols) < 10 || len(defs["StreamConfig"].Fields) < 10 {
		panic("incomplete source catalog")
	}
	used := map[string]Schema{}
	var visit func(Schema)
	visit = func(s Schema) {
		if s.Ref != "" {
			if _, exists := used[s.Ref]; !exists {
				if ref, ok := defs[s.Ref]; ok {
					used[s.Ref] = ref
					visit(ref)
				}
			}
		}
		if s.Item != nil {
			visit(*s.Item)
		}
		for _, f := range s.Fields {
			visit(f.Schema)
		}
	}
	for _, typ := range protocols {
		visit(Schema{Kind: "ref", Ref: typ})
	}
	visit(Schema{Kind: "ref", Ref: "InboundDetourConfig"})
	result := map[string]any{"version": *version, "sourceDigest": hex.EncodeToString(hash.Sum(nil)), "protocols": protocols, "definitions": used}
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		panic(err)
	}
	if err = os.WriteFile(*output, append(data, '\n'), 0644); err != nil {
		panic(err)
	}
}
