// Command openapi generates the public HTTP contract from Gateway routes and models.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
)

type operation struct {
	Tags        []string               `json:"tags"`
	Summary     string                 `json:"summary"`
	OperationID string                 `json:"operationId"`
	Security    []map[string][]string  `json:"security,omitempty"`
	RequestBody any                    `json:"requestBody,omitempty"`
	Responses   map[string]interface{} `json:"responses"`
}

type document struct {
	OpenAPI    string                    `json:"openapi"`
	Info       map[string]string         `json:"info"`
	Paths      map[string]map[string]any `json:"paths"`
	Components map[string]any            `json:"components"`
}

func main() {
	check := flag.Bool("check", false, "fail if the checked-in specification is stale")
	flag.Parse()
	root := "."
	if len(flag.Args()) != 0 {
		root = flag.Arg(0)
	}
	output := filepath.Join(root, "src", "core", "handlers", "openapi.json")
	data, err := generate(root)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if *check {
		current, err := os.ReadFile(output)
		if err != nil || !bytes.Equal(current, data) {
			fmt.Fprintln(os.Stderr, "openapi.json is stale; run go run ./tools/openapi")
			os.Exit(1)
		}
		return
	}
	if err := os.WriteFile(output, data, 0644); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func generate(root string) ([]byte, error) {
	fset := token.NewFileSet()
	router, err := parser.ParseFile(fset, filepath.Join(root, "src/core/handlers/handler.go"), nil, 0)
	if err != nil {
		return nil, err
	}
	handlers, err := parser.ParseDir(fset, filepath.Join(root, "src/core/handlers"), nil, 0)
	if err != nil {
		return nil, err
	}
	models, err := parser.ParseDir(fset, filepath.Join(root, "models"), nil, 0)
	if err != nil {
		return nil, err
	}
	schemas := make(map[string]any)
	for _, file := range models["models"].Files {
		for _, decl := range file.Decls {
			gen, ok := decl.(*ast.GenDecl)
			if !ok || gen.Tok != token.TYPE {
				continue
			}
			for _, spec := range gen.Specs {
				typ := spec.(*ast.TypeSpec)
				schemas[typ.Name.Name] = schema(typ.Type)
			}
		}
	}
	methods := make(map[string]*ast.FuncDecl)
	for _, file := range handlers["handlers"].Files {
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if ok && fn.Recv != nil {
				if receiver := receiverName(fn); receiver != "" {
					methods[receiver+"."+fn.Name.Name] = fn
				}
			}
		}
	}
	doc := document{
		OpenAPI: "3.0.3",
		Info: map[string]string{
			"title":       "Automatic City Services HTTP API",
			"version":     "1.0.0",
			"description": "Контракт HTTP-шлюза. Запросы и ответы выведены из маршрутов и моделей; для ответов без однозначной структуры схема не указывается.",
		},
		Paths: make(map[string]map[string]any),
		Components: map[string]any{
			"securitySchemes": map[string]any{"BearerAuth": map[string]string{"type": "http", "scheme": "bearer", "bearerFormat": "JWT"}},
			"schemas":         schemas,
		},
	}
	groups := map[string]string{"router": ""}
	ast.Inspect(router, func(node ast.Node) bool {
		switch n := node.(type) {
		case *ast.AssignStmt:
			if len(n.Lhs) != 1 || len(n.Rhs) != 1 {
				break
			}
			call, ok := n.Rhs[0].(*ast.CallExpr)
			if !ok || selector(call.Fun) != "Group" || len(call.Args) != 1 {
				break
			}
			name, ok := n.Lhs[0].(*ast.Ident)
			if !ok {
				break
			}
			base := call.Fun.(*ast.SelectorExpr).X.(*ast.Ident).Name
			if prefix, ok := groups[base]; ok {
				groups[name.Name] = prefix + literal(call.Args[0])
			}
		case *ast.CallExpr:
			method := selector(n.Fun)
			if (method != "GET" && method != "POST") || len(n.Args) != 2 {
				break
			}
			sel := n.Fun.(*ast.SelectorExpr)
			group, ok := sel.X.(*ast.Ident)
			if !ok {
				break
			}
			prefix, ok := groups[group.Name]
			if !ok {
				break
			}
			path := prefix + literal(n.Args[0])
			if path == "" {
				break
			}
			op := operation{Tags: []string{strings.Trim(prefix, "/")}, Responses: map[string]interface{}{"200": map[string]any{"description": "Успешный ответ"}}}
			if op.Tags[0] == "" {
				op.Tags[0] = "system"
			}
			if group.Name != "router" && group.Name != "publicAuth" {
				op.Security = []map[string][]string{{"BearerAuth": {}}}
			}
			if handler, ok := n.Args[1].(*ast.SelectorExpr); ok {
				op.Summary = handler.Sel.Name
				op.OperationID = group.Name + "." + handler.Sel.Name
				if fn := methods[routeHandlerName(handler.X)+"."+handler.Sel.Name]; fn != nil {
					fillOperation(&op, fn)
				}
			} else {
				op.Summary = strings.Trim(path, "/")
				op.OperationID = strings.ToLower(method) + "." + strings.Trim(path, "/")
			}
			if doc.Paths[path] == nil {
				doc.Paths[path] = make(map[string]any)
			}
			doc.Paths[path][strings.ToLower(method)] = op
		}
		return true
	})
	if len(doc.Paths) < 100 {
		return nil, fmt.Errorf("only %d routes discovered: check router parser", len(doc.Paths))
	}
	data, err := json.MarshalIndent(doc, "", "  ")
	return append(data, '\n'), err
}

func fillOperation(op *operation, fn *ast.FuncDecl) {
	locals := make(map[string]string)
	request := ""
	ast.Inspect(fn.Body, func(node ast.Node) bool {
		switch n := node.(type) {
		case *ast.ValueSpec:
			if typ := modelName(n.Type); typ != "" {
				for _, name := range n.Names {
					locals[name.Name] = typ
				}
			}
		case *ast.AssignStmt:
			if len(n.Lhs) == 1 && len(n.Rhs) == 1 {
				if name, ok := n.Lhs[0].(*ast.Ident); ok {
					if typ := modelValue(n.Rhs[0]); typ != "" {
						locals[name.Name] = typ
					}
				}
			}
		case *ast.CallExpr:
			if (selector(n.Fun) == "ShouldBindJSON" || identifier(n.Fun) == "bindJSON") && len(n.Args) > 0 {
				arg := n.Args[len(n.Args)-1]
				if unary, ok := arg.(*ast.UnaryExpr); ok {
					arg = unary.X
				}
				if name, ok := arg.(*ast.Ident); ok {
					request = locals[name.Name]
				}
			}
			responseCall := selector(n.Fun) == "JSON" && len(n.Args) == 2
			proxyCall := len(n.Args) == 4 && isResponseHelper(identifier(n.Fun))
			if responseCall || proxyCall {
				statusArg := n.Args[0]
				responseArg := n.Args[1]
				if proxyCall {
					statusArg = n.Args[1]
					responseArg = n.Args[3]
				}
				status := identifier(statusArg)
				if sel, ok := statusArg.(*ast.SelectorExpr); ok {
					status = sel.Sel.Name
				}
				code := ""
				switch status {
				case "StatusOK":
					code = "200"
				case "StatusCreated":
					code = "201"
				case "StatusNoContent":
					code = "204"
				}
				if code != "" {
					response := map[string]any{"description": "Успешный ответ"}
					typ := modelValue(responseArg)
					if typ == "" {
						if name, ok := responseArg.(*ast.Ident); ok {
							typ = locals[name.Name]
						}
					}
					if typ != "" {
						response["content"] = map[string]any{"application/json": map[string]any{"schema": ref(typ)}}
					}
					op.Responses[code] = response
					if code == "201" {
						delete(op.Responses, "200")
					}
				}
			}
		}
		return true
	})
	if request != "" {
		op.RequestBody = map[string]any{"required": fn.Name.Name != "SendVerificationEmail", "content": map[string]any{"application/json": map[string]any{"schema": ref(request)}}}
	}
}

func isResponseHelper(name string) bool {
	switch name {
	case "dispatchResponse", "brigadeResponse", "routingResponse", "profileResponse", "locationResponse":
		return true
	default:
		return false
	}
}

func schema(expr ast.Expr) any {
	switch n := expr.(type) {
	case *ast.StarExpr:
		return schema(n.X)
	case *ast.ArrayType:
		return map[string]any{"type": "array", "items": schema(n.Elt)}
	case *ast.MapType:
		return map[string]any{"type": "object", "additionalProperties": schema(n.Value)}
	case *ast.SelectorExpr:
		if identifier(n.X) == "time" && n.Sel.Name == "Time" {
			return map[string]string{"type": "string", "format": "date-time"}
		}
		return map[string]string{"type": "object"}
	case *ast.Ident:
		switch n.Name {
		case "string":
			return map[string]string{"type": "string"}
		case "bool":
			return map[string]string{"type": "boolean"}
		case "float32", "float64":
			return map[string]string{"type": "number"}
		case "int", "int32", "int64", "uint", "uint32", "uint64":
			return map[string]string{"type": "integer"}
		case "any":
			return map[string]string{}
		default:
			return ref(n.Name)
		}
	case *ast.StructType:
		properties := make(map[string]any)
		var required []string
		for _, field := range n.Fields.List {
			if len(field.Names) == 0 || field.Tag == nil {
				continue
			}
			tag, err := strconv.Unquote(field.Tag.Value)
			if err != nil {
				continue
			}
			jsonName := strings.Split(reflect.StructTag(tag).Get("json"), ",")[0]
			if jsonName == "-" || jsonName == "" {
				continue
			}
			properties[jsonName] = schema(field.Type)
			binding := reflect.StructTag(tag).Get("binding")
			for _, rule := range strings.Split(binding, ",") {
				if rule == "required" {
					required = append(required, jsonName)
				}
			}
		}
		result := map[string]any{"type": "object", "properties": properties}
		if len(required) > 0 {
			sort.Strings(required)
			result["required"] = required
		}
		return result
	default:
		return map[string]string{}
	}
}

func ref(name string) map[string]string {
	return map[string]string{"$ref": "#/components/schemas/" + name}
}

func modelName(expr ast.Expr) string {
	if p, ok := expr.(*ast.StarExpr); ok {
		return modelName(p.X)
	}
	if s, ok := expr.(*ast.SelectorExpr); ok && identifier(s.X) == "models" {
		return s.Sel.Name
	}
	return ""
}

func receiverName(fn *ast.FuncDecl) string {
	typ := fn.Recv.List[0].Type
	if ptr, ok := typ.(*ast.StarExpr); ok {
		typ = ptr.X
	}
	return identifier(typ)
}

func routeHandlerName(expr ast.Expr) string {
	field, ok := expr.(*ast.SelectorExpr)
	if !ok || identifier(field.X) != "h" || field.Sel.Name == "" {
		return ""
	}
	return strings.ToUpper(field.Sel.Name[:1]) + field.Sel.Name[1:]
}

func modelValue(expr ast.Expr) string {
	if p, ok := expr.(*ast.UnaryExpr); ok {
		return modelValue(p.X)
	}
	if c, ok := expr.(*ast.CompositeLit); ok {
		return modelName(c.Type)
	}
	return ""
}

func selector(expr ast.Expr) string {
	if s, ok := expr.(*ast.SelectorExpr); ok {
		return s.Sel.Name
	}
	return ""
}

func identifier(expr ast.Expr) string {
	if id, ok := expr.(*ast.Ident); ok {
		return id.Name
	}
	return ""
}

func literal(expr ast.Expr) string {
	if basic, ok := expr.(*ast.BasicLit); ok {
		value, _ := strconv.Unquote(basic.Value)
		return value
	}
	return ""
}
