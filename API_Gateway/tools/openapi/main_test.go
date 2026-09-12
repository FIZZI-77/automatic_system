package main

import (
	"encoding/json"
	"testing"
)

func TestGenerateFromGatewayCode(t *testing.T) {
	data, err := generate("../..")
	if err != nil {
		t.Fatal(err)
	}
	var doc document
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Paths) < 180 {
		t.Fatalf("expected all Gateway routes, got %d", len(doc.Paths))
	}
	login := doc.Paths["/auth/login"]["post"].(map[string]any)
	if login["requestBody"] == nil || login["security"] != nil {
		t.Fatal("public login must have a body and no bearer security")
	}
	asset := doc.Paths["/assets/create"]["post"].(map[string]any)
	if asset["requestBody"] == nil || asset["security"] == nil {
		t.Fatal("protected asset creation must have a body and bearer security")
	}
	if _, ok := asset["responses"].(map[string]any)["201"]; !ok {
		t.Fatal("asset creation returns 201 through dispatchResponse")
	}
	route := doc.Paths["/routing/build"]["post"].(map[string]any)
	if route["requestBody"] == nil {
		t.Fatal("routing/build request schema is missing")
	}
	for name, value := range doc.Components["schemas"].(map[string]any) {
		checkRefs(t, name, value, doc.Components["schemas"].(map[string]any))
	}
	for name, path := range doc.Paths {
		checkRefs(t, name, path, doc.Components["schemas"].(map[string]any))
	}
}

func checkRefs(t *testing.T, source string, value any, schemas map[string]any) {
	t.Helper()
	switch node := value.(type) {
	case map[string]any:
		for key, child := range node {
			if key == "$ref" {
				ref := child.(string)
				prefix := "#/components/schemas/"
				if len(ref) < len(prefix) || ref[:len(prefix)] != prefix || schemas[ref[len(prefix):]] == nil {
					t.Errorf("%s has unresolved reference %s", source, ref)
				}
				continue
			}
			checkRefs(t, source, child, schemas)
		}
	case []any:
		for _, child := range node {
			checkRefs(t, source, child, schemas)
		}
	}
}
