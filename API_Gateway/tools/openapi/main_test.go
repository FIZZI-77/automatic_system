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

	withoutBody := map[string]bool{
		"/analytics/projections/health":  true,
		"/auth/logout":                   true,
		"/auth/logout-all":               true,
		"/notifications/preferences/get": true,
		"/notifications/read-all":        true,
	}
	for path, methods := range doc.Paths {
		post, ok := methods["post"]

		if !ok {
			continue
		}

		operation := post.(map[string]any)

		if (operation["requestBody"] == nil) != withoutBody[path] {
			t.Errorf("%s has incorrect JSON request body", path)
		}

	}
	sla := doc.Paths["/sla/rules/create"]["post"].(map[string]any)
	requestBody := sla["requestBody"].(map[string]any)
	content := requestBody["content"].(map[string]any)["application/json"].(map[string]any)

	if content["schema"].(map[string]any)["$ref"] != "#/components/schemas/CreateSLARuleRequest" {
		t.Fatal("SLA creation must use its request model")
	}

	schema := doc.Components["schemas"].(map[string]any)["CreateSLARuleRequest"].(map[string]any)
	properties := schema["properties"].(map[string]any)
	responseTime := properties["response_time_seconds"].(map[string]any)

	if responseTime["minimum"] != float64(0) || responseTime["exclusiveMinimum"] != true {
		t.Fatal("SLA response time must be greater than zero")
	}

	ticket := doc.Components["schemas"].(map[string]any)["CreateTicketRequest"].(map[string]any)
	priority := ticket["properties"].(map[string]any)["priority"].(map[string]any)

	if len(priority["enum"].([]any)) != 4 {
		t.Fatal("ticket priority choices are missing")
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
