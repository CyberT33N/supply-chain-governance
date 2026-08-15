package evidencegraph

import (
	"bytes"
	"encoding/json"
	"testing"
)

func FuzzParseDocument(f *testing.F) {
	for _, seed := range []string{
		validDocumentJSON(),
		`{}`,
		`{"schema":"evidence-graph/v1"}`,
		`{"schema":"evidence-graph/v1"} trailing`,
		`not json`,
		``,
		`null`,
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		lowered := bytes.ToLower(data)
		document, err := Parse(data)
		for _, marker := range forbiddenContentMarkers {
			if bytes.Contains(lowered, []byte(marker)) && err == nil {
				t.Fatalf("Parse() succeeded despite forbidden content marker %q", marker)
			}
		}
		if err != nil {
			return
		}
		if document.Schema != SchemaID {
			t.Fatalf("Parse() succeeded with schema %q, want %q", document.Schema, SchemaID)
		}
		if err := ValidateDocument(data); err != nil {
			t.Fatalf("Parse() succeeded but ValidateDocument() failed: %v", err)
		}
		encoded, err := json.Marshal(document)
		if err != nil {
			t.Fatalf("json.Marshal(parsed document) error = %v", err)
		}
		if _, err := Parse(encoded); err != nil {
			t.Fatalf("Parse(json.Marshal(parsed document)) error = %v", err)
		}
	})
}
