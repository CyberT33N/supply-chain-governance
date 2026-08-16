package dependencypolicy

import (
	"encoding/json"
	"testing"

	"github.com/t33n-software/supply-chain-governance/internal/evidencegraph"
)

func FuzzParsePolicy(f *testing.F) {
	for _, seed := range []string{
		validPolicyJSON(),
		`{}`,
		`{"schema":"dependency-policy/v1"}`,
		`{"schema":"dependency-policy/v1"} trailing`,
		`not json`,
		``,
		`null`,
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		policy, err := Parse(data)
		if err != nil {
			return
		}
		if policy.Schema != SchemaID {
			t.Fatalf("Parse() succeeded with schema %q, want %q", policy.Schema, SchemaID)
		}
		if err := ValidatePolicy(data); err != nil {
			t.Fatalf("Parse() succeeded but ValidatePolicy() failed: %v", err)
		}
		if err := evidencegraph.RejectForbiddenContent(data); err != nil {
			t.Fatalf("Parse() succeeded despite forbidden content: %v", err)
		}
		encoded, err := json.Marshal(policy)
		if err != nil {
			t.Fatalf("json.Marshal(parsed policy) error = %v", err)
		}
		if _, err := Parse(encoded); err != nil {
			t.Fatalf("Parse(json.Marshal(parsed policy)) error = %v", err)
		}
	})
}
