package dependencypolicy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func validPolicyJSON() string {
	return `{
  "schema": "dependency-policy/v1",
  "ecosystem": "go",
  "admission": {
    "required_evidence": ["sbom", "provenance"],
    "max_cvss": 7.5,
    "blocked_licenses": ["AGPL-3.0"]
  },
  "exceptions": [{"reference": "exceptions/0001.json", "expires_at": "2027-01-01T00:00:00Z"}],
  "revocation": {"download_block": true}
}`
}

func mutatePolicy(t *testing.T, base string, old string, replacement string) string {
	t.Helper()
	if !strings.Contains(base, old) {
		t.Fatalf("mutation target %q not present in base policy", old)
	}
	return strings.Replace(base, old, replacement, 1)
}

func TestParseValidPolicies(t *testing.T) {
	base := validPolicyJSON()
	variants := map[string]string{
		"complete": base,
		"without max cvss": mutatePolicy(t, base,
			`"max_cvss": 7.5,`,
			``),
		"without blocked licenses": mutatePolicy(t, base,
			`"blocked_licenses": ["AGPL-3.0"]`,
			`"blocked_licenses": []`),
		"empty exceptions": mutatePolicy(t, base,
			`"exceptions": [{"reference": "exceptions/0001.json", "expires_at": "2027-01-01T00:00:00Z"}]`,
			`"exceptions": []`),
		"boundary max cvss zero": mutatePolicy(t, base,
			`"max_cvss": 7.5`,
			`"max_cvss": 0`),
		"boundary max cvss ten": mutatePolicy(t, base,
			`"max_cvss": 7.5`,
			`"max_cvss": 10`),
		"npm ecosystem": mutatePolicy(t, base,
			`"ecosystem": "go"`,
			`"ecosystem": "npm"`),
		"python ecosystem": mutatePolicy(t, base,
			`"ecosystem": "go"`,
			`"ecosystem": "python"`),
	}
	for name, policy := range variants {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse([]byte(policy)); err != nil {
				t.Fatalf("Parse() error = %v, want valid policy", err)
			}
		})
	}
}

func TestParseRejectsInvalidPolicies(t *testing.T) {
	base := validPolicyJSON()
	cases := map[string]struct {
		policy  string
		wantErr string
	}{
		"wrong schema": {
			policy:  mutatePolicy(t, base, `"dependency-policy/v1"`, `"dependency-policy/v9"`),
			wantErr: "schema must be",
		},
		"bad ecosystem": {
			policy:  mutatePolicy(t, base, `"ecosystem": "go"`, `"ecosystem": "node"`),
			wantErr: "ecosystem",
		},
		"empty required evidence": {
			policy:  mutatePolicy(t, base, `"required_evidence": ["sbom", "provenance"]`, `"required_evidence": []`),
			wantErr: "required_evidence must not be empty",
		},
		"unknown evidence type": {
			policy:  mutatePolicy(t, base, `"sbom"`, `"vibes"`),
			wantErr: "not an evidence-graph/v1 evidence type",
		},
		"max cvss too low": {
			policy:  mutatePolicy(t, base, `"max_cvss": 7.5`, `"max_cvss": -0.1`),
			wantErr: "max_cvss",
		},
		"max cvss too high": {
			policy:  mutatePolicy(t, base, `"max_cvss": 7.5`, `"max_cvss": 10.1`),
			wantErr: "max_cvss",
		},
		"empty blocked license": {
			policy:  mutatePolicy(t, base, `"AGPL-3.0"`, `""`),
			wantErr: "blocked_licenses[0]",
		},
		"exceptions missing": {
			policy: mutatePolicy(t, base,
				`"exceptions": [{"reference": "exceptions/0001.json", "expires_at": "2027-01-01T00:00:00Z"}],`,
				``),
			wantErr: "exceptions must be present",
		},
		"exception empty reference": {
			policy:  mutatePolicy(t, base, `"reference": "exceptions/0001.json"`, `"reference": ""`),
			wantErr: "exception reference",
		},
		"exception bad expiry": {
			policy:  mutatePolicy(t, base, `"expires_at": "2027-01-01T00:00:00Z"`, `"expires_at": "later"`),
			wantErr: "expires_at must be RFC 3339",
		},
		"revocation download block disabled": {
			policy:  mutatePolicy(t, base, `"download_block": true`, `"download_block": false`),
			wantErr: "download_block",
		},
		"unknown field": {
			policy: mutatePolicy(t, base,
				`"schema": "dependency-policy/v1",`,
				`"schema": "dependency-policy/v1", "unexpected": true,`),
			wantErr: "decode dependency policy",
		},
		"trailing data": {
			policy:  base + `{}`,
			wantErr: "trailing data",
		},
		"forbidden content": {
			policy:  mutatePolicy(t, base, `"exceptions/0001.json"`, `"github_pat_abc"`),
			wantErr: "forbidden credential-like content",
		},
		"invalid json": {
			policy:  `{`,
			wantErr: "decode dependency policy",
		},
	}
	for name, testCase := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Parse([]byte(testCase.policy))
			if err == nil {
				t.Fatalf("Parse() error = nil, want error containing %q", testCase.wantErr)
			}
			if !strings.Contains(err.Error(), testCase.wantErr) {
				t.Fatalf("Parse() error = %q, want substring %q", err.Error(), testCase.wantErr)
			}
		})
	}
}

func TestValidatePolicy(t *testing.T) {
	if err := ValidatePolicy([]byte(validPolicyJSON())); err != nil {
		t.Fatalf("ValidatePolicy() error = %v, want nil", err)
	}
	if err := ValidatePolicy([]byte(`{"schema": "nope"}`)); err == nil {
		t.Fatal("ValidatePolicy() error = nil, want error")
	}
}

func TestShippedPoliciesConform(t *testing.T) {
	for _, ecosystem := range []string{"go", "npm", "python"} {
		path := filepath.Join("..", "..", "policies", "dependency", ecosystem, "policy.json")
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("ReadFile(%q) error = %v", path, err)
		}
		if err := ValidatePolicy(data); err != nil {
			t.Fatalf("shipped policy %q is not conformant: %v", path, err)
		}
	}
}
