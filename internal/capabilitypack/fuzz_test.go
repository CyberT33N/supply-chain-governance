package capabilitypack

import "testing"

func FuzzParsePack(f *testing.F) {
	for _, seed := range []string{
		validDescriptor,
		`{"schema": "capability-pack/v1", "capability": "opentofu", "area": "infrastructure", "version": 1, "summary": "x", "provisioning": {"kind": "recipe", "tool": "tofu", "version": "1.12.5", "environment": {}, "artifacts": {"linux-amd64": {"url": "https://example.invalid/x.zip", "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}}, "discovery": {"roots": {"fileGlob": "**/*.tf"}, "excludeDirs": []}, "assertions": [], "gates": [{"name": "opentofu-fmt-check", "command": "tofu", "args": [], "scope": "repository"}]}`,
		`{"schema": "capability-pack/v2"}`,
		`{"schema": "capability-pack/v1", "version": 0}`,
		`{`,
		"",
		"\x00",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		_, _ = Parse([]byte(raw))
	})
}
