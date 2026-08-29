package qualitygateconfig

import "testing"

func FuzzParseConfig(f *testing.F) {
	for _, seed := range []string{
		validMinimalDocument,
		validFullDocument,
		`{"schemaVersion": 4, "toolchain": {"language": "go", "version": "1.26.6"}, "defaults": {"includeFamilies": []}, "gates": [{"name": "x", "command": "go"}]}`,
		`{"schemaVersion": 3}`,
		`{"schemaVersion": 4, "gates": []}`,
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
