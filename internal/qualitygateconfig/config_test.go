package qualitygateconfig

import (
	"slices"
	"strings"
	"testing"
)

const validMinimalDocument = `{
  "schemaVersion": 4,
  "toolchain": {"language": "go", "version": "1.26.6"},
  "gates": [
    {"name": "full-local-build", "command": "go", "args": ["tool", "-modfile", "tools/go.mod", "quality-gate"], "timeout": "15m"}
  ]
}`

const validFullDocument = `{
  "schemaVersion": 4,
  "toolchain": {"language": "go", "version": "1.26.6"},
  "extends": ["opentofu@1"],
  "defaults": {"includeFamilies": ["feature", "fix"], "excludeFamilies": ["scratch"]},
  "gates": [
    {
      "name": "full-local-build",
      "command": "go",
      "args": ["tool", "-modfile", "tools/go.mod", "quality-gate"],
      "timeout": "15m",
      "workingDirectory": "build",
      "includeFamilies": ["feature"],
      "excludeFamilies": ["scratch"]
    }
  ],
  "project": {
    "binaries": [{"package": "./cmd/build", "smoke": ["--version"]}],
    "fuzz": [{"package": "./internal/qualitygateconfig", "target": "FuzzParseConfig", "time": "50000x"}]
  }
}`

func validConfig() Config {
	return Config{
		SchemaVersion: SchemaVersion,
		Toolchain:     Toolchain{Language: "go", Version: "1.26.6"},
		Gates:         []Gate{{Name: "full-local-build", Command: "go"}},
	}
}

func TestDefaultIncludeFamilies(t *testing.T) {
	want := []string{"feature", "fix", "docs", "refactor", "chore", "test", "perf", "hotfix"}
	got := DefaultIncludeFamilies()
	if !slices.Equal(got, want) {
		t.Fatalf("DefaultIncludeFamilies() = %v, want %v", got, want)
	}
	got[0] = "mutated"
	if DefaultIncludeFamilies()[0] != "feature" {
		t.Fatal("DefaultIncludeFamilies() must return an independent copy")
	}
}

func TestParseFillsTheDefaultWhenDefaultsAreAbsent(t *testing.T) {
	config, err := Parse([]byte(validMinimalDocument))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if config.Defaults == nil {
		t.Fatal("Parse() left Defaults nil, want the filled block")
	}
	if !slices.Equal(config.Defaults.IncludeFamilies, DefaultIncludeFamilies()) {
		t.Fatalf("Defaults.IncludeFamilies = %v, want the canonical default", config.Defaults.IncludeFamilies)
	}
}

func TestParseFillsTheDefaultWhenIncludeFamiliesIsAbsent(t *testing.T) {
	document := `{
	  "schemaVersion": 4,
	  "toolchain": {"language": "go", "version": "1.26.6"},
	  "defaults": {"excludeFamilies": ["scratch"]},
	  "gates": [{"name": "full-local-build", "command": "go"}]
	}`
	config, err := Parse([]byte(document))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if !slices.Equal(config.Defaults.IncludeFamilies, DefaultIncludeFamilies()) {
		t.Fatalf("Defaults.IncludeFamilies = %v, want the canonical default", config.Defaults.IncludeFamilies)
	}
	if !slices.Equal(config.Defaults.ExcludeFamilies, []string{"scratch"}) {
		t.Fatalf("Defaults.ExcludeFamilies = %v, want the declared list", config.Defaults.ExcludeFamilies)
	}
}

func TestParseKeepsADeclaredDeviation(t *testing.T) {
	config, err := Parse([]byte(validFullDocument))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if !slices.Equal(config.Defaults.IncludeFamilies, []string{"feature", "fix"}) {
		t.Fatalf("Defaults.IncludeFamilies = %v, want the declared deviation", config.Defaults.IncludeFamilies)
	}
	if config.Gates[0].WorkingDirectory != "build" {
		t.Fatalf("Gates[0].WorkingDirectory = %q, want build", config.Gates[0].WorkingDirectory)
	}
}

func TestParseKeepsAnExplicitlyEmptyDeviation(t *testing.T) {
	document := `{
	  "schemaVersion": 4,
	  "toolchain": {"language": "go", "version": "1.26.6"},
	  "defaults": {"includeFamilies": []},
	  "gates": [{"name": "full-local-build", "command": "go"}]
	}`
	config, err := Parse([]byte(document))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if config.Defaults.IncludeFamilies == nil || len(config.Defaults.IncludeFamilies) != 0 {
		t.Fatalf("Defaults.IncludeFamilies = %v, want the declared empty list", config.Defaults.IncludeFamilies)
	}
}

func TestParseRejections(t *testing.T) {
	for _, tc := range []struct {
		name     string
		document string
		wantErr  string
	}{
		{
			name:     "forbidden content",
			document: `{"schemaVersion": 4, "toolchain": {"language": "go", "version": "1.26.6"}, "gates": [{"name": "x", "command": "cat private key"}]}`,
			wantErr:  "forbidden",
		},
		{
			name:     "malformed JSON",
			document: `{`,
			wantErr:  "decode quality gate config",
		},
		{
			name:     "trailing data",
			document: validMinimalDocument + "\n{}",
			wantErr:  "trailing data",
		},
		{
			name:     "unknown field",
			document: `{"schemaVersion": 4, "toolchain": {"language": "go", "version": "1.26.6"}, "gates": [{"name": "x", "command": "go"}], "unexpected": true}`,
			wantErr:  "decode quality gate config",
		},
		{
			name:     "invalid document",
			document: `{"schemaVersion": 3, "toolchain": {"language": "go", "version": "1.26.6"}, "gates": [{"name": "x", "command": "go"}]}`,
			wantErr:  "schemaVersion must be 4",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Parse([]byte(tc.document)); err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("Parse() error = %v, want substring %q", err, tc.wantErr)
			}
		})
	}
}

func TestValidateConfig(t *testing.T) {
	if err := ValidateConfig([]byte(validMinimalDocument)); err != nil {
		t.Fatalf("ValidateConfig() error = %v", err)
	}
	if err := ValidateConfig([]byte(`{`)); err == nil {
		t.Fatal("ValidateConfig() error = nil, want error")
	}
}

func TestValidate(t *testing.T) {
	for _, tc := range []struct {
		name    string
		mutate  func(*Config)
		wantErr string
	}{
		{
			name:    "valid minimal",
			mutate:  func(*Config) {},
			wantErr: "",
		},
		{
			name: "valid full surface",
			mutate: func(c *Config) {
				c.Extends = []string{"opentofu@1"}
				c.Defaults = &Defaults{IncludeFamilies: []string{"feature"}, ExcludeFamilies: []string{"scratch"}}
				c.Gates[0].Args = []string{"tool"}
				c.Gates[0].Timeout = "15m"
				c.Gates[0].WorkingDirectory = "build/out"
				c.Gates[0].IncludeFamilies = []string{"feature"}
				c.Gates[0].ExcludeFamilies = []string{"scratch"}
				c.Project = &Project{
					Binaries: []Binary{{Package: "./cmd/build", Smoke: []string{"--version"}}},
					Fuzz:     []Fuzz{{Package: "./internal/qualitygateconfig", Target: "FuzzParseConfig", Time: "30s"}},
				}
			},
			wantErr: "",
		},
		{
			name:    "wrong schema version",
			mutate:  func(c *Config) { c.SchemaVersion = 3 },
			wantErr: "schemaVersion must be 4",
		},
		{
			name:    "bad toolchain language",
			mutate:  func(c *Config) { c.Toolchain.Language = "Go" },
			wantErr: "toolchain.language",
		},
		{
			name:    "bad toolchain version",
			mutate:  func(c *Config) { c.Toolchain.Version = "go1.26.6" },
			wantErr: "toolchain.version",
		},
		{
			name: "too many extends",
			mutate: func(c *Config) {
				c.Extends = make([]string, 33)
				for index := range c.Extends {
					c.Extends[index] = "pack-" + strings.Repeat("a", index+1) + "@1"
				}
			},
			wantErr: "more than 32",
		},
		{
			name:    "bad extends reference",
			mutate:  func(c *Config) { c.Extends = []string{"opentofu"} },
			wantErr: "<capability>@<major>",
		},
		{
			name:    "duplicate extends",
			mutate:  func(c *Config) { c.Extends = []string{"opentofu@1", "opentofu@1"} },
			wantErr: "not unique",
		},
		{
			name:    "defaults with unknown family",
			mutate:  func(c *Config) { c.Defaults = &Defaults{IncludeFamilies: []string{"bugfix"}} },
			wantErr: "defaults: includeFamilies[0]",
		},
		{
			name:    "defaults with unknown exclude family",
			mutate:  func(c *Config) { c.Defaults = &Defaults{ExcludeFamilies: []string{"bugfix"}} },
			wantErr: "excludeFamilies[0]",
		},
		{
			name:    "no gates",
			mutate:  func(c *Config) { c.Gates = nil },
			wantErr: "at least one gate",
		},
		{
			name: "too many gates",
			mutate: func(c *Config) {
				c.Gates = make([]Gate, 33)
				for index := range c.Gates {
					c.Gates[index] = Gate{Name: "gate", Command: "go"}
				}
			},
			wantErr: "more than 32 gates",
		},
		{
			name:    "bad gate name",
			mutate:  func(c *Config) { c.Gates[0].Name = "Full build" },
			wantErr: "gates[0]: name",
		},
		{
			name:    "empty gate command",
			mutate:  func(c *Config) { c.Gates[0].Command = " " },
			wantErr: "command must be",
		},
		{
			name:    "gate command with line control",
			mutate:  func(c *Config) { c.Gates[0].Command = "go\r\nrun" },
			wantErr: "command must be",
		},
		{
			name: "too many gate args",
			mutate: func(c *Config) {
				c.Gates[0].Args = make([]string, 65)
			},
			wantErr: "more than 64",
		},
		{
			name:    "gate arg with NUL",
			mutate:  func(c *Config) { c.Gates[0].Args = []string{"a\x00b"} },
			wantErr: "args[0]",
		},
		{
			name:    "bad gate timeout",
			mutate:  func(c *Config) { c.Gates[0].Timeout = "abc" },
			wantErr: "timeout",
		},
		{
			name:    "zero gate timeout",
			mutate:  func(c *Config) { c.Gates[0].Timeout = "0s" },
			wantErr: "timeout",
		},
		{
			name:    "negative gate timeout",
			mutate:  func(c *Config) { c.Gates[0].Timeout = "-5m" },
			wantErr: "timeout",
		},
		{
			name:    "absolute working directory",
			mutate:  func(c *Config) { c.Gates[0].WorkingDirectory = "/abs" },
			wantErr: "workingDirectory",
		},
		{
			name:    "escaping working directory",
			mutate:  func(c *Config) { c.Gates[0].WorkingDirectory = "../outside" },
			wantErr: "escape",
		},
		{
			name:    "gate with unknown include family",
			mutate:  func(c *Config) { c.Gates[0].IncludeFamilies = []string{"bugfix"} },
			wantErr: "gates[0]: includeFamilies[0]",
		},
		{
			name:    "gate with duplicate exclude family",
			mutate:  func(c *Config) { c.Gates[0].ExcludeFamilies = []string{"fix", "fix"} },
			wantErr: "excludeFamilies[1]",
		},
		{
			name: "too many binaries",
			mutate: func(c *Config) {
				binaries := make([]Binary, 33)
				for index := range binaries {
					binaries[index] = Binary{Package: "./cmd/x"}
				}
				c.Project = &Project{Binaries: binaries}
			},
			wantErr: "more than 32",
		},
		{
			name:    "binary with bad package",
			mutate:  func(c *Config) { c.Project = &Project{Binaries: []Binary{{Package: "cmd/x"}}} },
			wantErr: "binaries[0]: package",
		},
		{
			name: "binary package not unique",
			mutate: func(c *Config) {
				c.Project = &Project{Binaries: []Binary{{Package: "./cmd/x"}, {Package: "./cmd/x"}}}
			},
			wantErr: "not unique per document",
		},
		{
			name: "binary smoke too many",
			mutate: func(c *Config) {
				c.Project = &Project{Binaries: []Binary{{Package: "./cmd/x", Smoke: make([]string, 17)}}}
			},
			wantErr: "more than 16",
		},
		{
			name: "binary smoke with line control",
			mutate: func(c *Config) {
				c.Project = &Project{Binaries: []Binary{{Package: "./cmd/x", Smoke: []string{"a\nb"}}}}
			},
			wantErr: "smoke[0]",
		},
		{
			name: "too many fuzz lanes",
			mutate: func(c *Config) {
				lanes := make([]Fuzz, 65)
				for index := range lanes {
					lanes[index] = Fuzz{Package: "./internal/x", Target: "FuzzX", Time: "1s"}
				}
				c.Project = &Project{Fuzz: lanes}
			},
			wantErr: "more than 64",
		},
		{
			name: "fuzz with bad package",
			mutate: func(c *Config) {
				c.Project = &Project{Fuzz: []Fuzz{{Package: "internal/x", Target: "FuzzX", Time: "1s"}}}
			},
			wantErr: "fuzz[0]: package",
		},
		{
			name: "fuzz with bad target",
			mutate: func(c *Config) {
				c.Project = &Project{Fuzz: []Fuzz{{Package: "./internal/x", Target: "fuzzX", Time: "1s"}}}
			},
			wantErr: "target",
		},
		{
			name: "fuzz with bad time",
			mutate: func(c *Config) {
				c.Project = &Project{Fuzz: []Fuzz{{Package: "./internal/x", Target: "FuzzX", Time: "abc"}}}
			},
			wantErr: "fuzz[0]: time",
		},
		{
			name:    "fuzz with empty time",
			mutate:  func(c *Config) { c.Project = &Project{Fuzz: []Fuzz{{Package: "./internal/x", Target: "FuzzX"}}} },
			wantErr: "time must not be empty",
		},
		{
			name: "fuzz pair not unique",
			mutate: func(c *Config) {
				c.Project = &Project{Fuzz: []Fuzz{
					{Package: "./internal/x", Target: "FuzzX", Time: "1s"},
					{Package: "./internal/x", Target: "FuzzX", Time: "2s"},
				}}
			},
			wantErr: "not unique per document",
		},
		{
			name: "same package with different fuzz targets",
			mutate: func(c *Config) {
				c.Project = &Project{Fuzz: []Fuzz{
					{Package: "./internal/x", Target: "FuzzX", Time: "1s"},
					{Package: "./internal/x", Target: "FuzzY", Time: "1s"},
				}}
			},
			wantErr: "",
		},
		{
			name: "same fuzz target in different packages",
			mutate: func(c *Config) {
				c.Project = &Project{Fuzz: []Fuzz{
					{Package: "./internal/x", Target: "FuzzX", Time: "1s"},
					{Package: "./internal/y", Target: "FuzzX", Time: "1s"},
				}}
			},
			wantErr: "",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config := validConfig()
			tc.mutate(&config)
			err := config.Validate()
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("Validate() error = %v, want nil", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("Validate() error = %v, want substring %q", err, tc.wantErr)
			}
		})
	}
}

func TestValidateWorkingDirectory(t *testing.T) {
	for _, tc := range []struct {
		value   string
		wantErr bool
	}{
		{"", false},
		{"build", false},
		{"a/b", false},
		{`a\b`, false},
		{"/abs", true},
		{`\abs`, true},
		{"C:/abs", true},
		{"..", true},
		{"../up", true},
		{`..\up`, true},
		{"a/../../b", true},
	} {
		t.Run("value="+tc.value, func(t *testing.T) {
			err := validateWorkingDirectory(tc.value)
			if tc.wantErr && err == nil {
				t.Fatalf("validateWorkingDirectory(%q) = nil, want error", tc.value)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("validateWorkingDirectory(%q) = %v, want nil", tc.value, err)
			}
		})
	}
}

func TestValidateFuzzTime(t *testing.T) {
	for _, tc := range []struct {
		value   string
		wantErr bool
	}{
		{"50000x", false},
		{"30s", false},
		{"", true},
		{"0s", true},
		{"-5m", true},
		{"abc", true},
	} {
		t.Run("value="+tc.value, func(t *testing.T) {
			err := validateFuzzTime(tc.value)
			if tc.wantErr && err == nil {
				t.Fatalf("validateFuzzTime(%q) = nil, want error", tc.value)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("validateFuzzTime(%q) = %v, want nil", tc.value, err)
			}
		})
	}
}

func TestIsFamily(t *testing.T) {
	for _, family := range []string{
		"main", "develop", "release", "support", "feature", "fix", "docs",
		"refactor", "chore", "test", "perf", "hotfix", "scratch",
	} {
		if !IsFamily(family) {
			t.Errorf("IsFamily(%q) = false, want true", family)
		}
	}
	for _, value := range []string{"", "bugfix", "main "} {
		if IsFamily(value) {
			t.Errorf("IsFamily(%q) = true, want false", value)
		}
	}
}
