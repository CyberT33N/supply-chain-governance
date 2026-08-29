// Package qualitygateconfig implements the quality-gate-config/v4 seam: the
// strict reference decoder for tenant quality gate configurations, the
// schema-owned canonical branch-family default for the include scope, and the
// validation rules of the centralized schema.
package qualitygateconfig

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/t33n-software/supply-chain-governance/internal/evidencegraph"
)

// SchemaVersion is the only accepted quality-gate-config schema version;
// earlier versions fail closed.
const SchemaVersion = 4

// Branch families defined by quality-gate-config/v4.
const (
	FamilyMain     = "main"
	FamilyDevelop  = "develop"
	FamilyRelease  = "release"
	FamilySupport  = "support"
	FamilyFeature  = "feature"
	FamilyFix      = "fix"
	FamilyDocs     = "docs"
	FamilyRefactor = "refactor"
	FamilyChore    = "chore"
	FamilyTest     = "test"
	FamilyPerf     = "perf"
	FamilyHotfix   = "hotfix"
	FamilyScratch  = "scratch"
)

var defaultIncludeFamilies = []string{
	FamilyFeature,
	FamilyFix,
	FamilyDocs,
	FamilyRefactor,
	FamilyChore,
	FamilyTest,
	FamilyPerf,
	FamilyHotfix,
}

// DefaultIncludeFamilies returns the canonical ticket-family set that applies
// whenever a configuration omits defaults.includeFamilies. The schema carries
// the same set as its default annotation; a declared list is a named
// deviation and is never rewritten.
func DefaultIncludeFamilies() []string {
	return slices.Clone(defaultIncludeFamilies)
}

var (
	languagePattern   = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)
	toolchainPattern  = regexp.MustCompile(`^[0-9]+\.[0-9]+(\.[0-9]+)?$`)
	extendsPattern    = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*@[0-9]+$`)
	gateNamePattern   = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)
	packagePattern    = regexp.MustCompile(`^\.?/[A-Za-z0-9_./-]+$`)
	fuzzTargetPattern = regexp.MustCompile(`^Fuzz[A-Za-z0-9_]*$`)
	fuzzCountPattern  = regexp.MustCompile(`^[0-9]+x$`)
)

// Config is one quality-gate-config/v4 document.
type Config struct {
	SchemaVersion int       `json:"schemaVersion"`
	Toolchain     Toolchain `json:"toolchain"`
	Extends       []string  `json:"extends"`
	Defaults      *Defaults `json:"defaults"`
	Gates         []Gate    `json:"gates"`
	Project       *Project  `json:"project"`
}

// Toolchain binds the language-keyed pinned toolchain identity.
type Toolchain struct {
	Language string `json:"language"`
	Version  string `json:"version"`
}

// Defaults carries the tenant-wide family scope. A missing includeFamilies
// list is filled with the canonical default during Parse.
type Defaults struct {
	IncludeFamilies []string `json:"includeFamilies"`
	ExcludeFamilies []string `json:"excludeFamilies"`
}

// Gate is one branch-family scoped gate command.
type Gate struct {
	Name             string   `json:"name"`
	Command          string   `json:"command"`
	Args             []string `json:"args"`
	Timeout          string   `json:"timeout"`
	WorkingDirectory string   `json:"workingDirectory"`
	IncludeFamilies  []string `json:"includeFamilies"`
	ExcludeFamilies  []string `json:"excludeFamilies"`
}

// Project carries the optional project-specific overrides.
type Project struct {
	Binaries []Binary `json:"binaries"`
	Fuzz     []Fuzz   `json:"fuzz"`
}

// Binary is one binary smoke contract.
type Binary struct {
	Package string   `json:"package"`
	Smoke   []string `json:"smoke"`
}

// Fuzz is one fuzz lane binding.
type Fuzz struct {
	Package string `json:"package"`
	Target  string `json:"target"`
	Time    string `json:"time"`
}

// Parse decodes and validates one quality-gate-config/v4 document. Unknown
// fields, trailing data, and credential-like content are rejected fail-closed.
// A missing defaults block or a missing includeFamilies list is filled with
// the canonical default; a declared list is a named deviation and is kept.
func Parse(data []byte) (Config, error) {
	var config Config
	if err := evidencegraph.RejectForbiddenContent(data); err != nil {
		return config, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&config); err != nil {
		return config, fmt.Errorf("decode quality gate config: %w", err)
	}
	if decoder.More() {
		return config, errors.New("quality gate config contains trailing data")
	}
	config.applyDefaults()
	if err := config.Validate(); err != nil {
		return config, err
	}
	return config, nil
}

// ValidateConfig parses and validates one quality-gate-config/v4 document.
func ValidateConfig(data []byte) error {
	_, err := Parse(data)
	return err
}

// applyDefaults fills the schema-owned default for the include scope. The
// fill happens only when the block or the list is absent; an explicitly
// declared list, even an empty one, is a named deviation.
func (c *Config) applyDefaults() {
	if c.Defaults == nil {
		c.Defaults = &Defaults{}
	}
	if c.Defaults.IncludeFamilies == nil {
		c.Defaults.IncludeFamilies = DefaultIncludeFamilies()
	}
}

// Validate enforces every quality-gate-config/v4 invariant.
func (c Config) Validate() error {
	if c.SchemaVersion != SchemaVersion {
		return fmt.Errorf("schemaVersion must be %d, got %d", SchemaVersion, c.SchemaVersion)
	}
	if err := c.Toolchain.validate(); err != nil {
		return err
	}
	if len(c.Extends) > 32 {
		return fmt.Errorf("extends must not contain more than 32 references, got %d", len(c.Extends))
	}
	seenExtends := make(map[string]struct{}, len(c.Extends))
	for index, reference := range c.Extends {
		if !extendsPattern.MatchString(reference) {
			return fmt.Errorf("extends[%d] %q must use the <capability>@<major> form", index, reference)
		}
		if _, found := seenExtends[reference]; found {
			return fmt.Errorf("extends[%d] %q is not unique", index, reference)
		}
		seenExtends[reference] = struct{}{}
	}
	if c.Defaults != nil {
		if err := c.Defaults.validate(); err != nil {
			return fmt.Errorf("defaults: %w", err)
		}
	}
	if len(c.Gates) == 0 {
		return errors.New("gates must contain at least one gate")
	}
	if len(c.Gates) > 32 {
		return fmt.Errorf("gates must not contain more than 32 gates, got %d", len(c.Gates))
	}
	for index, gate := range c.Gates {
		if err := gate.validate(); err != nil {
			return fmt.Errorf("gates[%d]: %w", index, err)
		}
	}
	if c.Project != nil {
		if err := c.Project.validate(); err != nil {
			return fmt.Errorf("project: %w", err)
		}
	}
	return nil
}

func (t Toolchain) validate() error {
	if !languagePattern.MatchString(t.Language) {
		return fmt.Errorf("toolchain.language %q must be a lowercase language identifier", t.Language)
	}
	if !toolchainPattern.MatchString(t.Version) {
		return fmt.Errorf("toolchain.version %q must be a pinned version such as 1.26.6", t.Version)
	}
	return nil
}

func (d Defaults) validate() error {
	if err := validateFamilyList(d.IncludeFamilies, "includeFamilies"); err != nil {
		return err
	}
	return validateFamilyList(d.ExcludeFamilies, "excludeFamilies")
}

func (g Gate) validate() error {
	if !gateNamePattern.MatchString(g.Name) {
		return fmt.Errorf("name %q must be a lowercase gate identifier", g.Name)
	}
	if strings.TrimSpace(g.Command) == "" || strings.ContainsAny(g.Command, "\x00\r\n") {
		return errors.New("command must be a non-empty executable name or path without control characters")
	}
	if len(g.Args) > 64 {
		return fmt.Errorf("args must not contain more than 64 arguments, got %d", len(g.Args))
	}
	for index, argument := range g.Args {
		if strings.ContainsAny(argument, "\x00\r\n") {
			return fmt.Errorf("args[%d] must not contain NUL or line-control characters", index)
		}
	}
	if g.Timeout != "" {
		timeout, err := time.ParseDuration(g.Timeout)
		if err != nil || timeout <= 0 {
			return fmt.Errorf("timeout %q must be a positive Go duration", g.Timeout)
		}
	}
	if err := validateWorkingDirectory(g.WorkingDirectory); err != nil {
		return err
	}
	if err := validateFamilyList(g.IncludeFamilies, "includeFamilies"); err != nil {
		return err
	}
	return validateFamilyList(g.ExcludeFamilies, "excludeFamilies")
}

// validateWorkingDirectory enforces the schema contract: a gate working
// directory is relative to the repository root, never absolute, never
// escaping.
func validateWorkingDirectory(value string) error {
	if value == "" {
		return nil
	}
	if strings.HasPrefix(value, "/") || strings.HasPrefix(value, `\`) || (len(value) > 1 && value[1] == ':') {
		return fmt.Errorf("workingDirectory %q must be relative to the repository root", value)
	}
	cleaned := path.Clean(strings.ReplaceAll(value, `\`, "/"))
	if cleaned == ".." || strings.HasPrefix(cleaned, "../") {
		return fmt.Errorf("workingDirectory %q must not escape the repository root", value)
	}
	return nil
}

func validateFamilyList(value []string, field string) error {
	seen := make(map[string]struct{}, len(value))
	for index, family := range value {
		if !IsFamily(family) {
			return fmt.Errorf("%s[%d] %q is not a quality-gate-config/v4 branch family", field, index, family)
		}
		if _, found := seen[family]; found {
			return fmt.Errorf("%s[%d] %q is not unique", field, index, family)
		}
		seen[family] = struct{}{}
	}
	return nil
}

func (p Project) validate() error {
	if len(p.Binaries) > 32 {
		return fmt.Errorf("binaries must not contain more than 32 entries, got %d", len(p.Binaries))
	}
	seenPackages := make(map[string]struct{}, len(p.Binaries))
	for index, binary := range p.Binaries {
		if !packagePattern.MatchString(binary.Package) {
			return fmt.Errorf("binaries[%d]: package %q must be a repository-relative package path", index, binary.Package)
		}
		if _, found := seenPackages[binary.Package]; found {
			return fmt.Errorf("binaries[%d]: package %q is not unique per document", index, binary.Package)
		}
		seenPackages[binary.Package] = struct{}{}
		if len(binary.Smoke) > 16 {
			return fmt.Errorf("binaries[%d]: smoke must not contain more than 16 arguments, got %d", index, len(binary.Smoke))
		}
		for smokeIndex, argument := range binary.Smoke {
			if strings.ContainsAny(argument, "\x00\r\n") {
				return fmt.Errorf("binaries[%d]: smoke[%d] must not contain NUL or line-control characters", index, smokeIndex)
			}
		}
	}
	if len(p.Fuzz) > 64 {
		return fmt.Errorf("fuzz must not contain more than 64 lanes, got %d", len(p.Fuzz))
	}
	seenLanes := make(map[string]struct{}, len(p.Fuzz))
	for index, lane := range p.Fuzz {
		if !packagePattern.MatchString(lane.Package) {
			return fmt.Errorf("fuzz[%d]: package %q must be a repository-relative package path", index, lane.Package)
		}
		if !fuzzTargetPattern.MatchString(lane.Target) {
			return fmt.Errorf("fuzz[%d]: target %q must be a Fuzz-prefixed Go fuzz target", index, lane.Target)
		}
		if err := validateFuzzTime(lane.Time); err != nil {
			return fmt.Errorf("fuzz[%d]: %w", index, err)
		}
		key := lane.Package + "\x00" + lane.Target
		if _, found := seenLanes[key]; found {
			return fmt.Errorf("fuzz[%d]: package plus target pair %q/%q is not unique per document", index, lane.Package, lane.Target)
		}
		seenLanes[key] = struct{}{}
	}
	return nil
}

// validateFuzzTime accepts a positive Go duration such as 30s or an execution
// count such as 50000x.
func validateFuzzTime(value string) error {
	if value == "" {
		return errors.New("time must not be empty")
	}
	if fuzzCountPattern.MatchString(value) {
		return nil
	}
	duration, err := time.ParseDuration(value)
	if err != nil || duration <= 0 {
		return fmt.Errorf("time %q must be a positive Go duration or an execution count", value)
	}
	return nil
}

// IsFamily reports whether value is a quality-gate-config/v4 branch family.
func IsFamily(value string) bool {
	switch value {
	case FamilyMain, FamilyDevelop, FamilyRelease, FamilySupport,
		FamilyFeature, FamilyFix, FamilyDocs, FamilyRefactor, FamilyChore,
		FamilyTest, FamilyPerf, FamilyHotfix, FamilyScratch:
		return true
	default:
		return false
	}
}
