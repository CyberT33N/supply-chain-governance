package packaging

import (
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

func TestSourceWorkflowsEmitOnlyEstablishedSharedLineChecks(t *testing.T) {
	for _, workflow := range []string{
		".github/workflows/ci.yml",
		".github/workflows/codeql.yml",
		".github/workflows/dependency-review.yml",
	} {
		content := readRepositoryFile(t, workflow)
		for _, forbidden := range []string{"release/**", "support/**"} {
			if strings.Contains(content, forbidden) {
				t.Fatalf("%s unexpectedly targets %q before the governed release lifecycle exists", workflow, forbidden)
			}
		}
		for _, required := range []string{"main", "develop"} {
			if !strings.Contains(content, required) {
				t.Fatalf("%s does not target %q", workflow, required)
			}
		}
	}

	ci := readRepositoryFile(t, ".github/workflows/ci.yml")
	for _, required := range []string{
		"Quality gates (linux-amd64)",
		"go run -mod=readonly ./cmd/build",
		"actions/checkout@9f698171ed81b15d1823a05fc7211befd50c8ae0",
		"actions/setup-go@4a3601121dd01d1626a1e23e37211e3254c1c06c",
	} {
		if !strings.Contains(ci, required) {
			t.Fatalf("CI workflow does not contain %q", required)
		}
	}

	dependencyReview := readRepositoryFile(t, ".github/workflows/dependency-review.yml")
	for _, required := range []string{
		"Dependency admission review",
		"fail-on-severity: low",
		"fail-on-scopes: runtime,development,unknown",
		"actions/dependency-review-action@2031cfc080254a8a887f58cffee85186f0e49e48",
	} {
		if !strings.Contains(dependencyReview, required) {
			t.Fatalf("dependency review workflow does not contain %q", required)
		}
	}
}

func TestRulesetSourcesMatchTheGovernedSet(t *testing.T) {
	rulesetDirectory := repositoryPath("docs", "hosting-platforms", "github", "rulesets")
	entries, err := os.ReadDir(rulesetDirectory)
	if err != nil {
		t.Fatalf("ReadDir(%q) error = %v", rulesetDirectory, err)
	}

	jsonNames := make([]string, 0)
	for _, entry := range entries {
		if filepath.Ext(entry.Name()) == ".json" {
			jsonNames = append(jsonNames, entry.Name())
		}
	}
	sort.Strings(jsonNames)
	wantNames := []string{
		"00-push-protections.json",
		"01-ticket-working-branches.json",
		"02-develop.json",
		"03-main.json",
	}
	if !reflect.DeepEqual(jsonNames, wantNames) {
		t.Fatalf("ruleset JSON files = %#v, want %#v", jsonNames, wantNames)
	}

	for _, name := range jsonNames {
		content := readRepositoryFile(t, filepath.Join("docs", "hosting-platforms", "github", "rulesets", name))
		for _, forbidden := range []string{"code_quality", "code_coverage"} {
			if strings.Contains(content, forbidden) {
				t.Fatalf("%s contains unsupported %q", name, forbidden)
			}
		}
		if !strings.Contains(content, "\"bypass_actors\": []") {
			t.Fatalf("%s does not prohibit Ruleset bypass actors", name)
		}
	}

	readme := readRepositoryFile(t, filepath.Join("docs", "hosting-platforms", "github", "rulesets", "README.md"))
	for _, required := range []string{
		"Do not import a `release/*` or `support/*` Ruleset yet.",
		"Quality gates (linux-amd64)",
		"Dependency admission review",
	} {
		if !strings.Contains(readme, required) {
			t.Fatalf("Ruleset README does not contain %q", required)
		}
	}
}

func TestPushProtectionsRulesetBlocksCredentialShapedArtifacts(t *testing.T) {
	push := readRepositoryFile(t, filepath.Join("docs", "hosting-platforms", "github", "rulesets", "00-push-protections.json"))
	for _, required := range []string{
		"\"name\": \"push-protections: block secret and key shaped artifacts\"",
		"\"target\": \"push\"",
		"\"source\": \"t33n-software/supply-chain-governance\"",
		"\"enforcement\": \"active\"",
		"\"conditions\": null",
		"\"bypass_actors\": []",
		"file_extension_restriction",
		"restricted_file_extensions",
		"file_path_restriction",
		"restricted_file_paths",
	} {
		if !strings.Contains(push, required) {
			t.Fatalf("00-push-protections.json does not contain %q", required)
		}
	}
	for _, extension := range []string{"pem", "key", "p12", "pfx", "jks", "keystore", "kdbx", "ppk", "gpg"} {
		if !strings.Contains(push, "\"*."+extension+"\"") {
			t.Fatalf("00-push-protections.json does not restrict the %q extension in glob form", extension)
		}
	}
	for _, path := range []string{"**/.env", "**/.env.*", "**/credentials", "**/credentials.*", "**/*.tfstate", "**/*.tfstate.*"} {
		if !strings.Contains(push, "\""+path+"\"") {
			t.Fatalf("00-push-protections.json does not restrict the %q path", path)
		}
	}
	for _, forbidden := range []string{"ref_name", "required_status_checks", "code_scanning", "code_quality", "code_coverage"} {
		if strings.Contains(push, forbidden) {
			t.Fatalf("00-push-protections.json unexpectedly contains %q; a push ruleset has no branch targets or check bindings", forbidden)
		}
	}

	readme := normalizeWhitespace(readRepositoryFile(t, filepath.Join("docs", "hosting-platforms", "github", "rulesets", "README.md")))
	for _, required := range []string{"00-push-protections.json", "fork network", "Team plan", "public"} {
		if !strings.Contains(readme, required) {
			t.Fatalf("Ruleset README does not document the push protections token %q", required)
		}
	}
}

func normalizeWhitespace(content string) string {
	return strings.Join(strings.Fields(content), " ")
}

func TestGovernanceDocumentationPreservesCoreInstanceAndTenantBoundaries(t *testing.T) {
	for _, path := range []string{
		"README.md",
		"docs/architecture/ADR-0001-SUPPLY-CHAIN-GOVERNANCE.md",
		"docs/development/VERIFICATION.md",
	} {
		content := strings.ToLower(readRepositoryFile(t, path))
		for _, required := range []string{"core", "instance", "tenant"} {
			if !strings.Contains(content, required) {
				t.Fatalf("%s does not document %q boundary", path, required)
			}
		}
	}

	adr := readRepositoryFile(t, "docs/architecture/ADR-0001-SUPPLY-CHAIN-GOVERNANCE.md")
	for _, required := range []string{
		"never contains concrete organization",
		"never contains tenant",
		"evidence-graph/v1",
	} {
		if !strings.Contains(adr, required) {
			t.Fatalf("ADR does not contain %q", required)
		}
	}
}

func TestConformanceVectorsAndShippedPoliciesArePresent(t *testing.T) {
	positiveDirectory := repositoryPath("schemas", "evidence-graph", "conformance", "positive")
	for _, name := range []string{
		"source.subject.json",
		"dependency-resolution.subject.json",
		"build.subject.json",
		"artifact.subject.json",
		"promotion.subject.json",
		"deployment.subject.json",
		"operation.subject.json",
	} {
		if _, err := os.Stat(filepath.Join(positiveDirectory, name)); err != nil {
			t.Fatalf("missing positive vector %q: %v", name, err)
		}
	}

	for _, directory := range []string{
		repositoryPath("schemas", "evidence-graph", "conformance", "negative"),
		repositoryPath("conformance", "positive"),
		repositoryPath("conformance", "negative"),
	} {
		entries, err := os.ReadDir(directory)
		if err != nil {
			t.Fatalf("ReadDir(%q) error = %v", directory, err)
		}
		if len(entries) == 0 {
			t.Fatalf("vector directory %q is empty", directory)
		}
	}

	for _, ecosystem := range []string{"go", "npm", "python"} {
		policyPath := repositoryPath("policies", "dependency", ecosystem, "policy.json")
		if _, err := os.Stat(policyPath); err != nil {
			t.Fatalf("missing shipped policy %q: %v", policyPath, err)
		}
	}
}

func TestJSONSchemasStayInSyncWithValidators(t *testing.T) {
	documentSchema := readRepositoryFile(t, filepath.Join("schemas", "evidence-graph", "v1", "document.schema.json"))
	for _, required := range []string{
		"evidence-graph/v1",
		"source", "dependency-resolution", "build", "artifact", "promotion", "deployment", "operation",
		"resolves", "built-from", "produces", "attests", "promotes", "deploys", "revalidates", "revokes", "supersedes", "quarantines",
		"not-recorded", "pending", "verified", "failed", "revoked", "quarantined", "superseded",
		"sbom", "signature", "provenance", "attestation", "test", "scan", "approval", "exception", "policy", "quality", "revocation",
		"sha256:",
	} {
		if !strings.Contains(documentSchema, required) {
			t.Fatalf("document.schema.json does not contain %q", required)
		}
	}

	policySchema := readRepositoryFile(t, filepath.Join("schemas", "dependency-policy", "v1", "policy.schema.json"))
	for _, required := range []string{
		"dependency-policy/v1", "go", "npm", "python", "required_evidence", "download_block",
	} {
		if !strings.Contains(policySchema, required) {
			t.Fatalf("policy.schema.json does not contain %q", required)
		}
	}
}

func readRepositoryFile(t *testing.T, path string) string {
	t.Helper()
	content, err := os.ReadFile(repositoryPath(filepath.FromSlash(path)))
	if err != nil {
		t.Fatalf("ReadFile(%q) error = %v", path, err)
	}
	return string(content)
}

func repositoryPath(parts ...string) string {
	return filepath.Join(append([]string{"..", ".."}, parts...)...)
}
