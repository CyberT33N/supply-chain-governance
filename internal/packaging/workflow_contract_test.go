package packaging

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// bindingManifest mirrors the tenant binding manifest (repo-bindings/v1) for
// the self-consistency proofs of the canonical adoption. The home-side proof
// against the canonical masters is owned by the verify-canonical tool; these
// tests bind the tenant files to the manifest.
type bindingManifest struct {
	Home struct {
		Repository string `json:"repository"`
		SHA        string `json:"sha"`
	} `json:"home"`
	Callers []struct {
		File   string `json:"file"`
		Master string `json:"master"`
		SHA256 string `json:"sha256"`
	} `json:"callers"`
	Files struct {
		Lefthook      fileBinding `json:"lefthook"`
		Gitattributes fileBinding `json:"gitattributes"`
		Gitignore     fileBinding `json:"gitignore"`
		Dependabot    fileBinding `json:"dependabot"`
	} `json:"files"`
	Codeowners struct {
		Path         string `json:"path"`
		DefaultOwner string `json:"defaultOwner"`
	} `json:"codeowners"`
}

type fileBinding struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

func readBindingManifest(t *testing.T) bindingManifest {
	t.Helper()
	var manifest bindingManifest
	if err := json.Unmarshal([]byte(readRepositoryFile(t, "repo-bindings.json")), &manifest); err != nil {
		t.Fatalf("repo-bindings.json is not valid JSON: %v", err)
	}
	if manifest.Home.Repository != "t33n-software/repository-governance" {
		t.Fatalf("the manifest binds home %q", manifest.Home.Repository)
	}
	return manifest
}

// hashRepositoryFile hashes the LF-normalized repository file; the canonical
// .gitattributes makes the checkout LF, and the normalization keeps the
// derivation tolerant as the second line of defense.
func hashRepositoryFile(t *testing.T, path string) string {
	t.Helper()
	normalized := strings.ReplaceAll(readRepositoryFile(t, path), "\r\n", "\n")
	sum := sha256.Sum256([]byte(normalized))
	return hex.EncodeToString(sum[:])
}

func TestCanonicalCallersMatchTheBindingManifest(t *testing.T) {
	manifest := readBindingManifest(t)
	want := map[string]string{
		".github/workflows/ci.yml":                "hosting-platforms/github/workflows/callers/go/ci.yml",
		".github/workflows/codeql.yml":            "hosting-platforms/github/workflows/callers/go/codeql.yml",
		".github/workflows/dependency-review.yml": "hosting-platforms/github/workflows/callers/go/dependency-review.yml",
	}
	if len(manifest.Callers) != len(want) {
		t.Fatalf("the manifest carries %d callers, want %d", len(manifest.Callers), len(want))
	}
	for _, caller := range manifest.Callers {
		master, found := want[caller.File]
		if !found {
			t.Fatalf("the manifest carries an unexpected caller %q", caller.File)
		}
		if caller.Master != master {
			t.Fatalf("caller %q binds master %q, want %q", caller.File, caller.Master, master)
		}
		if hash := hashRepositoryFile(t, caller.File); hash != caller.SHA256 {
			t.Fatalf("the tenant caller %s hashes to %s, want the bound %s", caller.File, hash, caller.SHA256)
		}
		content := readRepositoryFile(t, caller.File)
		if !strings.Contains(content, "uses: "+manifest.Home.Repository+"/.github/workflows/reusable-") {
			t.Fatalf("the tenant caller %s does not reference a home payload", caller.File)
		}
		if !strings.Contains(content, "@"+manifest.Home.SHA) {
			t.Fatalf("the tenant caller %s does not pin the bound home SHA", caller.File)
		}
		if !strings.Contains(content, `branches: [main, develop, "release/**", "support/**"]`) {
			t.Fatalf("the tenant caller %s does not cover every shared line", caller.File)
		}
	}
}

func TestCanonicalFileFamilyMatchesTheBindingManifest(t *testing.T) {
	manifest := readBindingManifest(t)
	for _, topic := range []fileBinding{
		manifest.Files.Lefthook,
		manifest.Files.Gitattributes,
		manifest.Files.Dependabot,
	} {
		if hash := hashRepositoryFile(t, topic.Path); hash != topic.SHA256 {
			t.Fatalf("the canonical file %s hashes to %s, want the bound %s", topic.Path, hash, topic.SHA256)
		}
	}
	// The gitignore topic is prefix-mode in the home verifier: the canonical
	// core is a verbatim prefix and project additions live below the mark.
	gitignore := readRepositoryFile(t, manifest.Files.Gitignore.Path)
	if !strings.HasSuffix(gitignore, "# -- project additions below this line --\n") {
		t.Fatal("the gitignore does not carry the canonical core with the project-block mark")
	}

	codeowners := readRepositoryFile(t, manifest.Codeowners.Path)
	if !strings.Contains(codeowners, "* "+manifest.Codeowners.DefaultOwner) {
		t.Fatalf("the ownership file does not bind the default owner %q", manifest.Codeowners.DefaultOwner)
	}
}

func TestConformanceWorkflowBindsTheVerifier(t *testing.T) {
	manifest := readBindingManifest(t)
	content := readRepositoryFile(t, ".github/workflows/canonical-conformance.yml")
	for _, required := range []string{
		"permissions: {}",
		"name: Canonical conformance",
		"uses: " + manifest.Home.Repository + "/.github/actions/verify-canonical-files@" + manifest.Home.SHA,
		`branches: [main, develop, "release/**", "support/**"]`,
	} {
		if !strings.Contains(content, required) {
			t.Fatalf("the canonical conformance workflow does not contain %q", required)
		}
	}
}

func TestOrganizationRulesetAdoptionHasNoLocalLegacyDefinitions(t *testing.T) {
	if _, err := os.Stat(repositoryPath("docs", "hosting-platforms")); !os.IsNotExist(err) {
		t.Fatalf("legacy ruleset location must not exist")
	}

	conventions := readRepositoryFile(t, filepath.Join("docs", "conventions", "hosting-plattform", "github", "rule-sets", "README.md"))
	for _, required := range []string{
		"git-governance",
		"quality-gates=linux-only",
		"~ALL",
	} {
		if !strings.Contains(conventions, required) {
			t.Fatalf("rule-set conventions README does not contain %q", required)
		}
	}
}

func TestModuleIdentityAndQualityContract(t *testing.T) {
	goMod := readRepositoryFile(t, "go.mod")
	for _, required := range []string{
		"module github.com/t33n-software/supply-chain-governance",
		"go 1.26",
		"toolchain go1.26.6",
	} {
		if !strings.Contains(goMod, required) {
			t.Fatalf("go.mod does not contain %q", required)
		}
	}

	quality := readRepositoryFile(t, "git-governance.quality.json")
	for _, required := range []string{
		"supply-chain-governance-source-quality",
		"./cmd/build",
	} {
		if !strings.Contains(quality, required) {
			t.Fatalf("git-governance.quality.json does not contain %q", required)
		}
	}

	lefthook := readRepositoryFile(t, "lefthook.yml")
	if !strings.Contains(lefthook, "git-governance --interactive never validate pre-push --remote") {
		t.Fatal("lefthook.yml does not bind the canonical pre-push validation")
	}
}

func TestGoToolchainAndBuildToolingContract(t *testing.T) {
	toolsMod := readRepositoryFile(t, filepath.Join("tools", "go.mod"))
	for _, required := range []string{
		"module github.com/t33n-software/supply-chain-governance/tools",
		"toolchain go1.26.6",
		"github.com/evilmartians/lefthook/v2",
		"golang.org/x/vuln/cmd/govulncheck",
		"honnef.co/go/tools/cmd/staticcheck",
		"github.com/t33n-software/go-quality-authority/cmd/quality-gate",
		"github.com/t33n-software/go-quality-authority/cmd/check-coverage",
		"github.com/t33n-software/repository-governance/cmd/verify-canonical",
	} {
		if !strings.Contains(toolsMod, required) {
			t.Fatalf("tools/go.mod does not contain %q", required)
		}
	}
	if _, err := os.Stat(repositoryPath("tools", "go.sum")); err != nil {
		t.Fatalf("tools/go.sum is missing: %v", err)
	}

	manifest := readBindingManifest(t)
	for _, caller := range []string{"ci.yml", "codeql.yml"} {
		content := readRepositoryFile(t, ".github/workflows/"+caller)
		if !strings.Contains(content, "uses: "+manifest.Home.Repository+"/.github/workflows/reusable-") {
			t.Fatalf("the caller %s does not reference a home payload", caller)
		}
	}

	lefthook := readRepositoryFile(t, "lefthook.yml")
	for _, required := range []string{
		"commit-msg:",
		`git-governance --interactive never commit validate --message-file "{1}"`,
		"pre-push:",
		`git-governance --interactive never validate pre-push --remote "{1}"`,
	} {
		if !strings.Contains(lefthook, required) {
			t.Fatalf("lefthook.yml does not contain %q", required)
		}
	}

	traceability := readRepositoryFile(t, filepath.Join("docs", "TRACEABILITY.md"))
	if !strings.Contains(traceability, "SCG-3") {
		t.Fatal("TRACEABILITY.md does not contain SCG-3")
	}
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
		repositoryPath("capabilities", "infrastructure", "opentofu", "conformance", "positive"),
		repositoryPath("capabilities", "infrastructure", "opentofu", "conformance", "negative"),
		repositoryPath("capabilities", "security", "cosign", "conformance", "positive"),
		repositoryPath("capabilities", "security", "cosign", "conformance", "negative"),
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

	for _, descriptor := range []string{
		repositoryPath("capabilities", "infrastructure", "opentofu", "v1", "pack.json"),
		repositoryPath("capabilities", "security", "cosign", "v1", "pack.json"),
	} {
		if _, err := os.Stat(descriptor); err != nil {
			t.Fatalf("missing shipped capability pack descriptor %q: %v", descriptor, err)
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

	packSchema := readRepositoryFile(t, filepath.Join("schemas", "capability-pack", "v1", "capability-pack.schema.json"))
	for _, required := range []string{
		"capability-pack/v1", "provisioning", "recipe", "artifacts", "sha256", "signature",
		"discovery", "fileGlob", "assertions", "gates", "repository", "per-root",
	} {
		if !strings.Contains(packSchema, required) {
			t.Fatalf("capability-pack.schema.json does not contain %q", required)
		}
	}

	configSchema := readRepositoryFile(t, filepath.Join("schemas", "quality-gate-config", "v4", "quality-gate-config.schema.json"))
	for _, required := range []string{
		"quality-gate-config/v4", `"const": 4`, "language", "version", "extends",
		"^[a-z0-9][a-z0-9-]*@[0-9]+$", "gates", "project", "scratch",
	} {
		if !strings.Contains(configSchema, required) {
			t.Fatalf("quality-gate-config.schema.json does not contain %q", required)
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
