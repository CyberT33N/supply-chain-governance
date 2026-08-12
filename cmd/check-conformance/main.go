// Command check-conformance runs every conformance vector set and validates
// the shipped dependency policies.
package main

import (
	"fmt"
	"io"
	"io/fs"
	"os"

	"github.com/CyberT33N/supply-chain-governance/internal/dependencypolicy"
	"github.com/CyberT33N/supply-chain-governance/internal/evidencegraph"
)

var (
	exitProcess = os.Exit
	commandArgs = os.Args
	vectorRoot  = "."
)

func main() {
	exitProcess(run(commandArgs[1:], vectorRoot, os.Stdout, os.Stderr))
}

type vectorSet struct {
	name        string
	directory   string
	expectValid bool
	parse       evidencegraph.ParseFunc
}

func conformanceSets() []vectorSet {
	return []vectorSet{
		{
			name:        "evidence-graph positive vectors",
			directory:   "schemas/evidence-graph/conformance/positive",
			expectValid: true,
			parse:       evidencegraph.ValidateDocument,
		},
		{
			name:        "evidence-graph negative vectors",
			directory:   "schemas/evidence-graph/conformance/negative",
			expectValid: false,
			parse:       evidencegraph.ValidateDocument,
		},
		{
			name:        "dependency-policy positive vectors",
			directory:   "conformance/positive",
			expectValid: true,
			parse:       dependencypolicy.ValidatePolicy,
		},
		{
			name:        "dependency-policy negative vectors",
			directory:   "conformance/negative",
			expectValid: false,
			parse:       dependencypolicy.ValidatePolicy,
		},
	}
}

func shippedPolicyEcosystems() []string {
	return []string{"go", "npm", "python"}
}

func run(arguments []string, root string, stdout io.Writer, stderr io.Writer) int {
	if len(arguments) != 0 {
		fmt.Fprintln(stderr, "usage: check-conformance")
		return 2
	}
	fsys := os.DirFS(root)
	for _, set := range conformanceSets() {
		fmt.Fprintln(stdout, "==>", set.name)
		if err := evidencegraph.RunVectorSet(fsys, set.directory, set.expectValid, set.parse); err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
	}
	for _, ecosystem := range shippedPolicyEcosystems() {
		name := "policies/dependency/" + ecosystem + "/policy.json"
		fmt.Fprintln(stdout, "==> shipped policy", name)
		data, err := fs.ReadFile(fsys, name)
		if err != nil {
			fmt.Fprintf(stderr, "read shipped policy %q: %v\n", name, err)
			return 1
		}
		if err := dependencypolicy.ValidatePolicy(data); err != nil {
			fmt.Fprintf(stderr, "shipped policy %q is not conformant: %v\n", name, err)
			return 1
		}
	}
	fmt.Fprintln(stdout, "All conformance vectors and shipped policies are conformant.")
	return 0
}
