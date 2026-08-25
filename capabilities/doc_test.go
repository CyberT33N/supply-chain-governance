package capabilities

import "testing"

// TestAnchorPackageIsImportable pins the presence of the registry anchor
// package under the kernel's per-package test-presence gate. The anchor
// carries no behavior; compiling and running this test proves the package
// exists and remains importable for tenant blank imports.
func TestAnchorPackageIsImportable(t *testing.T) {
	t.Parallel()
}
