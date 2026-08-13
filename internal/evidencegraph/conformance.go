package evidencegraph

import (
	"errors"
	"fmt"
	"io/fs"
	"path"
	"strings"
)

// ParseFunc validates one serialized document and returns an error when the
// document is not conformant.
type ParseFunc func([]byte) error

// RunVectorSet evaluates every JSON vector in a directory. Positive sets must
// validate, negative sets must be rejected. Empty sets fail closed.
func RunVectorSet(fsys fs.FS, directory string, expectValid bool, parse ParseFunc) error {
	if parse == nil {
		return errors.New("conformance parse function must not be nil")
	}
	entries, err := fs.ReadDir(fsys, directory)
	if err != nil {
		return fmt.Errorf("read vector directory %q: %w", directory, err)
	}
	vectors := 0
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		vectors++
		name := path.Join(directory, entry.Name())
		data, err := fs.ReadFile(fsys, name)
		if err != nil {
			return fmt.Errorf("read vector %q: %w", name, err)
		}
		err = parse(data)
		if expectValid && err != nil {
			return fmt.Errorf("positive vector %q must validate: %w", name, err)
		}
		if !expectValid && err == nil {
			return fmt.Errorf("negative vector %q must be rejected", name)
		}
	}
	if vectors == 0 {
		return fmt.Errorf("vector directory %q contains no JSON vectors", directory)
	}
	return nil
}
