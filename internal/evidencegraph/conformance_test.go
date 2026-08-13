package evidencegraph

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
)

func validVectorDocument(t *testing.T) []byte {
	t.Helper()
	return []byte(validDocumentJSON())
}

func TestRunVectorSetRejectsNilParse(t *testing.T) {
	err := RunVectorSet(fstest.MapFS{}, "vectors", true, nil)
	if err == nil || !strings.Contains(err.Error(), "parse function") {
		t.Fatalf("RunVectorSet() error = %v, want parse function error", err)
	}
}

func TestRunVectorSetRejectsMissingDirectory(t *testing.T) {
	err := RunVectorSet(fstest.MapFS{}, "missing", true, ValidateDocument)
	if err == nil || !strings.Contains(err.Error(), "read vector directory") {
		t.Fatalf("RunVectorSet() error = %v, want directory error", err)
	}
}

func TestRunVectorSetRejectsEmptyDirectory(t *testing.T) {
	fsys := fstest.MapFS{
		"vectors": &fstest.MapFile{Mode: fs.ModeDir},
	}
	err := RunVectorSet(fsys, "vectors", true, ValidateDocument)
	if err == nil || !strings.Contains(err.Error(), "no JSON vectors") {
		t.Fatalf("RunVectorSet() error = %v, want empty directory error", err)
	}
}

func TestRunVectorSetPositiveSuccess(t *testing.T) {
	fsys := fstest.MapFS{
		"vectors/ok.json": &fstest.MapFile{Data: validVectorDocument(t)},
	}
	if err := RunVectorSet(fsys, "vectors", true, ValidateDocument); err != nil {
		t.Fatalf("RunVectorSet() error = %v, want nil", err)
	}
}

func TestRunVectorSetPositiveFailure(t *testing.T) {
	fsys := fstest.MapFS{
		"vectors/bad.json": &fstest.MapFile{Data: []byte(`{"schema": "nope"}`)},
	}
	err := RunVectorSet(fsys, "vectors", true, ValidateDocument)
	if err == nil || !strings.Contains(err.Error(), "must validate") {
		t.Fatalf("RunVectorSet() error = %v, want positive failure", err)
	}
}

func TestRunVectorSetNegativeSuccess(t *testing.T) {
	fsys := fstest.MapFS{
		"vectors/bad.json": &fstest.MapFile{Data: []byte(`{"schema": "nope"}`)},
	}
	if err := RunVectorSet(fsys, "vectors", false, ValidateDocument); err != nil {
		t.Fatalf("RunVectorSet() error = %v, want nil", err)
	}
}

func TestRunVectorSetNegativeFailure(t *testing.T) {
	fsys := fstest.MapFS{
		"vectors/ok.json": &fstest.MapFile{Data: validVectorDocument(t)},
	}
	err := RunVectorSet(fsys, "vectors", false, ValidateDocument)
	if err == nil || !strings.Contains(err.Error(), "must be rejected") {
		t.Fatalf("RunVectorSet() error = %v, want negative failure", err)
	}
}

func TestRunVectorSetSkipsNonJSONAndSubdirectories(t *testing.T) {
	fsys := fstest.MapFS{
		"vectors/notes.txt":     &fstest.MapFile{Data: []byte("notes")},
		"vectors/nested":        &fstest.MapFile{Mode: fs.ModeDir},
		"vectors/ok.json":       &fstest.MapFile{Data: validVectorDocument(t)},
		"vectors/nested/x.json": &fstest.MapFile{Data: []byte(`{"schema": "nope"}`)},
	}
	if err := RunVectorSet(fsys, "vectors", true, ValidateDocument); err != nil {
		t.Fatalf("RunVectorSet() error = %v, want nil", err)
	}
}

type readFailFS struct {
	fs.FS
}

func (f readFailFS) Open(name string) (fs.File, error) {
	if strings.HasSuffix(name, ".json") {
		return nil, errors.New("read failure")
	}
	return f.FS.Open(name)
}

func TestRunVectorSetPropagatesReadErrors(t *testing.T) {
	base := fstest.MapFS{
		"vectors/bad.json": &fstest.MapFile{Data: []byte(`{"schema": "nope"}`)},
	}
	err := RunVectorSet(readFailFS{FS: base}, "vectors", true, ValidateDocument)
	if err == nil || !strings.Contains(err.Error(), "read vector") {
		t.Fatalf("RunVectorSet() error = %v, want read error", err)
	}
}

func TestRepositoryEvidenceGraphVectorsConform(t *testing.T) {
	root := os.DirFS(filepath.Join("..", ".."))
	if err := RunVectorSet(root, "schemas/evidence-graph/conformance/positive", true, ValidateDocument); err != nil {
		t.Fatalf("positive repository vectors: %v", err)
	}
	if err := RunVectorSet(root, "schemas/evidence-graph/conformance/negative", false, ValidateDocument); err != nil {
		t.Fatalf("negative repository vectors: %v", err)
	}
}
