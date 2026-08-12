package evidencegraph

import (
	"strings"
	"testing"
)

var (
	testDigestA = strings.Repeat("a", 64)
	testDigestB = strings.Repeat("b", 64)
	testDigestC = strings.Repeat("c", 64)
	testDigestD = strings.Repeat("d", 64)
)

func validDocumentJSON() string {
	return `{
  "schema": "evidence-graph/v1",
  "document": {"id": "doc-1", "type": "subject-document", "issuer": "doc-issuer", "created_at": "2026-08-12T00:00:00Z"},
  "subject": {"id": "sub-1", "type": "artifact", "primary_digest": "sha256:` + testDigestA + `"},
  "relations": [{"type": "produces", "target_subject_id": "sub-0", "target_digest": "sha256:` + testDigestB + `"}],
  "evidence": [{"evidence_type": "sbom", "subject_id": "sub-1", "immutable_reference": "ev-ref-1", "digest": "sha256:` + testDigestD + `", "issuer": "ev-issuer", "issued_at": "2026-08-12T01:00:00Z"}],
  "policy": {"bundle": "bundle-1", "decision": "allow"},
  "lifecycle": {"status": "verified"},
  "integrity": {"canonical_payload_digest": "sha256:` + testDigestB + `", "signature": {"issuer": "sig-issuer", "reference": "sig-ref-1", "digest": "sha256:` + testDigestC + `"}}
}`
}

func mutate(t *testing.T, base string, old string, replacement string) string {
	t.Helper()
	if !strings.Contains(base, old) {
		t.Fatalf("mutation target %q not present in base document", old)
	}
	return strings.Replace(base, old, replacement, 1)
}

func TestParseValidVariants(t *testing.T) {
	base := validDocumentJSON()
	variants := map[string]string{
		"signature proof": base,
		"attestation proof": mutate(t, base,
			`"signature": {"issuer": "sig-issuer"`,
			`"attestation": {"issuer": "sig-issuer"`),
		"approval evidence with expiry": mutate(t, mutate(t, base,
			`"evidence_type": "sbom"`,
			`"evidence_type": "approval"`),
			`"issued_at": "2026-08-12T01:00:00Z"`,
			`"issued_at": "2026-08-12T01:00:00Z", "expires_at": "2027-08-12T01:00:00Z"`),
		"exception evidence with expiry": mutate(t, mutate(t, base,
			`"evidence_type": "sbom"`,
			`"evidence_type": "exception"`),
			`"issued_at": "2026-08-12T01:00:00Z"`,
			`"issued_at": "2026-08-12T01:00:00Z", "expires_at": "2027-01-01T00:00:00Z"`),
		"empty relations and evidence": mutate(t, mutate(t, base,
			`"relations": [{"type": "produces", "target_subject_id": "sub-0", "target_digest": "sha256:`+testDigestB+`"}]`,
			`"relations": []`),
			`"evidence": [{"evidence_type": "sbom", "subject_id": "sub-1", "immutable_reference": "ev-ref-1", "digest": "sha256:`+testDigestD+`", "issuer": "ev-issuer", "issued_at": "2026-08-12T01:00:00Z"}]`,
			`"evidence": []`),
		"target lane and phase references": mutate(t, base,
			`"lifecycle": {"status": "verified"}`,
			`"lifecycle": {"status": "verified", "target_lane": "staging", "phase_references": ["run-1"]}`),
		"deny decision": mutate(t, base,
			`"decision": "allow"`,
			`"decision": "deny"`),
		"not-recorded status": mutate(t, base,
			`"status": "verified"`,
			`"status": "not-recorded"`),
	}
	for name, document := range variants {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse([]byte(document)); err != nil {
				t.Fatalf("Parse() error = %v, want valid document", err)
			}
		})
	}
}

func TestParseRejectsInvalidDocuments(t *testing.T) {
	base := validDocumentJSON()
	cases := map[string]struct {
		document string
		wantErr  string
	}{
		"wrong schema": {
			document: mutate(t, base, `"evidence-graph/v1"`, `"evidence-graph/v9"`),
			wantErr:  "schema must be",
		},
		"empty document id": {
			document: mutate(t, base, `"id": "doc-1"`, `"id": ""`),
			wantErr:  "document.id",
		},
		"empty document type": {
			document: mutate(t, base, `"type": "subject-document"`, `"type": ""`),
			wantErr:  "document.type",
		},
		"empty document issuer": {
			document: mutate(t, base, `"issuer": "doc-issuer"`, `"issuer": ""`),
			wantErr:  "document.issuer",
		},
		"bad created_at": {
			document: mutate(t, base, `"created_at": "2026-08-12T00:00:00Z"`, `"created_at": "soon"`),
			wantErr:  "document.created_at",
		},
		"empty subject id": {
			document: mutate(t, base, `"subject": {"id": "sub-1"`, `"subject": {"id": ""`),
			wantErr:  "subject.id",
		},
		"bad subject type": {
			document: mutate(t, base, `"type": "artifact"`, `"type": "cluster"`),
			wantErr:  "subject.type",
		},
		"bad primary digest": {
			document: mutate(t, base, `"primary_digest": "sha256:`+testDigestA+`"`, `"primary_digest": "sha256:ABC"`),
			wantErr:  "subject.primary_digest",
		},
		"relations missing": {
			document: mutate(t, base,
				`"relations": [{"type": "produces", "target_subject_id": "sub-0", "target_digest": "sha256:`+testDigestB+`"}],`,
				``),
			wantErr: "relations must be present",
		},
		"bad relation type": {
			document: mutate(t, base, `"type": "produces"`, `"type": "depends"`),
			wantErr:  "relations[0]",
		},
		"empty relation target": {
			document: mutate(t, base, `"target_subject_id": "sub-0"`, `"target_subject_id": ""`),
			wantErr:  "relations[0]",
		},
		"bad relation digest": {
			document: mutate(t, base, `"target_digest": "sha256:`+testDigestB+`"`, `"target_digest": "latest"`),
			wantErr:  "relations[0]",
		},
		"evidence missing": {
			document: mutate(t, base,
				`"evidence": [{"evidence_type": "sbom", "subject_id": "sub-1", "immutable_reference": "ev-ref-1", "digest": "sha256:`+testDigestD+`", "issuer": "ev-issuer", "issued_at": "2026-08-12T01:00:00Z"}],`,
				``),
			wantErr: "evidence must be present",
		},
		"bad evidence type": {
			document: mutate(t, base, `"evidence_type": "sbom"`, `"evidence_type": "vibes"`),
			wantErr:  "evidence[0]",
		},
		"empty evidence subject": {
			document: mutate(t, base, `"subject_id": "sub-1"`, `"subject_id": ""`),
			wantErr:  "evidence[0]",
		},
		"foreign evidence subject": {
			document: mutate(t, base, `"subject_id": "sub-1"`, `"subject_id": "sub-9"`),
			wantErr:  "does not match",
		},
		"empty immutable reference": {
			document: mutate(t, base, `"immutable_reference": "ev-ref-1"`, `"immutable_reference": ""`),
			wantErr:  "immutable_reference",
		},
		"bad evidence digest": {
			document: mutate(t, base, `"digest": "sha256:`+testDigestD+`"`, `"digest": "sha256:1"`),
			wantErr:  "evidence[0]",
		},
		"empty evidence issuer": {
			document: mutate(t, base, `"issuer": "ev-issuer"`, `"issuer": ""`),
			wantErr:  "evidence issuer",
		},
		"bad issued_at": {
			document: mutate(t, base, `"issued_at": "2026-08-12T01:00:00Z"`, `"issued_at": "yesterday"`),
			wantErr:  "issued_at must be RFC 3339",
		},
		"expires_at bad format": {
			document: mutate(t, base,
				`"issued_at": "2026-08-12T01:00:00Z"`,
				`"issued_at": "2026-08-12T01:00:00Z", "expires_at": "soon"`),
			wantErr: "expires_at must be RFC 3339",
		},
		"expires_at not after issued_at": {
			document: mutate(t, base,
				`"issued_at": "2026-08-12T01:00:00Z"`,
				`"issued_at": "2026-08-12T01:00:00Z", "expires_at": "2026-08-12T01:00:00Z"`),
			wantErr: "expires_at must be after issued_at",
		},
		"exception without expiry": {
			document: mutate(t, base, `"evidence_type": "sbom"`, `"evidence_type": "exception"`),
			wantErr:  "exception evidence requires expires_at",
		},
		"empty policy bundle": {
			document: mutate(t, base, `"bundle": "bundle-1"`, `"bundle": ""`),
			wantErr:  "policy.bundle",
		},
		"bad policy decision": {
			document: mutate(t, base, `"decision": "allow"`, `"decision": "maybe"`),
			wantErr:  "policy.decision",
		},
		"bad lifecycle status": {
			document: mutate(t, base, `"status": "verified"`, `"status": "approved"`),
			wantErr:  "lifecycle.status",
		},
		"empty phase reference": {
			document: mutate(t, base,
				`"lifecycle": {"status": "verified"}`,
				`"lifecycle": {"status": "verified", "phase_references": [""]}`),
			wantErr: "phase_references[0]",
		},
		"bad canonical digest": {
			document: mutate(t, base,
				`"canonical_payload_digest": "sha256:`+testDigestB+`"`,
				`"canonical_payload_digest": "sha256:zzz"`),
			wantErr: "canonical_payload_digest",
		},
		"both proofs": {
			document: mutate(t, base,
				`"signature": {"issuer": "sig-issuer"`,
				`"attestation": {"issuer": "att-issuer", "reference": "att-ref", "digest": "sha256:`+testDigestC+`"}, "signature": {"issuer": "sig-issuer"`),
			wantErr: "exactly one",
		},
		"no proof": {
			document: mutate(t, base,
				`, "signature": {"issuer": "sig-issuer", "reference": "sig-ref-1", "digest": "sha256:`+testDigestC+`"}`,
				``),
			wantErr: "exactly one",
		},
		"proof empty issuer": {
			document: mutate(t, base, `"issuer": "sig-issuer"`, `"issuer": ""`),
			wantErr:  "proof issuer",
		},
		"proof empty reference": {
			document: mutate(t, base, `"reference": "sig-ref-1"`, `"reference": ""`),
			wantErr:  "proof reference",
		},
		"proof bad digest": {
			document: mutate(t, base, `"digest": "sha256:`+testDigestC+`"`, `"digest": "sha256:q"`),
			wantErr:  "proof digest",
		},
		"unknown field": {
			document: mutate(t, base,
				`"schema": "evidence-graph/v1",`,
				`"schema": "evidence-graph/v1", "unexpected": true,`),
			wantErr: "decode evidence graph document",
		},
		"trailing data": {
			document: base + `{}`,
			wantErr:  "trailing data",
		},
		"forbidden content": {
			document: mutate(t, base, `"ev-ref-1"`, `"-----BEGIN PRIVATE KEY-----"`),
			wantErr:  "forbidden credential-like content",
		},
		"invalid json": {
			document: `{`,
			wantErr:  "decode evidence graph document",
		},
	}
	for name, testCase := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Parse([]byte(testCase.document))
			if err == nil {
				t.Fatalf("Parse() error = nil, want error containing %q", testCase.wantErr)
			}
			if !strings.Contains(err.Error(), testCase.wantErr) {
				t.Fatalf("Parse() error = %q, want substring %q", err.Error(), testCase.wantErr)
			}
		})
	}
}

func TestValidateDocument(t *testing.T) {
	if err := ValidateDocument([]byte(validDocumentJSON())); err != nil {
		t.Fatalf("ValidateDocument() error = %v, want nil", err)
	}
	if err := ValidateDocument([]byte(`{"schema": "nope"}`)); err == nil {
		t.Fatal("ValidateDocument() error = nil, want error")
	}
}

func TestIsSubjectType(t *testing.T) {
	for _, value := range []string{
		"source", "dependency-resolution", "build", "artifact",
		"promotion", "deployment", "operation",
	} {
		if !IsSubjectType(value) {
			t.Errorf("IsSubjectType(%q) = false, want true", value)
		}
	}
	if IsSubjectType("cluster") {
		t.Error("IsSubjectType(cluster) = true, want false")
	}
}

func TestIsRelationType(t *testing.T) {
	for _, value := range []string{
		"resolves", "built-from", "produces", "attests", "promotes",
		"deploys", "revalidates", "revokes", "supersedes", "quarantines",
	} {
		if !IsRelationType(value) {
			t.Errorf("IsRelationType(%q) = false, want true", value)
		}
	}
	if IsRelationType("depends-on") {
		t.Error("IsRelationType(depends-on) = true, want false")
	}
}

func TestIsStatus(t *testing.T) {
	for _, value := range []string{
		"not-recorded", "pending", "verified", "failed",
		"revoked", "quarantined", "superseded",
	} {
		if !IsStatus(value) {
			t.Errorf("IsStatus(%q) = false, want true", value)
		}
	}
	if IsStatus("approved") {
		t.Error("IsStatus(approved) = true, want false")
	}
}

func TestIsEvidenceType(t *testing.T) {
	for _, value := range []string{
		"sbom", "signature", "provenance", "attestation", "test", "scan",
		"approval", "exception", "policy", "quality", "revocation",
	} {
		if !IsEvidenceType(value) {
			t.Errorf("IsEvidenceType(%q) = false, want true", value)
		}
	}
	if IsEvidenceType("vibes") {
		t.Error("IsEvidenceType(vibes) = true, want false")
	}
}

func TestRejectForbiddenContent(t *testing.T) {
	for _, marker := range []string{
		"-----BEGIN PRIVATE KEY-----",
		"PRIVATE KEY",
		"Authorization: Bearer",
		"bearer token",
		"ghp_abc",
		"gho_abc",
		"ghu_abc",
		"ghs_abc",
		"ghr_abc",
		"github_pat_abc",
		"access_token",
		"refresh_token",
		"client_secret",
	} {
		document := `{"note": "` + marker + `"}`
		if err := RejectForbiddenContent([]byte(document)); err == nil {
			t.Errorf("RejectForbiddenContent(%q) = nil, want error", marker)
		}
	}
	if err := RejectForbiddenContent([]byte(`{"note": "nothing sensitive"}`)); err != nil {
		t.Fatalf("RejectForbiddenContent() error = %v, want nil", err)
	}
}
