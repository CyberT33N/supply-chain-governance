// Package evidencegraph implements the canonical evidence-graph/v1 document
// envelope, its validation rules, and the shared conformance vector runner.
package evidencegraph

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"time"
)

// SchemaID is the canonical schema identifier every evidence graph document
// must declare.
const SchemaID = "evidence-graph/v1"

// Subject types defined by evidence-graph/v1.
const (
	SubjectSource               = "source"
	SubjectDependencyResolution = "dependency-resolution"
	SubjectBuild                = "build"
	SubjectArtifact             = "artifact"
	SubjectPromotion            = "promotion"
	SubjectDeployment           = "deployment"
	SubjectOperation            = "operation"
)

// Relation types defined by evidence-graph/v1.
const (
	RelationResolves    = "resolves"
	RelationBuiltFrom   = "built-from"
	RelationProduces    = "produces"
	RelationAttests     = "attests"
	RelationPromotes    = "promotes"
	RelationDeploys     = "deploys"
	RelationRevalidates = "revalidates"
	RelationRevokes     = "revokes"
	RelationSupersedes  = "supersedes"
	RelationQuarantines = "quarantines"
)

// Lifecycle status values defined by evidence-graph/v1.
const (
	StatusNotRecorded = "not-recorded"
	StatusPending     = "pending"
	StatusVerified    = "verified"
	StatusFailed      = "failed"
	StatusRevoked     = "revoked"
	StatusQuarantined = "quarantined"
	StatusSuperseded  = "superseded"
)

// Evidence types defined by evidence-graph/v1.
const (
	EvidenceSBOM        = "sbom"
	EvidenceSignature   = "signature"
	EvidenceProvenance  = "provenance"
	EvidenceAttestation = "attestation"
	EvidenceTest        = "test"
	EvidenceScan        = "scan"
	EvidenceApproval    = "approval"
	EvidenceException   = "exception"
	EvidencePolicy      = "policy"
	EvidenceQuality     = "quality"
	EvidenceRevocation  = "revocation"
)

// Policy decisions defined by evidence-graph/v1.
const (
	DecisionAllow = "allow"
	DecisionDeny  = "deny"
)

var digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// Document is the canonical evidence-graph/v1 subject document envelope.
type Document struct {
	Schema    string     `json:"schema"`
	Document  Metadata   `json:"document"`
	Subject   Subject    `json:"subject"`
	Relations []Relation `json:"relations"`
	Evidence  []Evidence `json:"evidence"`
	Policy    Policy     `json:"policy"`
	Lifecycle Lifecycle  `json:"lifecycle"`
	Integrity Integrity  `json:"integrity"`
}

// Metadata describes the immutable document identity.
type Metadata struct {
	ID        string `json:"id"`
	Type      string `json:"type"`
	Issuer    string `json:"issuer"`
	CreatedAt string `json:"created_at"`
}

// Subject identifies the immutable subject the document records.
type Subject struct {
	ID            string `json:"id"`
	Type          string `json:"type"`
	PrimaryDigest string `json:"primary_digest"`
}

// Relation is a directed typed edge to another subject.
type Relation struct {
	Type            string `json:"type"`
	TargetSubjectID string `json:"target_subject_id"`
	TargetDigest    string `json:"target_digest,omitempty"`
}

// Evidence references one immutable evidence object bound to the subject.
type Evidence struct {
	EvidenceType       string `json:"evidence_type"`
	SubjectID          string `json:"subject_id"`
	ImmutableReference string `json:"immutable_reference"`
	Digest             string `json:"digest"`
	Issuer             string `json:"issuer"`
	IssuedAt           string `json:"issued_at"`
	ExpiresAt          string `json:"expires_at,omitempty"`
}

// Policy binds the policy bundle decision to the subject.
type Policy struct {
	Bundle    string `json:"bundle"`
	Decision  string `json:"decision"`
	Exception string `json:"exception,omitempty"`
	Approval  string `json:"approval,omitempty"`
}

// Lifecycle records the subject status and lane binding.
type Lifecycle struct {
	Status          string   `json:"status"`
	TargetLane      string   `json:"target_lane,omitempty"`
	PhaseReferences []string `json:"phase_references,omitempty"`
}

// Integrity binds the canonical payload digest to exactly one signature or
// attestation over that digest.
type Integrity struct {
	CanonicalPayloadDigest string       `json:"canonical_payload_digest"`
	Signature              *CryptoProof `json:"signature,omitempty"`
	Attestation            *CryptoProof `json:"attestation,omitempty"`
}

// CryptoProof is a signature or attestation over the canonical payload
// digest.
type CryptoProof struct {
	Issuer    string `json:"issuer"`
	Reference string `json:"reference"`
	Digest    string `json:"digest"`
}

// Parse decodes and validates one evidence-graph/v1 document. Unknown fields,
// trailing data, and credential-like content are rejected fail-closed.
func Parse(data []byte) (Document, error) {
	var document Document
	if err := RejectForbiddenContent(data); err != nil {
		return document, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&document); err != nil {
		return document, fmt.Errorf("decode evidence graph document: %w", err)
	}
	if decoder.More() {
		return document, errors.New("evidence graph document contains trailing data")
	}
	if err := document.Validate(); err != nil {
		return document, err
	}
	return document, nil
}

// ValidateDocument parses and validates one evidence-graph/v1 document.
func ValidateDocument(data []byte) error {
	_, err := Parse(data)
	return err
}

// Validate enforces every evidence-graph/v1 envelope invariant.
func (d Document) Validate() error {
	if d.Schema != SchemaID {
		return fmt.Errorf("schema must be %q, got %q", SchemaID, d.Schema)
	}
	if err := d.Document.validate(); err != nil {
		return err
	}
	if err := d.Subject.validate(); err != nil {
		return err
	}
	if d.Relations == nil {
		return errors.New("relations must be present and may be empty")
	}
	for index, relation := range d.Relations {
		if err := relation.validate(); err != nil {
			return fmt.Errorf("relations[%d]: %w", index, err)
		}
	}
	if d.Evidence == nil {
		return errors.New("evidence must be present and may be empty")
	}
	for index, evidence := range d.Evidence {
		if err := evidence.validate(d.Subject.ID); err != nil {
			return fmt.Errorf("evidence[%d]: %w", index, err)
		}
	}
	if err := d.Policy.validate(); err != nil {
		return err
	}
	if err := d.Lifecycle.validate(); err != nil {
		return err
	}
	return d.Integrity.validate()
}

func (m Metadata) validate() error {
	if m.ID == "" {
		return errors.New("document.id must not be empty")
	}
	if m.Type == "" {
		return errors.New("document.type must not be empty")
	}
	if m.Issuer == "" {
		return errors.New("document.issuer must not be empty")
	}
	if _, err := time.Parse(time.RFC3339, m.CreatedAt); err != nil {
		return fmt.Errorf("document.created_at must be RFC 3339: %w", err)
	}
	return nil
}

func (s Subject) validate() error {
	if s.ID == "" {
		return errors.New("subject.id must not be empty")
	}
	if !IsSubjectType(s.Type) {
		return fmt.Errorf("subject.type %q is not an evidence-graph/v1 subject type", s.Type)
	}
	if !digestPattern.MatchString(s.PrimaryDigest) {
		return errors.New("subject.primary_digest must be sha256:<64 lowercase hex>")
	}
	return nil
}

func (r Relation) validate() error {
	if !IsRelationType(r.Type) {
		return fmt.Errorf("relation type %q is not an evidence-graph/v1 relation type", r.Type)
	}
	if r.TargetSubjectID == "" {
		return errors.New("relation target_subject_id must not be empty")
	}
	if r.TargetDigest != "" && !digestPattern.MatchString(r.TargetDigest) {
		return errors.New("relation target_digest must be sha256:<64 lowercase hex>")
	}
	return nil
}

func (e Evidence) validate(subjectID string) error {
	if !IsEvidenceType(e.EvidenceType) {
		return fmt.Errorf("evidence type %q is not an evidence-graph/v1 evidence type", e.EvidenceType)
	}
	if e.SubjectID == "" {
		return errors.New("evidence subject_id must not be empty")
	}
	if e.SubjectID != subjectID {
		return fmt.Errorf("evidence subject_id %q does not match document subject %q", e.SubjectID, subjectID)
	}
	if e.ImmutableReference == "" {
		return errors.New("evidence immutable_reference must not be empty")
	}
	if !digestPattern.MatchString(e.Digest) {
		return errors.New("evidence digest must be sha256:<64 lowercase hex>")
	}
	if e.Issuer == "" {
		return errors.New("evidence issuer must not be empty")
	}
	issuedAt, err := time.Parse(time.RFC3339, e.IssuedAt)
	if err != nil {
		return fmt.Errorf("evidence issued_at must be RFC 3339: %w", err)
	}
	if e.ExpiresAt != "" {
		expiresAt, err := time.Parse(time.RFC3339, e.ExpiresAt)
		if err != nil {
			return fmt.Errorf("evidence expires_at must be RFC 3339: %w", err)
		}
		if !expiresAt.After(issuedAt) {
			return errors.New("evidence expires_at must be after issued_at")
		}
	}
	if e.EvidenceType == EvidenceException && e.ExpiresAt == "" {
		return errors.New("exception evidence requires expires_at")
	}
	return nil
}

func (p Policy) validate() error {
	if p.Bundle == "" {
		return errors.New("policy.bundle must not be empty")
	}
	if p.Decision != DecisionAllow && p.Decision != DecisionDeny {
		return fmt.Errorf("policy.decision must be %q or %q", DecisionAllow, DecisionDeny)
	}
	return nil
}

func (l Lifecycle) validate() error {
	if !IsStatus(l.Status) {
		return fmt.Errorf("lifecycle.status %q is not an evidence-graph/v1 status", l.Status)
	}
	for index, reference := range l.PhaseReferences {
		if reference == "" {
			return fmt.Errorf("lifecycle.phase_references[%d] must not be empty", index)
		}
	}
	return nil
}

func (i Integrity) validate() error {
	if !digestPattern.MatchString(i.CanonicalPayloadDigest) {
		return errors.New("integrity.canonical_payload_digest must be sha256:<64 lowercase hex>")
	}
	hasSignature := i.Signature != nil
	hasAttestation := i.Attestation != nil
	if hasSignature == hasAttestation {
		return errors.New("integrity requires exactly one of signature or attestation")
	}
	proof := i.Signature
	if proof == nil {
		proof = i.Attestation
	}
	return proof.validate()
}

func (p CryptoProof) validate() error {
	if p.Issuer == "" {
		return errors.New("integrity proof issuer must not be empty")
	}
	if p.Reference == "" {
		return errors.New("integrity proof reference must not be empty")
	}
	if !digestPattern.MatchString(p.Digest) {
		return errors.New("integrity proof digest must be sha256:<64 lowercase hex>")
	}
	return nil
}

// IsSubjectType reports whether value is an evidence-graph/v1 subject type.
func IsSubjectType(value string) bool {
	switch value {
	case SubjectSource, SubjectDependencyResolution, SubjectBuild, SubjectArtifact,
		SubjectPromotion, SubjectDeployment, SubjectOperation:
		return true
	default:
		return false
	}
}

// IsRelationType reports whether value is an evidence-graph/v1 relation type.
func IsRelationType(value string) bool {
	switch value {
	case RelationResolves, RelationBuiltFrom, RelationProduces, RelationAttests,
		RelationPromotes, RelationDeploys, RelationRevalidates, RelationRevokes,
		RelationSupersedes, RelationQuarantines:
		return true
	default:
		return false
	}
}

// IsStatus reports whether value is an evidence-graph/v1 lifecycle status.
func IsStatus(value string) bool {
	switch value {
	case StatusNotRecorded, StatusPending, StatusVerified, StatusFailed,
		StatusRevoked, StatusQuarantined, StatusSuperseded:
		return true
	default:
		return false
	}
}

// IsEvidenceType reports whether value is an evidence-graph/v1 evidence type.
func IsEvidenceType(value string) bool {
	switch value {
	case EvidenceSBOM, EvidenceSignature, EvidenceProvenance, EvidenceAttestation,
		EvidenceTest, EvidenceScan, EvidenceApproval, EvidenceException,
		EvidencePolicy, EvidenceQuality, EvidenceRevocation:
		return true
	default:
		return false
	}
}

var forbiddenContentMarkers = []string{
	"-----begin",
	"private key",
	"authorization:",
	"bearer ",
	"ghp_",
	"gho_",
	"ghu_",
	"ghs_",
	"ghr_",
	"github_pat_",
	"access_token",
	"refresh_token",
	"client_secret",
}

// RejectForbiddenContent fails when a document contains credential-like
// content. Evidence graph documents must never carry secrets, tokens, private
// keys, authorization headers, or volatile log fragments.
func RejectForbiddenContent(data []byte) error {
	lowered := bytes.ToLower(data)
	for _, marker := range forbiddenContentMarkers {
		if bytes.Contains(lowered, []byte(marker)) {
			return fmt.Errorf("document contains forbidden credential-like content marker %q", marker)
		}
	}
	return nil
}
