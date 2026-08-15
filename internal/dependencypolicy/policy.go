// Package dependencypolicy implements the dependency-policy/v1 document
// format used by the supply chain governance core.
package dependencypolicy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/t33n-software/supply-chain-governance/internal/evidencegraph"
)

// SchemaID is the canonical dependency policy schema identifier.
const SchemaID = "dependency-policy/v1"

// Ecosystems supported by dependency-policy/v1. The npm identifier denotes
// the npm dependency protocol; builder and runtime authorities are separate
// boundaries.
const (
	EcosystemGo     = "go"
	EcosystemNPM    = "npm"
	EcosystemPython = "python"
)

// Policy is a versioned dependency admission and revocation policy.
type Policy struct {
	Schema     string      `json:"schema"`
	Ecosystem  string      `json:"ecosystem"`
	Admission  Admission   `json:"admission"`
	Exceptions []Exception `json:"exceptions"`
	Revocation Revocation  `json:"revocation"`
}

// Admission describes the evidence a dependency must present before it may be
// promoted into an approved zone.
type Admission struct {
	RequiredEvidence []string `json:"required_evidence"`
	MaxCVSS          *float64 `json:"max_cvss,omitempty"`
	BlockedLicenses  []string `json:"blocked_licenses,omitempty"`
}

// Exception is a time-bounded policy exception reference.
type Exception struct {
	Reference string `json:"reference"`
	ExpiresAt string `json:"expires_at"`
}

// Revocation describes the active download block behaviour for revoked or
// quarantined dependencies.
type Revocation struct {
	DownloadBlock bool `json:"download_block"`
}

// Parse decodes and validates one dependency-policy/v1 document. Unknown
// fields, trailing data, and credential-like content are rejected fail-closed.
func Parse(data []byte) (Policy, error) {
	var policy Policy
	if err := evidencegraph.RejectForbiddenContent(data); err != nil {
		return policy, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&policy); err != nil {
		return policy, fmt.Errorf("decode dependency policy: %w", err)
	}
	if decoder.More() {
		return policy, errors.New("dependency policy contains trailing data")
	}
	if err := policy.Validate(); err != nil {
		return policy, err
	}
	return policy, nil
}

// ValidatePolicy parses and validates one dependency-policy/v1 document.
func ValidatePolicy(data []byte) error {
	_, err := Parse(data)
	return err
}

// Validate enforces every dependency-policy/v1 invariant.
func (p Policy) Validate() error {
	if p.Schema != SchemaID {
		return fmt.Errorf("schema must be %q, got %q", SchemaID, p.Schema)
	}
	switch p.Ecosystem {
	case EcosystemGo, EcosystemNPM, EcosystemPython:
	default:
		return fmt.Errorf("ecosystem %q is not supported", p.Ecosystem)
	}
	if err := p.Admission.validate(); err != nil {
		return err
	}
	if p.Exceptions == nil {
		return errors.New("exceptions must be present and may be empty")
	}
	for index, exception := range p.Exceptions {
		if err := exception.validate(); err != nil {
			return fmt.Errorf("exceptions[%d]: %w", index, err)
		}
	}
	return p.Revocation.validate()
}

func (a Admission) validate() error {
	if len(a.RequiredEvidence) == 0 {
		return errors.New("admission.required_evidence must not be empty")
	}
	for index, evidenceType := range a.RequiredEvidence {
		if !evidencegraph.IsEvidenceType(evidenceType) {
			return fmt.Errorf("admission.required_evidence[%d] %q is not an evidence-graph/v1 evidence type", index, evidenceType)
		}
	}
	if a.MaxCVSS != nil && (*a.MaxCVSS < 0 || *a.MaxCVSS > 10) {
		return errors.New("admission.max_cvss must be between 0 and 10")
	}
	for index, license := range a.BlockedLicenses {
		if license == "" {
			return fmt.Errorf("admission.blocked_licenses[%d] must not be empty", index)
		}
	}
	return nil
}

func (e Exception) validate() error {
	if e.Reference == "" {
		return errors.New("exception reference must not be empty")
	}
	if _, err := time.Parse(time.RFC3339, e.ExpiresAt); err != nil {
		return fmt.Errorf("exception expires_at must be RFC 3339: %w", err)
	}
	return nil
}

func (r Revocation) validate() error {
	if !r.DownloadBlock {
		return errors.New("revocation.download_block must be true so revoked dependencies are blocked before download")
	}
	return nil
}
