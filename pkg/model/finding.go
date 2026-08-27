package model

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"
)

// Finding represents the normalized, cross-scanner security finding model for Pentol.
type Finding struct {
	ID          string            `json:"id"`
	Title       string            `json:"title"`
	Severity    Severity          `json:"severity"`
	Target      string            `json:"target"`
	Endpoint    string            `json:"endpoint"`
	Description string            `json:"description"`
	Evidence    string            `json:"evidence"`
	Impact      string            `json:"impact"`
	Remediation string            `json:"remediation"`
	References  []string          `json:"references"`
	Scanner     string            `json:"scanner"`
	Status      FindingStatus     `json:"status"`
	Timestamp   time.Time         `json:"timestamp"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

// GenerateFindingID generates a deterministic, unique finding ID based on scanner, target, endpoint, and title.
func GenerateFindingID(scanner, target, endpoint, title string) string {
	raw := fmt.Sprintf("%s|%s|%s|%s", scanner, target, endpoint, title)
	hash := sha256.Sum256([]byte(raw))
	return fmt.Sprintf("PENTOL-%s", hex.EncodeToString(hash[:6]))
}

// NewFinding initializes a new normalized Finding with default OPEN status and deterministic ID.
func NewFinding(scanner, title string, severity Severity, target, endpoint, desc, evidence, impact, remediation string, references []string) *Finding {
	if references == nil {
		references = make([]string, 0)
	}
	id := GenerateFindingID(scanner, target, endpoint, title)
	return &Finding{
		ID:          id,
		Title:       title,
		Severity:    severity,
		Target:      target,
		Endpoint:    endpoint,
		Description: desc,
		Evidence:    evidence,
		Impact:      impact,
		Remediation: remediation,
		References:  references,
		Scanner:     scanner,
		Status:      StatusOpen,
		Timestamp:   time.Now().UTC(),
		Metadata:    make(map[string]string),
	}
}

// Validate validates that the finding satisfies all normalized minimum schema requirements.
func (f *Finding) Validate() error {
	if f.ID == "" {
		return fmt.Errorf("finding ID is required")
	}
	if f.Title == "" {
		return fmt.Errorf("finding Title is required")
	}
	if _, err := ParseSeverity(string(f.Severity)); err != nil {
		return fmt.Errorf("invalid severity in finding %s: %w", f.ID, err)
	}
	if f.Target == "" {
		return fmt.Errorf("finding Target is required")
	}
	if f.Description == "" {
		return fmt.Errorf("finding Description is required")
	}
	if f.Scanner == "" {
		return fmt.Errorf("finding Scanner name is required")
	}
	if _, err := ParseStatus(string(f.Status)); err != nil {
		return fmt.Errorf("invalid status in finding %s: %w", f.ID, err)
	}
	return nil
}
