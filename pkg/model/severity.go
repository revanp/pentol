package model

import (
	"fmt"
	"strings"
)

// Severity represents the standardized risk severity of a security finding.
type Severity string

const (
	SeverityInfo     Severity = "INFO"
	SeverityLow      Severity = "LOW"
	SeverityMedium   Severity = "MEDIUM"
	SeverityHigh     Severity = "HIGH"
	SeverityCritical Severity = "CRITICAL"
)

// ParseSeverity parses a string into a valid Severity or returns an error.
func ParseSeverity(s string) (Severity, error) {
	upper := strings.ToUpper(strings.TrimSpace(s))
	switch Severity(upper) {
	case SeverityInfo, SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical:
		return Severity(upper), nil
	default:
		return "", fmt.Errorf("invalid severity level: %q (valid: INFO, LOW, MEDIUM, HIGH, CRITICAL)", s)
	}
}

// Weight returns a numeric weight for severity sorting and scoring.
func (s Severity) Weight() int {
	switch s {
	case SeverityCritical:
		return 5
	case SeverityHigh:
		return 4
	case SeverityMedium:
		return 3
	case SeverityLow:
		return 2
	case SeverityInfo:
		return 1
	default:
		return 0
	}
}

// String implements fmt.Stringer.
func (s Severity) String() string {
	return string(s)
}
