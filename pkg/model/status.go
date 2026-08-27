package model

import (
	"fmt"
	"strings"
)

// FindingStatus represents the lifecycle state of a security finding.
type FindingStatus string

const (
	StatusOpen     FindingStatus = "OPEN"
	StatusTriaged  FindingStatus = "TRIAGED"
	StatusFixed    FindingStatus = "FIXED"
	StatusRetested FindingStatus = "RETESTED"
	StatusClosed   FindingStatus = "CLOSED"
)

// ParseStatus parses a string into a FindingStatus or returns an error.
func ParseStatus(s string) (FindingStatus, error) {
	upper := strings.ToUpper(strings.TrimSpace(s))
	switch FindingStatus(upper) {
	case StatusOpen, StatusTriaged, StatusFixed, StatusRetested, StatusClosed:
		return FindingStatus(upper), nil
	default:
		return "", fmt.Errorf("invalid finding status: %q (valid: OPEN, TRIAGED, FIXED, RETESTED, CLOSED)", s)
	}
}

// String implements fmt.Stringer.
func (s FindingStatus) String() string {
	return string(s)
}
