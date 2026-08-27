package scanners

import (
	"context"

	"pentol/pkg/model"
)

// Scanner is the common interface that all Pentol assessment modules must implement.
type Scanner interface {
	// Name returns the unique identifier for the scanner (e.g. "http-scanner", "tls-scanner", "recon-scanner")
	Name() string

	// Description returns a concise summary of what this scanner checks.
	Description() string

	// Run executes the scanner against the given target and returns normalized findings.
	Run(ctx context.Context, target *model.Target, scope *model.ScopeConfig) ([]*model.Finding, error)
}
