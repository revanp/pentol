package engine

import (
	"context"
	"fmt"
	"sync"
	"time"

	"pentol/pkg/model"
	"pentol/pkg/scanners"
	httpScanner "pentol/pkg/scanners/http"
	reconScanner "pentol/pkg/scanners/recon"
	tlsScanner "pentol/pkg/scanners/tls"
)

// Orchestrator coordinates target validation, safety verification, scanner execution, and result normalization.
type Orchestrator struct {
	config   *ScanConfig
	scanners []scanners.Scanner
	version  string
}

// NewOrchestrator creates and initializes an Orchestrator with enabled scanners according to configuration.
func NewOrchestrator(cfg *ScanConfig, version string) (*Orchestrator, error) {
	if cfg == nil {
		return nil, fmt.Errorf("scan config cannot be nil")
	}
	if cfg.Target == nil {
		return nil, fmt.Errorf("target cannot be nil")
	}
	if cfg.Scope == nil {
		cfg.Scope = model.NewDefaultScope(cfg.Target)
	}

	orc := &Orchestrator{
		config:  cfg,
		version: version,
	}

	// Register scanners according to config
	if cfg.EnableHTTP {
		orc.scanners = append(orc.scanners, httpScanner.NewHTTPScanner(
			httpScanner.WithUserAgent(cfg.UserAgent),
			httpScanner.WithRateLimitDelay(cfg.RateLimitDelay),
			httpScanner.WithInsecureTLS(cfg.InsecureSkipTLS),
		))
	}

	if cfg.EnableTLS {
		orc.scanners = append(orc.scanners, tlsScanner.NewTLSScanner(cfg.RequestTimeout))
	}

	if cfg.EnableRecon {
		orc.scanners = append(orc.scanners, reconScanner.NewReconScanner())
	}

	return orc, nil
}

// ProgressCallback receives updates when a scanner starts or finishes.
type ProgressCallback func(scannerName, status string, findingCount int)

// Execute runs the full assessment suite against the configured target.
func (o *Orchestrator) Execute(ctx context.Context, cb ProgressCallback) (*model.ScanResult, error) {
	// 1. Safety verification
	if err := o.verifySafety(); err != nil {
		return nil, fmt.Errorf("safety check failed: %w", err)
	}

	result := model.NewScanResult(o.version, o.config.Target)
	result.Metadata["safe_mode"] = fmt.Sprintf("%v", o.config.SafeMode)
	result.Metadata["user_agent"] = o.config.UserAgent

	var mu sync.Mutex
	var wg sync.WaitGroup

	// Rate limiter channel
	limiter := time.Tick(o.config.RateLimitDelay)

	for _, s := range o.scanners {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		result.ScannersRun = append(result.ScannersRun, s.Name())
		if cb != nil {
			cb(s.Name(), "RUNNING", 0)
		}

		// Execute scanner
		findings, err := s.Run(ctx, o.config.Target, o.config.Scope)
		if err != nil && o.config.Verbose {
			// Scanner had a non-fatal error (e.g. port closed, DNS resolution failure)
			result.Metadata[fmt.Sprintf("scanner_error_%s", s.Name())] = err.Error()
		}

		count := 0
		if findings != nil {
			for _, f := range findings {
				if f != nil {
					_ = f.Validate()
					mu.Lock()
					result.AddFinding(f)
					mu.Unlock()
					count++
				}
			}
		}

		if cb != nil {
			cb(s.Name(), "COMPLETED", count)
		}

		// Wait safe rate limit delay before starting next scanner
		<-limiter
	}

	_ = wg
	result.Finalize()
	return result, nil
}

// verifySafety enforces safe scanning policies.
func (o *Orchestrator) verifySafety() error {
	// Check scope
	inScope, reason := o.config.Scope.IsInScope(o.config.Target.URL)
	if !inScope {
		return fmt.Errorf("target %s violates defined scope: %s", o.config.Target.URL, reason)
	}

	return nil
}
