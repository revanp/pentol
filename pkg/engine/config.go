package engine

import (
	"time"

	"pentol/pkg/model"
)

// ScanConfig holds execution parameters, scope, and safety settings for a Pentol assessment.
type ScanConfig struct {
	// Target and Scope
	Target          *model.Target      `json:"target"`
	Scope           *model.ScopeConfig `json:"scope"`
	
	// Execution controls
	Timeout         time.Duration      `json:"timeout"`
	RequestTimeout  time.Duration      `json:"request_timeout"`
	RateLimitDelay  time.Duration      `json:"rate_limit_delay"` // Delay between requests to ensure safe scanning
	MaxConcurrency  int                `json:"max_concurrency"`
	UserAgent       string             `json:"user_agent"`
	CustomHeaders   map[string]string  `json:"custom_headers"`

	// Scanner selection
	EnableHTTP      bool               `json:"enable_http"`
	EnableTLS       bool               `json:"enable_tls"`
	EnableRecon     bool               `json:"enable_recon"`

	// Safety and debugging
	SafeMode        bool               `json:"safe_mode"` // Safe by default: passive checks only
	Verbose         bool               `json:"verbose"`
	Debug           bool               `json:"debug"`
	InsecureSkipTLS bool               `json:"insecure_skip_tls"` // Used for analyzing targets with self-signed certs
}

// NewDefaultConfig returns a conservative, safe-by-default configuration for the given target.
func NewDefaultConfig(target *model.Target) *ScanConfig {
	return &ScanConfig{
		Target:          target,
		Scope:           model.NewDefaultScope(target),
		Timeout:         60 * time.Second,
		RequestTimeout:  10 * time.Second,
		RateLimitDelay:  150 * time.Millisecond,
		MaxConcurrency:  3,
		UserAgent:       "Pentol-Security-Scanner/1.0 (Authorized Security Assessment; +https://github.com/pentol-security/pentol)",
		CustomHeaders:   make(map[string]string),
		EnableHTTP:      true,
		EnableTLS:       true,
		EnableRecon:     true,
		SafeMode:        true,
		Verbose:         false,
		Debug:           false,
		InsecureSkipTLS: false,
	}
}
