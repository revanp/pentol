package model

import (
	"fmt"
	"net"
	"strings"
)

// ScopeConfig defines boundaries and restrictions for Pentol scans.
type ScopeConfig struct {
	AllowedHosts    []string `json:"allowed_hosts"`
	ExcludedHosts   []string `json:"excluded_hosts"`
	AllowSubdomains bool     `json:"allow_subdomains"`
	DisallowPrivate bool     `json:"disallow_private"` // Blocks private IP ranges (127.0.0.1, 10.x, etc.) when true
}

// NewDefaultScope returns a conservative safe default scope for a given target.
func NewDefaultScope(target *Target) *ScopeConfig {
	return &ScopeConfig{
		AllowedHosts:    []string{target.Hostname},
		ExcludedHosts:   []string{},
		AllowSubdomains: false,
		DisallowPrivate: false,
	}
}

// IsInScope checks whether a given host or URL is permitted by the scope configuration.
func (s *ScopeConfig) IsInScope(hostOrURL string) (bool, string) {
	if hostOrURL == "" {
		return false, "empty host or URL"
	}

	// Extract hostname
	host := hostOrURL
	if strings.Contains(host, "://") {
		parsed, err := ParseTarget(hostOrURL)
		if err != nil {
			return false, fmt.Sprintf("failed to parse candidate URL %s: %v", hostOrURL, err)
		}
		host = parsed.Hostname
	} else if strings.Contains(host, ":") {
		h, _, err := net.SplitHostPort(host)
		if err == nil {
			host = h
		}
	}
	host = strings.ToLower(strings.TrimSpace(host))

	// Check private IP restriction if enabled
	if s.DisallowPrivate {
		ip := net.ParseIP(host)
		if ip != nil && (ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast()) {
			return false, fmt.Sprintf("target host %s is a private or loopback IP and DisallowPrivate is active", host)
		}
	}

	// Check Excluded hosts
	for _, excluded := range s.ExcludedHosts {
		excluded = strings.ToLower(strings.TrimSpace(excluded))
		if excluded == "" {
			continue
		}
		if host == excluded || strings.HasSuffix(host, "."+excluded) {
			return false, fmt.Sprintf("host %s is explicitly excluded by rule %s", host, excluded)
		}
	}

	// Check Allowed hosts
	if len(s.AllowedHosts) == 0 {
		return true, "" // Default open if no restrictions configured
	}

	for _, allowed := range s.AllowedHosts {
		allowed = strings.ToLower(strings.TrimSpace(allowed))
		if allowed == "" {
			continue
		}
		if host == allowed {
			return true, ""
		}
		if s.AllowSubdomains && strings.HasSuffix(host, "."+allowed) {
			return true, ""
		}
	}

	return false, fmt.Sprintf("host %s is outside allowed scope (%s)", host, strings.Join(s.AllowedHosts, ", "))
}
