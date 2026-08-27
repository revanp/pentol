package model

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// Target represents a parsed, validated target for Pentol scans.
type Target struct {
	RawInput string `json:"raw_input"`
	URL      string `json:"url"`
	Scheme   string `json:"scheme"`
	Host     string `json:"host"`
	Hostname string `json:"hostname"`
	Port     int    `json:"port"`
	Path     string `json:"path"`
	IsIP     bool   `json:"is_ip"`
	IsHTTPS  bool   `json:"is_https"`
}

// ParseTarget validates and normalizes an input target string.
func ParseTarget(input string) (*Target, error) {
	trimmed := strings.TrimSpace(input)
	if trimmed == "" {
		return nil, fmt.Errorf("target cannot be empty")
	}

	// If no scheme provided, default to http:// for parsing
	toParse := trimmed
	if !strings.HasPrefix(toParse, "http://") && !strings.HasPrefix(toParse, "https://") {
		toParse = "https://" + toParse
	}

	u, err := url.Parse(toParse)
	if err != nil {
		return nil, fmt.Errorf("failed to parse target URL %q: %w", input, err)
	}

	if u.Host == "" {
		return nil, fmt.Errorf("invalid target host in %q", input)
	}

	hostname := u.Hostname()
	if hostname == "" {
		return nil, fmt.Errorf("could not determine hostname for %q", input)
	}

	port := 0
	if u.Port() != "" {
		p, err := strconv.Atoi(u.Port())
		if err != nil {
			return nil, fmt.Errorf("invalid port %q: %w", u.Port(), err)
		}
		port = p
	} else {
		if strings.EqualFold(u.Scheme, "https") {
			port = 443
		} else {
			port = 80
		}
	}

	isIP := net.ParseIP(hostname) != nil
	isHTTPS := strings.EqualFold(u.Scheme, "https")

	path := u.Path
	if path == "" {
		path = "/"
	}

	normURL := fmt.Sprintf("%s://%s", u.Scheme, u.Host)
	if path != "/" {
		normURL += path
	}

	return &Target{
		RawInput: input,
		URL:      normURL,
		Scheme:   strings.ToLower(u.Scheme),
		Host:     u.Host,
		Hostname: strings.ToLower(hostname),
		Port:     port,
		Path:     path,
		IsIP:     isIP,
		IsHTTPS:  isHTTPS,
	}, nil
}

// BaseURL returns the protocol + host string.
func (t *Target) BaseURL() string {
	return fmt.Sprintf("%s://%s", t.Scheme, t.Host)
}

// RootHost returns the domain without port.
func (t *Target) RootHost() string {
	return t.Hostname
}
