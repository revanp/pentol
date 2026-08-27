package model

import (
	"sort"
	"time"
)

// ScanSummary aggregates finding counts by severity.
type ScanSummary struct {
	Total    int `json:"total"`
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
}

// ScanResult holds the full output of a Pentol assessment run.
type ScanResult struct {
	PentolVersion string            `json:"pentol_version"`
	Target        *Target           `json:"target"`
	StartTime     time.Time         `json:"start_time"`
	EndTime       time.Time         `json:"end_time"`
	Duration      string            `json:"duration"`
	ScannersRun   []string          `json:"scanners_run"`
	Findings      []*Finding        `json:"findings"`
	Summary       ScanSummary       `json:"summary"`
	Metadata      map[string]string `json:"metadata,omitempty"`
}

// NewScanResult creates an initialized ScanResult.
func NewScanResult(version string, target *Target) *ScanResult {
	return &ScanResult{
		PentolVersion: version,
		Target:        target,
		StartTime:     time.Now().UTC(),
		ScannersRun:   make([]string, 0),
		Findings:      make([]*Finding, 0),
		Summary:       ScanSummary{},
		Metadata:      make(map[string]string),
	}
}

// AddFinding appends a validated finding and updates summary counts.
func (r *ScanResult) AddFinding(f *Finding) {
	if f == nil {
		return
	}
	r.Findings = append(r.Findings, f)
}

// Finalize sorts findings by severity (descending) and computes final metrics.
func (r *ScanResult) Finalize() {
	r.EndTime = time.Now().UTC()
	r.Duration = r.EndTime.Sub(r.StartTime).Round(time.Millisecond).String()

	// Reset summary
	r.Summary = ScanSummary{
		Total: len(r.Findings),
	}

	for _, f := range r.Findings {
		switch f.Severity {
		case SeverityCritical:
			r.Summary.Critical++
		case SeverityHigh:
			r.Summary.High++
		case SeverityMedium:
			r.Summary.Medium++
		case SeverityLow:
			r.Summary.Low++
		case SeverityInfo:
			r.Summary.Info++
		}
	}

	// Sort findings by severity weight (highest first), then by scanner, then by title
	sort.Slice(r.Findings, func(i, j int) bool {
		wi := r.Findings[i].Severity.Weight()
		wj := r.Findings[j].Severity.Weight()
		if wi != wj {
			return wi > wj
		}
		if r.Findings[i].Scanner != r.Findings[j].Scanner {
			return r.Findings[i].Scanner < r.Findings[j].Scanner
		}
		return r.Findings[i].Title < r.Findings[j].Title
	})
}
