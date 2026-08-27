package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"pentol/pkg/engine"
	"pentol/pkg/model"
	"pentol/pkg/report"

	"github.com/spf13/cobra"
)

const (
	Version   = "0.1.0-v1"
	BannerArt = `
  ██████╗ ███████╗███╗   ██╗████████╗ ██████╗ ██╗     
  ██╔══██╗██╔════╝████╗  ██║╚══██╔══╝██╔═══██╗██║     
  ██████╔╝█████╗  ██╔██╗ ██║   ██║   ██║   ██║██║     
  ██╔═══╝ ██╔══╝  ██║╚██╗██║   ██║   ██║   ██║██║     
  ██║     ███████╗██║ ╚████║   ██║   ╚██████╔╝███████╗
  ╚═╝     ╚══════╝╚═╝  ╚═══╝   ╚═╝    ╚═════╝ ╚══════╝
   PENetration Testing tOOL — Phase V1 (Passive/Low-Risk)
`
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "pentol",
		Short: "Pentol is a security assessment and penetration testing toolkit.",
		Long: BannerArt + `
Pentol is an extensible security testing toolkit designed for authorized
assessments of applications, APIs, and infrastructure.

Phase V1 focuses on safe, passive, and low-risk reconnaissance, HTTP security,
and TLS configuration analysis.`,
	}

	rootCmd.AddCommand(newScanCmd())
	rootCmd.AddCommand(newVersionCmd())

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print Pentol version and build details",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("Pentol version %s (Phase V1 - Foundation & Passive/Low-Risk)\n", Version)
		},
	}
}

func newScanCmd() *cobra.Command {
	var (
		formatStr       string
		outputPath      string
		allowedHosts    []string
		excludedHosts   []string
		allowSubdomains bool
		disallowPrivate bool
		timeoutSec      int
		delayMs         int
		safeMode        bool
		verbose         bool
		debug           bool
		insecure        bool
		noColor         bool
		httpOnly        bool
		tlsOnly         bool
		reconOnly       bool
		userAgent       string
	)

	scanCmd := &cobra.Command{
		Use:   "scan <target>",
		Short: "Execute a passive security assessment against an authorized target",
		Long: `Performs passive and low-risk security scanning including:
  • HTTP Security (Headers, Cookies, HTTP Methods, Information Disclosure)
  • TLS/SSL Configuration (Certificates, Expiration, Protocol Versions)
  • Passive Reconnaissance (DNS records, Technology Fingerprint, robots.txt, sitemap.xml)

Example:
  pentol scan https://staging.example.com
  pentol scan staging.example.com --format html --output report.html
  pentol scan https://example.com --format markdown --output assessment.md`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			rawTarget := args[0]

			// Parse and validate target
			target, err := model.ParseTarget(rawTarget)
			if err != nil {
				return fmt.Errorf("invalid target: %w", err)
			}

			// Setup Scope
			scope := model.NewDefaultScope(target)
			if len(allowedHosts) > 0 {
				scope.AllowedHosts = allowedHosts
			}
			if len(excludedHosts) > 0 {
				scope.ExcludedHosts = excludedHosts
			}
			scope.AllowSubdomains = allowSubdomains
			scope.DisallowPrivate = disallowPrivate

			// Verify target is in scope
			if inScope, reason := scope.IsInScope(target.URL); !inScope {
				return fmt.Errorf("target validation failed: %s", reason)
			}

			// Display Target Confirmation & Safety Information
			fmt.Print(BannerArt)
			fmt.Println("──────────────────────────────────────────────────────────────────────────────")
			fmt.Printf("  Target URL:       %s\n", target.URL)
			fmt.Printf("  Hostname:         %s (Port: %d)\n", target.Hostname, target.Port)
			fmt.Printf("  Allowed Scope:    %s\n", strings.Join(scope.AllowedHosts, ", "))
			fmt.Printf("  Safe Mode:        %t (Passive / Non-destructive)\n", safeMode)
			fmt.Printf("  Rate Limit Delay: %d ms\n", delayMs)
			fmt.Printf("  Timeout:          %d s\n", timeoutSec)
			fmt.Println("──────────────────────────────────────────────────────────────────────────────")
			fmt.Println("  [!] Notice: Ensure you have explicit authorization to scan this target.")
			fmt.Println("──────────────────────────────────────────────────────────────────────────────")
			fmt.Println()

			// Build Scan Config
			cfg := engine.NewDefaultConfig(target)
			cfg.Scope = scope
			cfg.SafeMode = safeMode
			cfg.Verbose = verbose
			cfg.Debug = debug
			cfg.InsecureSkipTLS = insecure
			cfg.Timeout = time.Duration(timeoutSec) * time.Second
			cfg.RateLimitDelay = time.Duration(delayMs) * time.Millisecond
			if userAgent != "" {
				cfg.UserAgent = userAgent
			}

			// Module filtering if specific flag given
			if httpOnly || tlsOnly || reconOnly {
				cfg.EnableHTTP = httpOnly
				cfg.EnableTLS = tlsOnly
				cfg.EnableRecon = reconOnly
			}

			// Initialize Orchestrator
			orc, err := engine.NewOrchestrator(cfg, Version)
			if err != nil {
				return fmt.Errorf("failed to initialize scanner orchestrator: %w", err)
			}

			// Setup Context with Signal Cancellation
			ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout)
			defer cancel()

			sigChan := make(chan os.Signal, 1)
			signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
			go func() {
				<-sigChan
				fmt.Println("\n[!] Scan interrupted by user. Finalizing current findings...")
				cancel()
			}()

			// Run scan with progress callback
			result, err := orc.Execute(ctx, func(scannerName, status string, findingCount int) {
				if status == "RUNNING" {
					fmt.Printf("  ⚡ Running scanner: %-15s ...\n", scannerName)
				} else if status == "COMPLETED" {
					fmt.Printf("  ✓ Completed:       %-15s (%d findings)\n", scannerName, findingCount)
				}
			})
			if err != nil && result == nil {
				return fmt.Errorf("assessment execution failed: %w", err)
			}

			// Infer format from output path if not specified
			if outputPath != "" && formatStr == "terminal" {
				ext := strings.ToLower(filepath.Ext(outputPath))
				switch ext {
				case ".json":
					formatStr = "json"
				case ".md", ".markdown":
					formatStr = "markdown"
				case ".html", ".htm":
					formatStr = "html"
				}
			}

			// Select Reporter
			var rep report.Reporter
			switch strings.ToLower(formatStr) {
			case "json":
				rep = report.NewJSONReporter(true)
			case "markdown", "md":
				rep = report.NewMarkdownReporter()
			case "html":
				rep = report.NewHTMLReporter()
			case "terminal", "term":
				rep = report.NewTerminalReporter(noColor)
			default:
				return fmt.Errorf("unsupported output format %q (supported: terminal, json, markdown, html)", formatStr)
			}

			// Always render summary to terminal if outputting to file
			if outputPath != "" {
				termRep := report.NewTerminalReporter(noColor)
				_ = termRep.Render(os.Stdout, result)

				// Write full report to destination file
				file, err := os.Create(outputPath)
				if err != nil {
					return fmt.Errorf("failed to create report file %s: %w", outputPath, err)
				}
				defer file.Close()

				if err := rep.Render(file, result); err != nil {
					return fmt.Errorf("failed to write %s report: %w", formatStr, err)
				}
				fmt.Printf("\n  📁 Full %s report written to: %s\n\n", strings.ToUpper(formatStr), outputPath)
			} else {
				if err := rep.Render(os.Stdout, result); err != nil {
					return fmt.Errorf("failed to render report: %w", err)
				}
			}

			return nil
		},
	}

	scanCmd.Flags().StringVarP(&formatStr, "format", "f", "terminal", "Output format (terminal, json, markdown, html)")
	scanCmd.Flags().StringVarP(&outputPath, "output", "o", "", "File path to save the assessment report")
	scanCmd.Flags().StringSliceVar(&allowedHosts, "allowed-hosts", nil, "Comma-separated list of allowed hosts in scope")
	scanCmd.Flags().StringSliceVar(&excludedHosts, "exclude", nil, "Comma-separated list of excluded hosts")
	scanCmd.Flags().BoolVar(&allowSubdomains, "allow-subdomains", false, "Include subdomains within scope")
	scanCmd.Flags().BoolVar(&disallowPrivate, "disallow-private", false, "Block scans targeting private/internal IP addresses")
	scanCmd.Flags().IntVar(&timeoutSec, "timeout", 60, "Total scan timeout in seconds")
	scanCmd.Flags().IntVar(&delayMs, "rate-limit", 150, "Delay in milliseconds between requests")
	scanCmd.Flags().BoolVar(&safeMode, "safe-mode", true, "Enforce safe, non-destructive passive checks")
	scanCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose logging")
	scanCmd.Flags().BoolVar(&debug, "debug", false, "Enable debug traces")
	scanCmd.Flags().BoolVar(&insecure, "insecure", false, "Allow insecure TLS connections for self-signed certs")
	scanCmd.Flags().BoolVar(&noColor, "no-color", false, "Disable color in terminal output")
	scanCmd.Flags().BoolVar(&httpOnly, "http-only", false, "Run only HTTP security checks")
	scanCmd.Flags().BoolVar(&tlsOnly, "tls-only", false, "Run only TLS security checks")
	scanCmd.Flags().BoolVar(&reconOnly, "recon-only", false, "Run only Reconnaissance checks")
	scanCmd.Flags().StringVar(&userAgent, "user-agent", "", "Custom HTTP User-Agent string")

	return scanCmd
}
