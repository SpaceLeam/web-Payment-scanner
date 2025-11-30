package main

import (
	"fmt"
	"os"
	"time"
	
	"github.com/SpaceLeam/web-Payment-scanner/internal/browser"
	"github.com/SpaceLeam/web-Payment-scanner/internal/models"
	"github.com/SpaceLeam/web-Payment-scanner/internal/scanner"
	"github.com/SpaceLeam/web-Payment-scanner/internal/reporter"
	"github.com/SpaceLeam/web-Payment-scanner/internal/utils"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var (
	// Version information
	version = "0.1.0"
	
	// Global flags
	verbose    bool
	headless   bool
	browserType string
	loginURL   string
	timeout    int
	
	// Scan flags
	targetURL string
	outputDir string
	wordlistPath string
	maxDepth int
	
	// Discovery flags
	enableCrawl       bool
	enableWayback     bool
	enableCommonPaths bool
	enableJSAnalysis  bool
	
	// Scanner flags
	enableRace      bool
	enablePrice     bool
	enableIDOR      bool
	enableOTP       bool
	enableCallback  bool
	enableAmount    bool
	enableIdempotency bool
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "scanner",
		Short: "Web Payment Security Scanner",
		Long: `🛡️  Web Payment Scanner - Automated payment security testing tool
		
For authorized penetration testing only.
Detects race conditions, price manipulation, IDOR, and more.`,
		Version: version,
		Run:     runScan,
	}
	
	// Global flags
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose output")
	rootCmd.PersistentFlags().BoolVar(&headless, "headless", false, "Run browser in headless mode")
	rootCmd.PersistentFlags().StringVarP(&browserType, "browser", "b", "firefox", "Browser type (firefox, chromium, webkit)")
	rootCmd.PersistentFlags().IntVarP(&timeout, "timeout", "t", 300, "Login timeout in seconds")
	
	// Scan flags
	rootCmd.Flags().StringVarP(&targetURL, "target", "u", "", "Target URL to scan (required)")
	rootCmd.Flags().StringVarP(&loginURL, "login", "l", "", "Login URL (if different from target)")
	rootCmd.Flags().StringVarP(&outputDir, "output", "o", "reports", "Output directory for reports")
	rootCmd.Flags().StringVarP(&wordlistPath, "wordlist", "w", "configs/wordlists/payment_paths.txt", "Path to wordlist file")
	rootCmd.Flags().IntVarP(&maxDepth, "depth", "d", 3, "Max crawl depth")
	
	// Discovery flags
	rootCmd.Flags().BoolVar(&enableCrawl, "crawl", true, "Enable crawler")
	rootCmd.Flags().BoolVar(&enableWayback, "wayback", true, "Enable Wayback Machine discovery")
	rootCmd.Flags().BoolVar(&enableCommonPaths, "common-paths", true, "Enable common path brute-forcing")
	rootCmd.Flags().BoolVar(&enableJSAnalysis, "js-analysis", true, "Enable JavaScript analysis")
	
	// Scanner flags
	rootCmd.Flags().BoolVar(&enableRace, "race", true, "Enable Race Condition scanner")
	rootCmd.Flags().BoolVar(&enablePrice, "price", true, "Enable Price Manipulation scanner")
	rootCmd.Flags().BoolVar(&enableIDOR, "idor", true, "Enable IDOR scanner")
	rootCmd.Flags().BoolVar(&enableOTP, "otp", true, "Enable OTP Security scanner")
	rootCmd.Flags().BoolVar(&enableCallback, "callback", true, "Enable Callback/Webhook scanner")
	rootCmd.Flags().BoolVar(&enableAmount, "amount", true, "Enable Amount Validation scanner")
	rootCmd.Flags().BoolVar(&enableIdempotency, "idempotency", true, "Enable Idempotency scanner")
	
	rootCmd.MarkFlagRequired("target")
	
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func runScan(cmd *cobra.Command, args []string) {
	logger := utils.NewLogger(verbose)
	logger.Banner("🛡️  Web Payment Scanner v" + version)
	
	// Validate target
	if !utils.IsValidURL(targetURL) {
		logger.Fatal(fmt.Errorf("invalid target URL: %s", targetURL))
	}
	
	// Setup config
	config := models.ScanConfig{
		TargetURL:          targetURL,
		LoginURL:           loginURL,
		Browser:            browserType,
		Headless:           headless,
		BrowserTimeout:     time.Duration(timeout) * time.Second,
		OutputDir:          outputDir,
		Verbose:            verbose,
		MaxDepth:           maxDepth,
		WordlistPath:       wordlistPath,
		EnableCrawl:        enableCrawl,
		EnableWayback:      enableWayback,
		EnableCommonPaths:  enableCommonPaths,
		EnableJSAnalysis:   enableJSAnalysis,
		EnableRaceCondition: enableRace,
		EnablePriceManipulation: enablePrice,
		EnableIDOR:         enableIDOR,
		EnableOTPSecurity:  enableOTP,
		EnableCallbackAuth: enableCallback,
		EnableAmountValidation: enableAmount,
		EnableIdempotency:  enableIdempotency,
		Domain:             utils.ExtractDomain(targetURL),
	}
	
	// 1. Initialize Browser & Login
	logger.Section("Phase 0: Initialization & Authentication")
	
	// Check if session file exists
	sessionFile := "session.json"
	var session *models.Session
	
	if _, err := os.Stat(sessionFile); err == nil {
		logger.Info("Found existing session file: %s", sessionFile)
		session, err = browser.LoadSessionFromFile(sessionFile)
		if err != nil {
			logger.Warn("Failed to load session: %v", err)
		} else {
			logger.Success("Loaded session with %d cookies", len(session.Cookies))
		}
	}
	
	br, err := browser.NewBrowser(browserType, headless)
	if err != nil {
		logger.Fatal(err)
	}
	defer br.Close()
	
	// If no session or login requested
	if session == nil || loginURL != "" {
		// Handle login if URL provided
		if loginURL != "" {
			logger.Info("Waiting for manual login at %s...", loginURL)
			err = br.WaitForManualLogin(loginURL, config.BrowserTimeout)
			if err != nil {
				logger.Fatal(fmt.Errorf("login failed: %w", err))
			}
			logger.Success("Login detected!")
			
			// Extract and save session
			session, err = br.ExtractSession()
			if err != nil {
				logger.Error("Failed to extract session: %v", err)
			} else {
				logger.Success("Session extracted (%d cookies)", len(session.Cookies))
				if err := browser.SaveSessionToFile(session, sessionFile); err != nil {
					logger.Warn("Failed to save session: %v", err)
				} else {
					logger.Success("Session saved to %s", sessionFile)
				}
			}
		} else {
			logger.Info("No login URL provided and no session found. Proceeding as anonymous.")
			// Create empty session
			session = &models.Session{
				Cookies: make(map[string]string),
				Headers: make(map[string]string),
			}
		}
	} else {
		// We have a loaded session, we should probably load cookies into browser if we want to use it for crawling
		// But for now, we pass it to the engine.
		// Ideally: br.LoadCookies(session.Cookies)
	}
	
	// 2. Initialize Engine
	engine := scanner.NewEngine(config, session, br)
	
	// 3. Start Discovery
	startTime := time.Now()
	if err := engine.StartDiscovery(); err != nil {
		logger.Error("Discovery failed: %v", err)
	}
	
	// 4. Start Scanning
	if err := engine.StartScanning(); err != nil {
		logger.Error("Scanning failed: %v", err)
	}
	
	// 5. Generate Reports
	logger.Section("Phase 3: Reporting")
	result := engine.GetResults()
	result.Duration = time.Since(startTime)
	
	// Console Report
	reporter.PrintConsoleSummary(result)
	
	// JSON Report
	jsonFile, err := reporter.GenerateJSONReport(result, outputDir)
	if err != nil {
		logger.Error("Failed to generate JSON report: %v", err)
	} else {
		logger.Success("JSON report saved to: %s", jsonFile)
	}
	
	// HTML Report
	htmlFile, err := reporter.GenerateHTMLReport(result, outputDir)
	if err != nil {
		logger.Error("Failed to generate HTML report: %v", err)
	} else {
		logger.Success("HTML report saved to: %s", htmlFile)
	}
	
	fmt.Println()
	color.Green("✨ Scan completed successfully!")
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
