package main

import (
	"crypto/md5"
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
	version = "0.2.0"
	
	// Flags
	verbose, headless bool
	browserType, loginURL, targetURL, outputDir, wordlistPath string
	timeout, maxDepth int
	enableCrawl, enableWayback, enableCommonPaths, enableJSAnalysis bool
	enableRace, enablePrice, enableIDOR, enableOTP, enableCallback, enableAmount, enableIdempotency bool
	enableWSInterceptor bool // NEW
	skipSessionCache bool    // NEW
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "scanner",
		Short: "Web Payment Security Scanner",
		Long:  `🛡️ Payment scanner with WebSocket support`,
		Version: version,
		Run:     runScan,
	}
	
	// Global flags
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Verbose output")
	rootCmd.PersistentFlags().BoolVar(&headless, "headless", false, "Headless browser")
	rootCmd.PersistentFlags().StringVarP(&browserType, "browser", "b", "firefox", "Browser type")
	rootCmd.PersistentFlags().IntVarP(&timeout, "timeout", "t", 300, "Login timeout (seconds)")
	
	// Scan flags
	rootCmd.Flags().StringVarP(&targetURL, "target", "u", "", "Target URL (required)")
	rootCmd.Flags().StringVarP(&loginURL, "login", "l", "", "Login URL")
	rootCmd.Flags().StringVarP(&outputDir, "output", "o", "reports", "Output directory")
	rootCmd.Flags().StringVarP(&wordlistPath, "wordlist", "w", "configs/wordlists/payment_paths.txt", "Path to wordlist file")
	rootCmd.Flags().IntVarP(&maxDepth, "depth", "d", 3, "Max crawl depth")
	
	// Discovery
	rootCmd.Flags().BoolVar(&enableCrawl, "crawl", true, "Enable crawler")
	rootCmd.Flags().BoolVar(&enableWayback, "wayback", true, "Enable Wayback")
	rootCmd.Flags().BoolVar(&enableCommonPaths, "common-paths", true, "Enable path brute-force")
	rootCmd.Flags().BoolVar(&enableJSAnalysis, "js-analysis", true, "Enable JS analysis")
	
	// Scanners
	rootCmd.Flags().BoolVar(&enableRace, "race", true, "Enable Race Condition")
	rootCmd.Flags().BoolVar(&enablePrice, "price", true, "Enable Price Manipulation")
	rootCmd.Flags().BoolVar(&enableIDOR, "idor", true, "Enable IDOR")
	rootCmd.Flags().BoolVar(&enableOTP, "otp", true, "Enable OTP Security")
	rootCmd.Flags().BoolVar(&enableCallback, "callback", true, "Enable Callback Auth")
	rootCmd.Flags().BoolVar(&enableAmount, "amount", true, "Enable Amount Validation")
	rootCmd.Flags().BoolVar(&enableIdempotency, "idempotency", true, "Enable Idempotency")
	
	// WebSocket
	rootCmd.Flags().BoolVar(&enableWSInterceptor, "ws-intercept", true, "Enable WebSocket interceptor")
	rootCmd.Flags().BoolVar(&skipSessionCache, "no-cache", false, "Skip session cache")
	
	rootCmd.MarkFlagRequired("target")
	
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func runScan(cmd *cobra.Command, args []string) {
	logger := utils.NewLogger(verbose)
	logger.Banner("🛡️ Web Payment Scanner v" + version)
	
	if !utils.IsValidURL(targetURL) {
		logger.Fatal(fmt.Errorf("invalid target URL"))
	}
	
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
	
	// Session management
	sessionTTL := 6 * time.Hour // P1: Reduced from 20 days to 6 hours
	var session *models.Session
	var br *browser.Browser
	var wsi *browser.WSInterceptor
	
	hash := fmt.Sprintf("%x", md5.Sum([]byte(loginURL+targetURL)))
	sessionFile := fmt.Sprintf("sessions/session_%s.json", hash)
	
	// Try load cached session
	if !skipSessionCache {
		if cachedSession, err := browser.LoadSessionFromFile(sessionFile); err == nil && cachedSession != nil {
			if time.Since(cachedSession.CreatedAt) < sessionTTL {
				age := time.Since(cachedSession.CreatedAt)
				logger.Success("Using cached session (age: %s)", age.Round(time.Second))
				session = cachedSession
			} else {
				logger.Warn("Cached session expired (age: %s > %s TTL)", 
					time.Since(cachedSession.CreatedAt).Round(time.Hour),
					sessionTTL)
			}
		}
	}
	
	// Login if no valid session
	if session == nil {
		logger.Section("Phase 0: Authentication")
		
		var err error
		br, err = browser.NewBrowser(browserType, headless)
		if err != nil {
			logger.Fatal(err)
		}
		
		// Login
		if loginURL != "" {
			// Navigate to login page first (to have a page context)
			logger.Info("Navigating to login page...")
			err = br.Navigate(loginURL)
			if err != nil {
				logger.Fatal(fmt.Errorf("failed to navigate: %w", err))
			}
			
			// Enable WebSocket interceptor BEFORE user login
			if enableWSInterceptor {
				wsi = browser.NewWSInterceptor()
				if err := wsi.Enable(br.GetPage()); err != nil {
					logger.Error("Failed to enable WS interceptor: %v", err)
				} else {
					logger.Success("WebSocket interceptor enabled")
				}
			}
			
			// Wait for user to complete login
			logger.Info("Waiting for manual login...")
			err = br.WaitForManualLogin(loginURL, config.BrowserTimeout)
			if err != nil {
				logger.Fatal(fmt.Errorf("login failed: %w", err))
			}
		} else {
			// Navigate to target directly
			err = br.Navigate(targetURL)
			if err != nil {
				logger.Fatal(err)
			}
			
			// Enable WS interceptor after navigation
			if enableWSInterceptor {
				wsi = browser.NewWSInterceptor()
				if err := wsi.Enable(br.GetPage()); err != nil {
					logger.Error("Failed to enable WS interceptor: %v", err)
				} else {
					logger.Success("WebSocket interceptor enabled")
				}
			}
		}
		
		logger.Success("Authentication complete")
		
		// Wait for cookies and WebSocket connection to be established
		logger.Info("Waiting for session to stabilize...")
		time.Sleep(3 * time.Second)
		
		// Wait for WebSocket connection
		if enableWSInterceptor && wsi != nil {
			wsInfo := wsi.GetConnectionInfo(br.GetPage())
			if wsInfo != nil && wsInfo["connected"].(bool) {
				logger.Success("WebSocket connected: %s", wsInfo["url"])
			} else {
				logger.Warn("No WebSocket connection detected (site may use HTTP polling)")
			}
		}
		
		// Extract session
		session, err = browser.ExtractWebSocketSession(br.GetPage())
		if err != nil {
			logger.Error("Failed to extract session: %v", err)
		} else {
			cookieCount := len(session.Cookies)
			tokenPreview := truncate(session.SessionToken, 20)
			if tokenPreview == "" {
				tokenPreview = "(none)"
			}
			logger.Success("Session extracted (%d cookies, token: %s)", cookieCount, tokenPreview)
		}
		
		// Save session
		os.MkdirAll("sessions", 0700)
		if err := browser.SaveSessionToFile(session, sessionFile); err != nil {
			logger.Warn("Failed to save session: %v", err)
		} else {
			logger.Success("Session cached to: %s", sessionFile)
		}
	} else {
		// Reuse browser with cached session (optional)
		// For now, we skip browser for cached sessions unless needed
		logger.Info("Skipping browser (using cached session)")
	}
	
	// Initialize engine
	engine := scanner.NewEngine(config, session, br)
	
	// Discovery
	startTime := time.Now()
	if err := engine.StartDiscovery(); err != nil {
		logger.Error("Discovery failed: %v", err)
	}
	
	// Scanning
	if err := engine.StartScanning(); err != nil {
		logger.Error("Scanning failed: %v", err)
	}
	
	// WebSocket-specific tests
	if enableWSInterceptor && wsi != nil && br != nil {
		logger.Section("Phase 2b: WebSocket Scanning")
		
		// Show traffic summary
		wsi.PrintSummary()
		
		// Test race conditions
		if enableRace {
			logger.Info("Testing WebSocket race conditions...")
			wsVulns := scanner.TestWebSocketRaceCondition(br.GetPage(), wsi, 10)
			engine.AddVulnerabilities(wsVulns)
		}
		
		// Test replay
		logger.Info("Testing WebSocket replay attacks...")
		replayVulns := scanner.TestWebSocketReplay(br.GetPage(), wsi)
		engine.AddVulnerabilities(replayVulns)
		
		// Test amount manipulation
		if enablePrice {
			logger.Info("Testing WebSocket amount manipulation...")
			amountVulns := scanner.TestWebSocketAmountManipulation(br.GetPage(), wsi)
			engine.AddVulnerabilities(amountVulns)
		}
	}
	
	// Cleanup browser
	if br != nil {
		br.Close()
	}
	
	// Reports
	logger.Section("Phase 3: Reporting")
	result := engine.GetResults()
	result.Duration = time.Since(startTime)
	
	reporter.PrintConsoleSummary(result)
	
	jsonFile, _ := reporter.GenerateJSONReport(result, outputDir)
	logger.Success("JSON: %s", jsonFile)
	
	htmlFile, _ := reporter.GenerateHTMLReport(result, outputDir)
	logger.Success("HTML: %s", htmlFile)
	
	color.Green("\n✨ Scan completed!")
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
