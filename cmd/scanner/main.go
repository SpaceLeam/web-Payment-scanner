package main

import (
	"fmt"
	"os"
	"time"
	
	"github.com/SpaceLeam/web-Payment-scanner/internal/browser"
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
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "scanner",
		Short: "Web Payment Security Scanner",
		Long: `🛡️  Web Payment Scanner - Automated payment security testing tool
		
For authorized penetration testing only.
Detects race conditions, price manipulation, IDOR, and more.`,
		Version: version,
	}
	
	// Add flags
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose output")
	rootCmd.PersistentFlags().BoolVar(&headless, "headless", false, "Run browser in headless mode")
	rootCmd.PersistentFlags().StringVarP(&browserType, "browser", "b", "firefox", "Browser type (firefox, chromium, webkit)")
	rootCmd.PersistentFlags().IntVarP(&timeout, "timeout", "t", 300, "Login timeout in seconds")
	
	// Test command
	testCmd := &cobra.Command{
		Use:   "test",
		Short: "Test browser automation",
		Long:  "Test browser automation and session extraction",
		Run:   runTest,
	}
	
	testCmd.Flags().StringVarP(&loginURL, "url", "u", "", "Login URL to test (required)")
	testCmd.MarkFlagRequired("url")
	
	rootCmd.AddCommand(testCmd)
	
	// Version command (already built-in with --version flag)
	
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func runTest(cmd *cobra.Command, args []string) {
	logger := utils.NewLogger(verbose)
	
	logger.Banner("🛡️  Web Payment Scanner v" + version)
	logger.Info("Testing browser automation...")
	
	// Validate URL
	if !utils.IsValidURL(loginURL) {
		logger.Error("Invalid URL: %s", loginURL)
		return
	}
	
	logger.Info("Browser: %s (headless: %v)", browserType, headless)
	logger.Info("Login URL: %s", loginURL)
	
	// Create browser instance
	logger.Section("Step 1: Launching Browser")
	br, err := browser.NewBrowser(browserType, headless)
	if err != nil {
		logger.Fatal(err)
	}
	defer br.Close()
	
	logger.Success("Browser launched Successfully")
	
	// Wait for manual login
	logger.Section("Step 2: Manual Login")
	loginTimeout := time.Duration(timeout) * time.Second
	err = br.WaitForManualLogin(loginURL, loginTimeout)
	if err != nil {
		logger.Error("Login failed: %v", err)
		return
	}
	
	logger.Success("Login successful!")
	logger.Info("Current URL: %s", br.GetCurrentURL())
	
	// Extract session
	logger.Section("Step 3: Extracting Session Data")
	session, err := br.ExtractSession()
	if err != nil {
		logger.Error("Failed to extract session: %v", err)
		return
	}
	
	logger.Success("Session extracted successfully")
	
	// Display session info
	logger.Info("Cookies found: %d", len(session.Cookies))
	logger.Info("LocalStorage items: %d", len(session.LocalStorage))
	logger.Info("SessionStorage items: %d", len(session.SessionStorage))
	
	if verbose {
		logger.Debug("\n=== Cookies ===")
		for name, value := range session.Cookies {
			logger.Debug("  %s: %s", name, truncate(value, 50))
		}
	}
	
	logger.Section("Test Complete")
	logger.Success("All tests passed! ✓")
	
	fmt.Println()
	fmt.Println(color.CyanString("Next steps:"))
	fmt.Println("  1. Run endpoint discovery")
	fmt.Println("  2. Execute vulnerability scans")
	fmt.Println("  3. Generate security report")
	fmt.Println()
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
