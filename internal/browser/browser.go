package browser

import (
	"fmt"
	"time"
	
	"github.com/SpaceLeam/web-Payment-scanner/internal/models"
	"github.com/playwright-community/playwright-go"
)

// Browser wraps Playwright browser automation
type Browser struct {
	pw      *playwright.Playwright
	browser playwright.Browser
	context playwright.BrowserContext
	page    playwright.Page
}

// NewBrowser creates a new browser instance
func NewBrowser(browserType string, headless bool) (*Browser, error) {
	// Initialize Playwright
	pw, err := playwright.Run()
	if err != nil {
		return nil, fmt.Errorf("failed to start playwright: %w", err)
	}
	
	// Launch options with anti-detection
	launchOptions := playwright.BrowserTypeLaunchOptions{
		Headless: playwright.Bool(headless),
		Args: []string{
			"--disable-blink-features=AutomationControlled",
			"--disable-dev-shm-usage",
			"--no-sandbox",
		},
	}
	
	var browser playwright.Browser
	
	// Select browser type
	switch browserType {
	case "firefox":
		browser, err = pw.Firefox.Launch(launchOptions)
	case "chromium":
		browser, err = pw.Chromium.Launch(launchOptions)
	case "webkit":
		browser, err = pw.WebKit.Launch(launchOptions)
	default:
		browser, err = pw.Firefox.Launch(launchOptions)
	}
	
	if err != nil {
		pw.Stop()
		return nil, fmt.Errorf("failed to launch browser: %w", err)
	}
	
	// Create context with realistic settings
	context, err := browser.NewContext(playwright.BrowserNewContextOptions{
		UserAgent: playwright.String("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"),
		Viewport: &playwright.Size{
			Width:  1920,
			Height: 1080,
		},
		Locale:           playwright.String("en-US"),
		TimezoneId:       playwright.String("America/New_York"),
		AcceptDownloads:  playwright.Bool(false),
		IgnoreHttpsErrors: playwright.Bool(true), // For testing environments
	})
	
	if err != nil {
		browser.Close()
		pw.Stop()
		return nil, fmt.Errorf("failed to create context: %w", err)
	}
	
	// Create page
	page, err := context.NewPage()
	if err != nil {
		context.Close()
		browser.Close()
		pw.Stop()
		return nil, fmt.Errorf("failed to create page: %w", err)
	}
	
	return &Browser{
		pw:      pw,
		browser: browser,
		context: context,
		page:    page,
	}, nil
}

// Navigate navigates to a URL
func (b *Browser) Navigate(url string) error {
	_, err := b.page.Goto(url, playwright.PageGotoOptions{
		WaitUntil: playwright.WaitUntilStateNetworkidle,
		Timeout:   playwright.Float(30000),
	})
	return err
}

// WaitForManualLogin waits for the user to manually log in
func (b *Browser) WaitForManualLogin(loginURL string, timeout time.Duration) error {
	// Navigate to login page
	if err := b.Navigate(loginURL); err != nil {
		return fmt.Errorf("failed to navigate to login page: %w", err)
	}
	
	fmt.Println("\n Please complete authentication (phone + PIN)...")
	fmt.Printf("  Timeout: %v\n", timeout)
	
	startTime := time.Now()
	for {
		if time.Since(startTime) > timeout {
			return fmt.Errorf("login timeout exceeded")
		}
		
		// Check multiple success indicators
		currentURL := b.page.URL()
		
		// 1. URL changed from login
		if currentURL != loginURL {
			// Also ensure we are not just on a different login page (e.g. sso)
			if !isLoginPage(currentURL) {
				fmt.Println("✓ URL change detected")
				time.Sleep(2 * time.Second)
				return nil
			}
		}
		
		// 2. Check for payment/dashboard elements
		selectors := []string{
			"[data-testid='user-balance']",
			".user-menu",
			"#payment-form",
			"button[type='submit']", // Payment button often appears after login
			".dashboard",
			".wallet-balance",
		}
		
		for _, selector := range selectors {
			count, _ := b.page.Locator(selector).Count()
			if count > 0 {
				fmt.Println("✓ Dashboard/Payment page detected")
				return nil
			}
		}
		
		time.Sleep(1 * time.Second)
	}
}

func isLoginPage(url string) bool {
	// Simple check if URL contains login keywords
	// In reality, we might need more sophisticated checks
	return false // Placeholder, rely on element detection mostly
}

// GetCurrentURL returns the current page URL
func (b *Browser) GetCurrentURL() string {
	return b.page.URL()
}

// GetPage returns the Playwright page object
func (b *Browser) GetPage() playwright.Page {
	return b.page
}

// GetContext returns the browser context
func (b *Browser) GetContext() playwright.BrowserContext {
	return b.context
}

// Close closes the browser and cleanup
func (b *Browser) Close() error {
	if b.page != nil {
		_ = b.page.Close()
	}
	if b.context != nil {
		_ = b.context.Close()
	}
	if b.browser != nil {
		_ = b.browser.Close()
	}
	if b.pw != nil {
		_ = b.pw.Stop()
	}
	return nil
}

// Screenshot takes a screenshot of the current page
func (b *Browser) Screenshot(path string) error {
	_, err := b.page.Screenshot(playwright.PageScreenshotOptions{
		Path: playwright.String(path),
		FullPage: playwright.Bool(true),
	})
	return err
}

// ExtractSession extracts cookies, headers, and storage from the current session
func (b *Browser) ExtractSession() (*models.Session, error) {
	session := &models.Session{
		Cookies:        make(map[string]string),
		Headers:        make(map[string]string),
		LocalStorage:   make(map[string]string),
		SessionStorage: make(map[string]string),
		Authenticated:  true,
		CreatedAt:      time.Now(),
	}
	
	// Extract cookies
	cookies, err := b.context.Cookies()
	if err == nil {
		for _, cookie := range cookies {
			session.Cookies[cookie.Name] = cookie.Value
		}
	}
	
	// Extract localStorage
	localStorageData, err := b.page.Evaluate("() => JSON.stringify(localStorage)")
	if err == nil {
		if localStr, ok := localStorageData.(string); ok {
			// Parse JSON manually or use a simple approach
			session.LocalStorage["_raw"] = localStr
		}
	}
	
	// Extract sessionStorage
	sessionStorageData, err := b.page.Evaluate("() => JSON.stringify(sessionStorage)")
	if err == nil {
		if sessStr, ok := sessionStorageData.(string); ok {
			session.SessionStorage["_raw"] = sessStr
		}
	}
	
	// Set User-Agent
	session.UserAgent = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
	
	return session, nil
}
