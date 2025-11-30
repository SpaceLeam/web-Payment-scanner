package models

import "time"

// ScanConfig holds the configuration for a security scan
type ScanConfig struct {
	// Target configuration
	LoginURL    string
	TargetURL   string
	PaymentURL  string
	Domain      string
	
	// Browser settings
	Browser       string        // "firefox", "chromium", "webkit"
	Headless      bool
	BrowserTimeout time.Duration
	
	// Scan settings
	ConcurrentReqs int
	Timeout        time.Duration
	MaxDepth       int
	WordlistPath   string
	AutoDiscovery  bool
	
	// Test selection
	EnableRaceCondition      bool
	EnablePriceManipulation  bool
	EnableIDOR               bool
	EnableOTPSecurity        bool
	EnableCallbackAuth       bool
	EnableAmountValidation   bool
	EnableIdempotency        bool
	
	// Discovery settings
	EnableCrawl       bool
	EnableWayback     bool
	EnableCommonPaths bool
	EnableJSAnalysis  bool
	
	// Output settings
	OutputDir     string
	ReportFormats []string // "json", "html", "console"
	Verbose       bool
}

// Session represents an authenticated browser session
type Session struct {
	Cookies       map[string]string
	Headers       map[string]string
	LocalStorage  map[string]string
	SessionStorage map[string]string
	
	// WebSocket session support
	WebSocketURL   string
	SessionToken   string
	URLToken       string  // Token from URL path
	
	Authenticated bool
	UserAgent     string
	CreatedAt     time.Time
}

// Endpoint represents a discovered API endpoint or page
type Endpoint struct {
	URL         string
	Method      string            // GET, POST, PUT, DELETE, etc.
	Type        string            // "payment", "checkout", "order", "webhook", etc.
	Parameters  map[string]string
	Headers     map[string]string
	Body        string
	Source      string            // "crawl", "wayback", "wordlist", "js_analysis"
	DiscoveredAt time.Time
}

// Vulnerability represents a discovered security vulnerability
type Vulnerability struct {
	ID          string
	Type        string    // "Race Condition", "Price Manipulation", etc.
	Severity    string    // "CRITICAL", "HIGH", "MEDIUM", "LOW"
	Title       string
	Description string
	Endpoint    string
	Method      string
	Proof       string    // Evidence/PoC
	Impact      string
	Remediation string
	CVSSScore   float64
	CVSS        string    // CVSS vector string
	Timestamp   time.Time
	Verified    bool
	
	// Additional details
	Request  string
	Response string
	Payload  string
}

// ScanResult represents the complete results of a security scan
type ScanResult struct {
	ScanID      string
	Target      string
	StartTime   time.Time
	EndTime     time.Time
	Duration    time.Duration
	
	// Discovery results
	EndpointsFound     int
	Endpoints          []Endpoint
	
	// Testing results
	VulnerabilitiesFound int
	Vulnerabilities      []Vulnerability
	VulnsBySeverity      map[string]int // "CRITICAL": 2, "HIGH": 5, etc.
	
	// Statistics
	RequestsSent       int
	ResponsesReceived  int
	ErrorsEncountered  int
	TestsRun           int
	
	// Configuration used
	Config ScanConfig
}

// TestResult represents the result of a single vulnerability test
type TestResult struct {
	TestName    string
	Endpoint    string
	Success     bool
	Vulnerable  bool
	Details     string
	Evidence    string
	Duration    time.Duration
	Error       error
}

// ScanProgress tracks the progress of an ongoing scan
type ScanProgress struct {
	Phase           string  // "discovery", "testing", "verification", "reporting"
	CurrentTask     string
	TotalEndpoints  int
	TestedEndpoints int
	FoundVulns      int
	Progress        float64 // 0.0 to 100.0
}
