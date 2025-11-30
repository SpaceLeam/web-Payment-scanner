package discovery

import (
	"regexp"
	"strings"
	"time"

	"github.com/SpaceLeam/web-Payment-scanner/internal/browser"
	"github.com/SpaceLeam/web-Payment-scanner/internal/models"
	"github.com/SpaceLeam/web-Payment-scanner/internal/utils"
)

// JSAnalyzer scans JavaScript files for endpoints
type JSAnalyzer struct {
	Browser *browser.Browser
	logger  *utils.Logger
}

// NewJSAnalyzer creates a new JS analyzer
func NewJSAnalyzer(br *browser.Browser) *JSAnalyzer {
	return &JSAnalyzer{
		Browser: br,
		logger:  utils.NewLogger(true),
	}
}

// AnalyzePage scans the current page's loaded JS files for API endpoints
func (j *JSAnalyzer) AnalyzePage() ([]models.Endpoint, error) {
	j.logger.Info("Analyzing JavaScript files on current page...")
	
	// Get all script src
	page := j.Browser.GetPage()
	result, err := page.Evaluate(`() => {
		return Array.from(document.scripts)
			.map(s => s.src)
			.filter(src => src && src.length > 0);
	}`)
	
	if err != nil {
		return nil, err
	}
	
	var scripts []string
	if list, ok := result.([]interface{}); ok {
		for _, item := range list {
			if s, ok := item.(string); ok {
				scripts = append(scripts, s)
			}
		}
	}
	
	endpoints := make([]models.Endpoint, 0)
	client := utils.NewHTTPClient(10 * time.Second)
	
	// Regex for finding endpoints/paths
	// Looks for strings starting with / or http, followed by path chars
	// This is a heuristic and may produce false positives
	pathRegex := regexp.MustCompile(`["'](\/[a-zA-Z0-9_\-\/]+|https?:\/\/[^"']+)["']`)
	
	for _, scriptURL := range scripts {
		// Only analyze scripts from same domain or CDN?
		// For now, analyze all
		
		j.logger.Debug("Fetching script: %s", scriptURL)
		resp, err := client.Get(scriptURL)
		if err != nil {
			continue
		}
		
		body, err := utils.ReadResponseBody(resp)
		if err != nil {
			continue
		}
		
		content := string(body)
		matches := pathRegex.FindAllStringSubmatch(content, -1)
		
		for _, match := range matches {
			if len(match) > 1 {
				path := match[1]
				
				// Filter out common false positives
				if isFalsePositive(path) {
					continue
				}
				
				// If it looks like an API endpoint
				if utils.IsPaymentRelated(path) || strings.Contains(path, "/api/") {
					endpoints = append(endpoints, models.Endpoint{
						URL:          path, // Note: might be relative
						Method:       "GET", // Assumption
						Type:         "js_extracted",
						Source:       "js_analysis",
						DiscoveredAt: time.Now(),
					})
				}
			}
		}
	}
	
	j.logger.Success("JS Analysis found %d potential endpoints", len(endpoints))
	return endpoints, nil
}

func isFalsePositive(path string) bool {
	// Filter out common non-endpoint strings
	common := []string{
		"application/json", "text/html", "use strict",
		".js", ".css", ".png", ".jpg", ".svg", ".woff",
		"//", "http://www.w3.org",
	}
	
	for _, c := range common {
		if strings.Contains(path, c) {
			return true
		}
	}
	
	if len(path) < 4 { // Too short
		return true
	}
	
	return false
}
