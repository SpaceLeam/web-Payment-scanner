package utils

import (
	"net/url"
	"regexp"
	"strings"
)

// IsValidURL validates if a string is a valid URL
func IsValidURL(rawURL string) bool {
	if rawURL == "" {
		return false
	}
	
	_, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	
	// Check if URL has a scheme
	if !strings.HasPrefix(rawURL, "http://") && !strings.HasPrefix(rawURL, "https://") {
		return false
	}
	
	return true
}

// IsValidDomain validates if a string is a valid domain
func IsValidDomain(domain string) bool {
	if domain == "" {
		return false
	}
	
	// Simple domain regex
	domainRegex := regexp.MustCompile(`^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$`)
	return domainRegex.MatchString(domain)
}

// NormalizeURL normalizes a URL by removing trailing slashes and fragments
func NormalizeURL(rawURL string) string {
	// Remove trailing slash
	rawURL = strings.TrimRight(rawURL, "/")
	
	// Remove fragment
	if idx := strings.Index(rawURL, "#"); idx != -1 {
		rawURL = rawURL[:idx]
	}
	
	return rawURL
}

// ExtractDomain extracts the domain from a URL
func ExtractDomain(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return u.Host
}

// IsSameDomain checks if two URLs belong to the same domain
func IsSameDomain(url1, url2 string) bool {
	return ExtractDomain(url1) == ExtractDomain(url2)
}

// IsPaymentRelated checks if a URL path appears to be payment-related
func IsPaymentRelated(path string) bool {
	paymentKeywords := []string{
		"payment", "checkout", "pay", "order", "cart",
		"transaction", "purchase", "invoice", "billing",
		"subscription", "wallet", "balance",
	}
	
	lowerPath := strings.ToLower(path)
	for _, keyword := range paymentKeywords {
		if strings.Contains(lowerPath, keyword) {
			return true
		}
	}
	
	return false
}

// SanitizeInput removes potentially dangerous characters from user input
func SanitizeInput(input string) string {
	// Remove null bytes
	input = strings.ReplaceAll(input, "\x00", "")
	
	// Trim whitespace
	input = strings.TrimSpace(input)
	
	return input
}

// ValidateHTTPMethod checks if the HTTP method is valid
func ValidateHTTPMethod(method string) bool {
	validMethods := []string{"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}
	method = strings.ToUpper(method)
	
	for _, valid := range validMethods {
		if method == valid {
			return true
		}
	}
	
	return false
}
