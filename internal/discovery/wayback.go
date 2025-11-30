package discovery

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/SpaceLeam/web-Payment-scanner/internal/models"
	"github.com/SpaceLeam/web-Payment-scanner/internal/utils"
)

// WaybackMachine handles querying the Wayback Machine API
type WaybackMachine struct {
	Client *http.Client
	logger *utils.Logger
}

// NewWaybackMachine creates a new Wayback Machine client
func NewWaybackMachine() *WaybackMachine {
	return &WaybackMachine{
		Client: utils.NewHTTPClient(30 * time.Second),
		logger: utils.NewLogger(true),
	}
}

// Search queries the Wayback Machine for URLs matching the domain
func (w *WaybackMachine) Search(domain string) ([]models.Endpoint, error) {
	w.logger.Info("Querying Wayback Machine for %s...", domain)
	
	// CDX API URL
	// Filter for status 200 and collapse by urlkey to reduce duplicates
	apiURL := fmt.Sprintf("http://web.archive.org/cdx/search/cdx?url=%s/*&output=json&fl=original,mimetype,statuscode&filter=statuscode:200&collapse=urlkey", domain)
	
	resp, err := w.Client.Get(apiURL)
	if err != nil {
		return nil, fmt.Errorf("failed to query wayback machine: %w", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("wayback machine returned status %d", resp.StatusCode)
	}
	
	var results [][]string
	if err := json.NewDecoder(resp.Body).Decode(&results); err != nil {
		return nil, fmt.Errorf("failed to decode wayback response: %w", err)
	}
	
	endpoints := make([]models.Endpoint, 0)
	
	// Skip header row (index 0)
	if len(results) > 0 {
		results = results[1:]
	}
	
	for _, row := range results {
		if len(row) < 1 {
			continue
		}
		
		urlStr := row[0]
		
		// Filter relevant endpoints (payment, api, etc)
		if utils.IsPaymentRelated(urlStr) || isInteresting(urlStr) {
			endpoints = append(endpoints, models.Endpoint{
				URL:          urlStr,
				Method:       "GET", // Assumption
				Type:         determineType(urlStr),
				Source:       "wayback",
				DiscoveredAt: time.Now(),
			})
		}
	}
	
	w.logger.Success("Wayback Machine found %d potential endpoints", len(endpoints))
	return endpoints, nil
}

func isInteresting(urlStr string) bool {
	interesting := []string{"api", "v1", "v2", "graphql", "admin", "dashboard"}
	for _, i := range interesting {
		if utils.IsPaymentRelated(urlStr) { // Already checked but good for completeness
			return true
		}
		if contains(urlStr, i) {
			return true
		}
	}
	return false
}

func determineType(urlStr string) string {
	if utils.IsPaymentRelated(urlStr) {
		return "payment_related"
	}
	return "unknown"
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 || 
		(len(s) > 0 && len(substr) > 0 && findSubstring(s, substr)))
}

func findSubstring(s, substr string) bool {
	// Simple implementation
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
