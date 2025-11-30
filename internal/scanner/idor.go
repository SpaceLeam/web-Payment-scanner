package scanner

import (
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/SpaceLeam/web-Payment-scanner/internal/models"
	"github.com/SpaceLeam/web-Payment-scanner/internal/utils"
)

// TestIDOR tests for Insecure Direct Object References
func TestIDOR(endpoint models.Endpoint, session *models.Session) []models.Vulnerability {
	vulns := make([]models.Vulnerability, 0)
	
	// Look for IDs in URL
	// e.g. /api/orders/12345
	idRegex := regexp.MustCompile(`\/(\d+)(\/|$)`)
	matches := idRegex.FindStringSubmatch(endpoint.URL)
	
	if len(matches) > 1 {
		originalIDStr := matches[1]
		originalID, _ := strconv.Atoi(originalIDStr)
		
		// Test IDs: +1, -1
		testIDs := []int{originalID + 1, originalID - 1}
		
		client := utils.NewHTTPClient(10 * time.Second)
		
		for _, testID := range testIDs {
			// Construct new URL
			newURL := strings.Replace(endpoint.URL, originalIDStr, fmt.Sprintf("%d", testID), 1)
			
			req, _ := http.NewRequest(endpoint.Method, newURL, nil)
			
			// Add auth
			for k, v := range session.Cookies {
				req.AddCookie(&http.Cookie{Name: k, Value: v})
			}
			
			resp, err := client.Do(req)
			if err != nil {
				continue
			}
			defer resp.Body.Close()
			
			// Analysis
			// If we get 200 OK and data looks valid (not an error page), it might be IDOR
			// Ideally we compare response length/structure with original
			if resp.StatusCode == 200 {
				vulns = append(vulns, models.Vulnerability{
					Type:        "IDOR",
					Severity:    "HIGH",
					Title:       "Potential IDOR Detected",
					Description: fmt.Sprintf("Accessed resource ID %d (original: %d) successfully.", testID, originalID),
					Endpoint:    newURL,
					Method:      endpoint.Method,
					Timestamp:   time.Now(),
				})
			}
		}
	}
	
	return vulns
}
