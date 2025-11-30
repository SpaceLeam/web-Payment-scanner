package scanner

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/SpaceLeam/web-Payment-scanner/internal/models"
	"github.com/SpaceLeam/web-Payment-scanner/internal/utils"
)

// TestPaymentSQLInjection tests for SQL injection in payment parameters
func TestPaymentSQLInjection(endpoint models.Endpoint, session *models.Session) []models.Vulnerability {
	vulns := []models.Vulnerability{}
	
	// SQL injection payloads
	sqlPayloads := []struct {
		name    string
		payload string
	}{
		{"Boolean-based blind", "' OR '1'='1"},
		{"Time-based blind", "' AND SLEEP(5)--"},
		{"Union-based", "' UNION SELECT NULL,NULL,NULL--"},
		{"Error-based", "' AND 1=CONVERT(int,(SELECT @@version))--"},
		{"Stacked queries", "'; DROP TABLE orders--"},
		{"PostgreSQL", "' OR 1=1; SELECT pg_sleep(5)--"},
		{"MySQL", "' OR 1=1#"},
		{"MSSQL", "' OR 1=1;--"},
	}
	
	client := utils.NewHTTPClient(15 * time.Second)
	
	for _, sqli := range sqlPayloads {
		// Test in URL parameters
		testURL := endpoint.URL + "?payment_id=" + url.QueryEscape(sqli.payload)
		
		req, _ := http.NewRequest("GET", testURL, nil)
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
		
		// Detection logic
		// 1. Time-based: if SLEEP(5) and duration > 5s
		if strings.Contains(sqli.payload, "SLEEP") && duration > 5*time.Second {
			vulns = append(vulns, models.Vulnerability{
				Type:        "SQL Injection",
				Severity:    "CRITICAL",
				Title:       fmt.Sprintf("Time-based Blind SQL Injection (%s)", sqli.name),
				Description: fmt.Sprintf("SQL injection detected using time-based technique. Payload caused %v delay.", duration),
				Endpoint:    testURL,
				Method:      "GET",
				Payload:     sqli.payload,
				Proof:       fmt.Sprintf("Payload: %s, Duration: %v (expected: >5s)", sqli.payload, duration),
				Timestamp:   time.Now(),
				CWE:         "CWE-89",
				CVSSScore:   9.8,
				CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
				Confidence:  "High",
				Impact:      "Attacker can extract entire database, modify data, or execute arbitrary SQL commands",
				Remediation: `Use parameterized queries (prepared statements):

// Go example with database/sql:
// VULNERABLE:
query := fmt.Sprintf("SELECT * FROM payments WHERE id = '%s'", paymentID)
rows, err := db.Query(query)

// SECURE:
stmt, err := db.Prepare("SELECT * FROM payments WHERE id = ?")
rows, err := stmt.Query(paymentID)

// Or with ORM (GORM):
var payment Payment
db.Where("id = ?", paymentID).First(&payment)`,
				References: []string{
					"https://cwe.mitre.org/data/definitions/89.html",
					"https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
				},
			})
		}
		
		// 2. Error-based: SQL error messages in response
		sqlErrors := []string{
			"SQL syntax",
			"mysql_fetch",
			"PostgreSQL",
			"ORA-",
			"Microsoft SQL",
			"ODBC",
			"SQLite",
			"Unclosed quotation mark",
			"syntax error",
		}
		
		for _, errMsg := range sqlErrors {
			if strings.Contains(body, errMsg) {
				vulns = append(vulns, models.Vulnerability{
					Type:        "SQL Injection",
					Severity:    "CRITICAL",
					Title:       fmt.Sprintf("Error-based SQL Injection (%s)", sqli.name),
					Description: fmt.Sprintf("SQL error message exposed in response: %s", errMsg),
					Endpoint:    testURL,
					Method:      "GET",
					Payload:     sqli.payload,
					Proof:       fmt.Sprintf("Response contains SQL error: %s", errMsg),
					Timestamp:   time.Now(),
					CWE:         "CWE-89",
					CVSSScore:   9.8,
					CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
					Confidence:  "High",
					Remediation: "Use parameterized queries and disable detailed error messages in production",
					References: []string{
						"https://cwe.mitre.org/data/definitions/89.html",
						"https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
					},
				})
				break
			}
		}
	}
	
	return vulns
}
