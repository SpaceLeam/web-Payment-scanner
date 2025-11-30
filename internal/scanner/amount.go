package scanner

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/SpaceLeam/web-Payment-scanner/internal/models"
	"github.com/SpaceLeam/web-Payment-scanner/internal/utils"
)

// TestAmountValidation tests for amount validation vulnerabilities
func TestAmountValidation(endpoint models.Endpoint, session *models.Session) []models.Vulnerability {
	vulns := []models.Vulnerability{}
	
	// Original tests
	vulns = append(vulns, testAmountPrecision(endpoint, session)...)
	vulns = append(vulns, testAmountOverflow(endpoint, session)...)
	
	// P1 Enhanced tests
	vulns = append(vulns, testCurrencyMismatch(endpoint, session)...)
	vulns = append(vulns, testNegativeZero(endpoint, session)...)
	vulns = append(vulns, testScientificNotation(endpoint, session)...)
	vulns = append(vulns, testUnicodeDigits(endpoint, session)...)
	vulns = append(vulns, testFloatingPointPrecision(endpoint, session)...)
	
	return vulns
}

// testCurrencyMismatch tests if server validates currency conversion
func testCurrencyMismatch(endpoint models.Endpoint, session *models.Session) []models.Vulnerability {
	vulns := []models.Vulnerability{}
	
	// Send request with USD but expect system uses IDR
	payload := map[string]interface{}{
		"amount":   100,
		"currency": "USD", // Send USD
		// Server might process as IDR without conversion
	}
	
	payloadJSON, _ := json.Marshal(payload)
	client := utils.NewHTTPClient(10 * time.Second)
	req, _ := http.NewRequest(endpoint.Method, endpoint.URL, bytes.NewBuffer(payloadJSON))
	req.Header.Set("Content-Type", "application/json")
	addAuthHeaders(req, session)
	
	resp, err := client.Do(req)
	if err != nil {
		return vulns
	}
	defer resp.Body.Close()
	
	// If accepted without proper conversion validation
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		vulns = append(vulns, models.Vulnerability{
			Type:        "Amount Validation",
			Severity:    "HIGH",
			Title:       "Currency Mismatch Not Validated",
			Description: "Server may not properly validate currency conversion. Sending $100 USD could be processed as 100 IDR (massive underpayment).",
			Endpoint:    endpoint.URL,
			Method:      endpoint.Method,
			Proof:       fmt.Sprintf("Sent amount=100 currency=USD, received %d (may be processed without conversion)", resp.StatusCode),
			Timestamp:   time.Now(),
			CWE:         "CWE-20", // Improper Input Validation
			CVSSScore:   8.1,
			CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H",
			Confidence:  "Medium",
			Remediation: `Always validate currency matches expected currency:

// Go example:
if request.Currency != expectedCurrency {
    return errors.New("currency mismatch")
}

// Or enforce conversion rate:
if request.Currency == "USD" {
    amountInIDR = request.Amount * exchangeRate["USD_TO_IDR"]
}`,
			References: []string{
				"https://cwe.mitre.org/data/definitions/20.html",
			},
		})
	}
	
	return vulns
}

// testNegativeZero tests if server handles -0.00 correctly
func testNegativeZero(endpoint models.Endpoint, session *models.Session) []models.Vulnerability {
	vulns := []models.Vulnerability{}
	
	// Test negative zero (IEEE 754 allows this)
	payload := map[string]interface{}{
		"amount": -0.00, // Negative zero
	}
	
	payloadJSON, _ := json.Marshal(payload)
	client := utils.NewHTTPClient(10 * time.Second)
	req, _ := http.NewRequest(endpoint.Method, endpoint.URL, bytes.NewBuffer(payloadJSON))
	req.Header.Set("Content-Type", "application/json")
	addAuthHeaders(req, session)
	
	resp, err := client.Do(req)
	if err != nil {
		return vulns
	}
	defer resp.Body.Close()
	
	// Negative zero should be rejected or normalized
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		vulns = append(vulns, models.Vulnerability{
			Type:        "Amount Validation",
			Severity:    "MEDIUM",
			Title:       "Negative Zero Accepted",
			Description: "Server accepts -0.00 which may cause inconsistent behavior in financial calculations",
			Endpoint:    endpoint.URL,
			Method:      endpoint.Method,
			Proof:       "Sent amount=-0.00, received " + strconv.Itoa(resp.StatusCode),
			Timestamp:   time.Now(),
			CWE:         "CWE-682", // Incorrect Calculation
			CVSSScore:   5.3,
			CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
			Confidence:  "Low",
			Remediation: "Reject or normalize negative zero to positive zero",
		})
	}
	
	return vulns
}

// testScientificNotation tests if server properly validates scientific notation
func testScientificNotation(endpoint models.Endpoint, session *models.Session) []models.Vulnerability {
	vulns := []models.Vulnerability{}
	
	// Test cases: 1e10, 1.23e-4, etc.
	testCases := []struct {
		value       string
		description string
	}{
		{"1e10", "10 billion (very large)"},
		{"1e-10", "0.0000000001 (very small)"},
		{"9.999e99", "extremely large number"},
	}
	
	for _, tc := range testCases {
		payload := fmt.Sprintf(`{"amount": %s}`, tc.value)
		
		client := utils.NewHTTPClient(10 * time.Second)
		req, _ := http.NewRequest(endpoint.Method, endpoint.URL, bytes.NewBufferString(payload))
		req.Header.Set("Content-Type", "application/json")
		addAuthHeaders(req, session)
		
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()
		
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			vulns = append(vulns, models.Vulnerability{
				Type:        "Amount Validation",
				Severity:    "MEDIUM",
				Title:       "Scientific Notation Not Validated",
				Description: fmt.Sprintf("Server accepts scientific notation (%s = %s) which may bypass amount validation", tc.value, tc.description),
				Endpoint:    endpoint.URL,
				Method:      endpoint.Method,
				Proof:       fmt.Sprintf("Sent amount=%s, received %d", tc.value, resp.StatusCode),
				Timestamp:   time.Now(),
				CWE:         "CWE-20",
				CVSSScore:   6.5,
				CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",
				Confidence:  "Medium",
				Remediation: "Validate amount format and reject scientific notation in payment amounts",
			})
			break // Only report once
		}
	}
	
	return vulns
}

// testUnicodeDigits tests if server validates unicode digits
func testUnicodeDigits(endpoint models.Endpoint, session *models.Session) []models.Vulnerability {
	vulns := []models.Vulnerability{}
	
	// Unicode digits: ١٢٣ (Arabic), १२३ (Devanagari), 일이삼 (Korean), etc.
	// For simplicity, test fullwidth digits
	unicodeAmount := "１２３" // Fullwidth 123
	normalAmount := "123"
	
	// First check if unicode is normalized to normal digits
	payload := fmt.Sprintf(`{"amount": "%s"}`, unicodeAmount)
	
	client := utils.NewHTTPClient(10 * time.Second)
	req, _ := http.NewRequest(endpoint.Method, endpoint.URL, bytes.NewBufferString(payload))
	req.Header.Set("Content-Type", "application/json")
	addAuthHeaders(req, session)
	
	resp, err := client.Do(req)
	if err != nil {
		return vulns
	}
	defer resp.Body.Close()
	
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		vulns = append(vulns, models.Vulnerability{
			Type:        "Amount Validation",
			Severity:    "MEDIUM",
			Title:       "Unicode Digits Not Normalized",
			Description: fmt.Sprintf("Server accepts unicode digits (%s) which may bypass validation. Could be normalized to %s or cause parsing errors.", unicodeAmount, normalAmount),
			Endpoint:    endpoint.URL,
			Method:      endpoint.Method,
			Proof:       fmt.Sprintf("Sent amount='%s' (unicode), received %d", unicodeAmount, resp.StatusCode),
			Timestamp:   time.Now(),
			CWE:         "CWE-20",
			CVSSScore:   5.3,
			CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
			Confidence:  "Low",
			Remediation: "Normalize unicode digits to ASCII or reject non-ASCII digits in amount fields",
		})
	}
	
	return vulns
}

// testFloatingPointPrecision tests floating point rounding exploits
func testFloatingPointPrecision(endpoint models.Endpoint, session *models.Session) []models.Vulnerability {
	vulns := []models.Vulnerability{}
	
	// Test precision edge cases
	payload := map[string]interface{}{
		"amount": 0.999999999999, // Many 9s, might round to 1.00
	}
	
	payloadJSON, _ := json.Marshal(payload)
	client := utils.NewHTTPClient(10 * time.Second)
	req, _ := http.NewRequest(endpoint.Method, endpoint.URL, bytes.NewBuffer(payloadJSON))
	req.Header.Set("Content-Type", "application/json")
	addAuthHeaders(req, session)
	
	resp, err := client.Do(req)
	if err != nil {
		return vulns
	}
	defer resp.Body.Close()
	
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		vulns = append(vulns, models.Vulnerability{
			Type:        "Amount Validation",
			Severity:    "LOW",
			Title:       "Floating Point Precision Not Validated",
			Description: "Server may have floating point rounding issues. Amount 0.999999999999 could round to 1.00 causing small discrepancies",
			Endpoint:    endpoint.URL,
			Method:      endpoint.Method,
			Proof:       "Sent amount=0.999999999999, received " + strconv.Itoa(resp.StatusCode),
			Timestamp:   time.Now(),
			CWE:         "CWE-682",
			CVSSScore:   3.7,
			CVSSVector:  "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N",
			Confidence:  "Low",
			Remediation: "Use fixed-point arithmetic (integers) for monetary values. Store cents/pence instead of dollars.",
		})
	}
	
	return vulns
}

// Original tests (kept for backward compatibility)
func testAmountPrecision(endpoint models.Endpoint, session *models.Session) []models.Vulnerability {
	// Existing implementation returns empty for now
	return []models.Vulnerability{}
}

func testAmountOverflow(endpoint models.Endpoint, session *models.Session) []models.Vulnerability {
	// Existing implementation returns empty for now
	return []models.Vulnerability{}
}

