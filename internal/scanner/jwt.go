package scanner

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/SpaceLeam/web-Payment-scanner/internal/models"
	"github.com/SpaceLeam/web-Payment-scanner/internal/utils"
)

// TestJWTVulnerabilities tests JWT security issues
func TestJWTVulnerabilities(endpoint models.Endpoint, session *models.Session) []models.Vulnerability {
	vulns := []models.Vulnerability{}
	
	// Find JWT token in session
	jwtToken := findJWTToken(session)
	if jwtToken == "" {
		return vulns // No JWT found
	}
	
	// Test 1: Algorithm confusion (alg: none)
	vulns = append(vulns, testJWTAlgNone(endpoint, session, jwtToken)...)
	
	// Test 2: Weak secret
	vulns = append(vulns, testJWTWeakSecret(endpoint, session, jwtToken)...)
	
	// Test 3: Token expiration not validated
	vulns = append(vulns, testJWTExpiration(endpoint, session, jwtToken)...)
	
	// Test 4: Claims manipulation
	vulns = append(vulns, testJWTClaimsManipulation(endpoint, session, jwtToken)...)
	
	return vulns
}

func findJWTToken(session *models.Session) string {
	// Check headers
	for k, v := range session.Headers {
		if strings.ToLower(k) == "authorization" && strings.HasPrefix(v, "Bearer ") {
			return strings.TrimPrefix(v, "Bearer ")
		}
	}
	
	// Check cookies
	for _, v := range session.Cookies {
		if strings.Count(v, ".") == 2 && len(v) > 50 {
			// Looks like JWT (header.payload.signature)
			return v
		}
	}
	
	// Check session token
	if session.SessionToken != "" && strings.Count(session.SessionToken, ".") == 2 {
		return session.SessionToken
	}
	
	return ""
}

func testJWTAlgNone(endpoint models.Endpoint, session *models.Session, token string) []models.Vulnerability {
	vulns := []models.Vulnerability{}
	
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return vulns
	}
	
	// Decode header
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return vulns
	}
	
	var header map[string]interface{}
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return vulns
	}
	
	// Change algorithm to "none"
	header["alg"] = "none"
	newHeaderJSON, _ := json.Marshal(header)
	newHeader := base64.RawURLEncoding.EncodeToString(newHeaderJSON)
	
	// Create token with no signature
	manipulatedToken := newHeader + "." + parts[1] + "."
	
	// Test with manipulated token
	client := utils.NewHTTPClient(10 * time.Second)
	req, _ := http.NewRequest(endpoint.Method, endpoint.URL, nil)
	req.Header.Set("Authorization", "Bearer "+manipulatedToken)
	
	resp, err := client.Do(req)
	if err != nil {
		return vulns
	}
	defer resp.Body.Close()
	
	if resp.StatusCode == 200 {
		vulns = append(vulns, models.Vulnerability{
			Type:        "JWT Algorithm Confusion",
			Severity:    "CRITICAL",
			Title:       "JWT 'alg: none' Vulnerability",
			Description: "Server accepts JWT tokens with 'alg: none', allowing complete authentication bypass",
			Endpoint:    endpoint.URL,
			Method:      endpoint.Method,
			Proof:       "Token with alg=none and no signature was accepted",
			Payload:     manipulatedToken,
			Timestamp:   time.Now(),
			CWE:         "CWE-347",
			CVSSScore:   10.0,
			CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
			Confidence:  "High",
			Impact:      "Complete authentication bypass - attacker can forge any token",
			Remediation: `Reject 'alg: none' tokens:

// Go example with jwt-go:
token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
    // Validate algorithm
    if token.Method.Alg() == "none" {
        return nil, errors.New("alg none not allowed")
    }
    
    // Only allow expected algorithms
    if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
        return nil, fmt.Errorf("unexpected algorithm: %v", token.Header["alg"])
    }
    
    return []byte(secret), nil
})`,
			References: []string{
				"https://cwe.mitre.org/data/definitions/347.html",
				"https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/",
			},
		})
	}
	
	return vulns
}

func testJWTWeakSecret(endpoint models.Endpoint, session *models.Session, token string) []models.Vulnerability {
	vulns := []models.Vulnerability{}
	
	// Common weak secrets to test
	weakSecrets := []string{
		"secret", "password", "12345", "admin", "jwt",
		"secret123", "password123", "your-256-bit-secret",
	}
	
	// Note: Full implementation would need actual JWT verification
	// This is a simplified version showing the concept
	_ = weakSecrets
	
	return vulns
}

func testJWTExpiration(endpoint models.Endpoint, session *models.Session, token string) []models.Vulnerability {
	vulns := []models.Vulnerability{}
	
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return vulns
	}
	
	// Decode payload
	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return vulns
	}
	
	var payload map[string]interface{}
	if err := json.Unmarshal(payloadJSON, &payload); err != nil {
		return vulns
	}
	
	// Set expiration to past (1 year ago)
	payload["exp"] = time.Now().Add(-365 * 24 * time.Hour).Unix()
	
	newPayloadJSON, _ := json.Marshal(payload)
	newPayload := base64.RawURLEncoding.EncodeToString(newPayloadJSON)
	
	// Keep original signature (won't match, but test if exp is checked)
	expiredToken := parts[0] + "." + newPayload + "." + parts[2]
	
	client := utils.NewHTTPClient(10 * time.Second)
	req, _ := http.NewRequest(endpoint.Method, endpoint.URL, nil)
	req.Header.Set("Authorization", "Bearer "+expiredToken)
	
	resp, err := client.Do(req)
	if err != nil {
		return vulns
	}
	defer resp.Body.Close()
	
	// If signature verification fails first, we won't see exp issue
	// But if exp is not checked before signature, server might process it
	if resp.StatusCode != 401 && resp.StatusCode != 403 {
		vulns = append(vulns, models.Vulnerability{
			Type:        "JWT Expiration",
			Severity:    "HIGH",
			Title:       "JWT Expiration Not Validated",
			Description: "Server does not properly validate JWT expiration time",
			Endpoint:    endpoint.URL,
			Method:      endpoint.Method,
			Proof:       "Token expired 1 year ago was not rejected with proper error",
			Timestamp:   time.Now(),
			CWE:         "CWE-613",
			CVSSScore:   7.5,
			CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
			Confidence:  "Medium",
			Remediation: "Always validate exp claim in JWT verification",
			References: []string{
				"https://cwe.mitre.org/data/definitions/613.html",
			},
		})
	}
	
	return vulns
}

func testJWTClaimsManipulation(endpoint models.Endpoint, session *models.Session, token string) []models.Vulnerability {
	vulns := []models.Vulnerability{}
	
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return vulns
	}
	
	// Decode payload
	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return vulns
	}
	
	var payload map[string]interface{}
	if err := json.Unmarshal(payloadJSON, &payload); err != nil {
		return vulns
	}
	
	// Try privilege escalation
	privilegeFields := []string{"role", "admin", "is_admin", "permissions", "scope"}
	
	for _, field := range privilegeFields {
		if _, exists := payload[field]; exists {
			// Modify to admin
			originalValue := payload[field]
			payload[field] = "admin"
			
			newPayloadJSON, _ := json.Marshal(payload)
			newPayload := base64.RawURLEncoding.EncodeToString(newPayloadJSON)
			
			// Create token (signature won't match)
			manipulatedToken := parts[0] + "." + newPayload + "." + parts[2]
			
			client := utils.NewHTTPClient(10 * time.Second)
			req, _ := http.NewRequest(endpoint.Method, endpoint.URL, nil)
			req.Header.Set("Authorization", "Bearer "+manipulatedToken)
			
			resp, err := client.Do(req)
			if err != nil {
				continue
			}
			defer resp.Body.Close()
			
			// If accepted (shouldn't be due to signature)
			if resp.StatusCode == 200 {
				vulns = append(vulns, models.Vulnerability{
					Type:        "JWT Claims Manipulation",
					Severity:    "CRITICAL",
					Title:       "JWT Claims Can Be Manipulated",
					Description: fmt.Sprintf("Modified JWT claim '%s' from '%v' to 'admin' and was accepted", field, originalValue),
					Endpoint:    endpoint.URL,
					Method:      endpoint.Method,
					Proof:       fmt.Sprintf("Claim %s modified, token accepted", field),
					Timestamp:   time.Now(),
					CWE:         "CWE-347",
					CVSSScore:   9.8,
					CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
					Confidence:  "High",
					Impact:      "Privilege escalation - regular users can gain admin access",
					Remediation: "Always verify JWT signature before trusting claims",
				})
			}
			
			// Restore original value
			payload[field] = originalValue
		}
	}
	
	return vulns
}
