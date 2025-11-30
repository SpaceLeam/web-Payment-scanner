package scanner

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/SpaceLeam/web-Payment-scanner/internal/models"
	"github.com/SpaceLeam/web-Payment-scanner/internal/utils"
)

// TestGraphQLVulnerabilities tests GraphQL-specific vulnerabilities
func TestGraphQLVulnerabilities(endpoint models.Endpoint, session *models.Session) []models.Vulnerability {
	vulns := []models.Vulnerability{}
	
	// Test 1: Introspection enabled (CRITICAL in production)
	vulns = append(vulns, testGraphQLIntrospection(endpoint, session)...)
	
	// Test 2: No depth limit (DoS)
	vulns = append(vulns, testGraphQLDepthLimit(endpoint, session)...)
	
	// Test 3: Batch query attack
	vulns = append(vulns, testGraphQLBatchAttack(endpoint, session)...)
	
	// Test 4: Field duplication (resource exhaustion)
	vulns = append(vulns, testGraphQLFieldDuplication(endpoint, session)...)
	
	// Test 5: Authorization bypass
	vulns = append(vulns, testGraphQLAuthBypass(endpoint, session)...)
	
	return vulns
}

func testGraphQLIntrospection(endpoint models.Endpoint, session *models.Session) []models.Vulnerability {
	vulns := []models.Vulnerability{}
	
	// Full introspection query
	query := map[string]string{
		"query": `
			query IntrospectionQuery {
				__schema {
					queryType { name }
					mutationType { name }
					types {
						kind
						name
						description
					}
				}
			}
		`,
	}
	
	jsonData, _ := json.Marshal(query)
	client := utils.NewHTTPClient(10 * time.Second)
	
	req, _ := http.NewRequest("POST", endpoint.URL, bytes.NewBuffer(jsonData))
	req.Header.Set("Content-Type", "application/json")
	addAuthHeaders(req, session)
	
	resp, err := client.Do(req)
	if err != nil {
		return vulns
	}
	defer resp.Body.Close()
	
	if resp.StatusCode == 200 {
		bodyBytes := make([]byte, 8192)
		n, _ := resp.Body.Read(bodyBytes)
		body := string(bodyBytes[:n])
		
		// Check if introspection succeeded
		if strings.Contains(body, "queryType") || strings.Contains(body, "mutationType") {
			vulns = append(vulns, models.Vulnerability{
				Type:        "GraphQL Introspection",
				Severity:    "HIGH",
				Title:       "GraphQL Introspection Enabled in Production",
				Description: "GraphQL introspection is enabled, allowing attackers to enumerate the entire API schema including sensitive queries and mutations.",
				Endpoint:    endpoint.URL,
				Method:      "POST",
				Proof:       "Introspection query succeeded and returned full schema",
				Timestamp:   time.Now(),
				CWE:         "CWE-200",
				CVSSScore:   7.5,
				CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
				Confidence:  "High",
				Impact:      "Attackers can map entire API surface, discover hidden queries, and plan targeted attacks",
				Remediation: `Disable introspection in production:

// Go example with gqlgen:
srv := handler.NewDefaultServer(generated.NewExecutableSchema(generated.Config{Resolvers: &graph.Resolver{}}))
if os.Getenv("ENV") == "production" {
    srv.Use(extension.Introspection{})
}`,
				References: []string{
					"https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html",
					"https://cwe.mitre.org/data/definitions/200.html",
				},
			})
		}
	}
	
	return vulns
}

func testGraphQLDepthLimit(endpoint models.Endpoint, session *models.Session) []models.Vulnerability {
	vulns := []models.Vulnerability{}
	
	// Create deeply nested query (20 levels)
	deepQuery := `
		query DeepNesting {
			user {
				posts {
					comments {
						author {
							posts {
								comments {
									author {
										posts {
											comments {
												author {
													posts {
														comments {
															author {
																posts {
																	comments {
																		author {
																			id
																		}
																	}
																}
															}
														}
													}
												}
											}
										}
									}
								}
							}
						}
					}
				}
			}
		}
	`
	
	query := map[string]string{"query": deepQuery}
	jsonData, _ := json.Marshal(query)
	
	client := utils.NewHTTPClient(30 * time.Second)
	req, _ := http.NewRequest("POST", endpoint.URL, bytes.NewBuffer(jsonData))
	req.Header.Set("Content-Type", "application/json")
	addAuthHeaders(req, session)
	
	startTime := time.Now()
	resp, err := client.Do(req)
	duration := time.Since(startTime)
	
	if err != nil {
		return vulns
	}
	defer resp.Body.Close()
	
	// If query succeeds or takes very long = vulnerability
	if resp.StatusCode == 200 || duration > 10*time.Second {
		vulns = append(vulns, models.Vulnerability{
			Type:        "GraphQL DoS",
			Severity:    "CRITICAL",
			Title:       "GraphQL Query Depth Not Limited",
			Description: fmt.Sprintf("GraphQL accepts deeply nested queries (20 levels) which can cause severe performance degradation. Query took %v to execute.", duration),
			Endpoint:    endpoint.URL,
			Method:      "POST",
			Proof:       fmt.Sprintf("20-level nested query executed in %v", duration),
			Timestamp:   time.Now(),
			CWE:         "CWE-770",
			CVSSScore:   7.5,
			CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
			Confidence:  "High",
			Impact:      "Attackers can exhaust server resources with complex queries, causing DoS",
			Remediation: "Implement query depth limiting (max 10-15 levels recommended)",
			References: []string{
				"https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html#query-limiting-depth",
				"https://cwe.mitre.org/data/definitions/770.html",
			},
		})
	}
	
	return vulns
}

func testGraphQLBatchAttack(endpoint models.Endpoint, session *models.Session) []models.Vulnerability {
	vulns := []models.Vulnerability{}
	
	// Create batch query with 100 identical queries
	batchQueries := make([]map[string]string, 100)
	for i := 0; i < 100; i++ {
		batchQueries[i] = map[string]string{
			"query": fmt.Sprintf(`query Query%d { __typename }`, i),
		}
	}
	
	jsonData, _ := json.Marshal(batchQueries)
	client := utils.NewHTTPClient(30 * time.Second)
	
	req, _ := http.NewRequest("POST", endpoint.URL, bytes.NewBuffer(jsonData))
	req.Header.Set("Content-Type", "application/json")
	addAuthHeaders(req, session)
	
	startTime := time.Now()
	resp, err := client.Do(req)
	duration := time.Since(startTime)
	
	if err != nil {
		return vulns
	}
	defer resp.Body.Close()
	
	if resp.StatusCode == 200 {
		vulns = append(vulns, models.Vulnerability{
			Type:        "GraphQL Batch Attack",
			Severity:    "HIGH",
			Title:       "GraphQL Batch Queries Not Limited",
			Description: fmt.Sprintf("Server accepted 100 batched queries in a single request (executed in %v). This can be exploited for amplification attacks.", duration),
			Endpoint:    endpoint.URL,
			Method:      "POST",
			Proof:       fmt.Sprintf("Sent 100 batched queries, all processed in %v", duration),
			Timestamp:   time.Now(),
			CWE:         "CWE-799",
			CVSSScore:   6.5,
			CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
			Confidence:  "High",
			Remediation: "Limit batch query size to maximum 10-20 queries per request",
		})
	}
	
	return vulns
}

func testGraphQLFieldDuplication(endpoint models.Endpoint, session *models.Session) []models.Vulnerability {
	vulns := []models.Vulnerability{}
	
	// Create query with 1000 duplicate fields
	duplicatedFields := strings.Repeat("__typename\n", 1000)
	query := fmt.Sprintf(`query { %s }`, duplicatedFields)
	
	payload := map[string]string{"query": query}
	jsonData, _ := json.Marshal(payload)
	
	client := utils.NewHTTPClient(30 * time.Second)
	req, _ := http.NewRequest("POST", endpoint.URL, bytes.NewBuffer(jsonData))
	req.Header.Set("Content-Type", "application/json")
	addAuthHeaders(req, session)
	
	resp, err := client.Do(req)
	if err != nil {
		return vulns
	}
	defer resp.Body.Close()
	
	if resp.StatusCode == 200 {
		vulns = append(vulns, models.Vulnerability{
			Type:        "GraphQL Field Duplication",
			Severity:    "MEDIUM",
			Title:       "GraphQL Field Duplication Not Limited",
			Description: "Server accepted query with 1000 duplicate fields, which can cause excessive memory usage and CPU consumption.",
			Endpoint:    endpoint.URL,
			Method:      "POST",
			Proof:       "Query with 1000 duplicate __typename fields was processed",
			Timestamp:   time.Now(),
			CWE:         "CWE-1333",
			CVSSScore:   5.3,
			CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
			Confidence:  "Medium",
			Remediation: "Implement field count limits and query complexity analysis",
		})
	}
	
	return vulns
}

func testGraphQLAuthBypass(endpoint models.Endpoint, session *models.Session) []models.Vulnerability {
	vulns := []models.Vulnerability{}
	
	// Test accessing sensitive queries without auth
	sensitiveQueries := []string{
		`query { users { id email } }`,
		`query { payments { id amount } }`,
		`mutation { deleteUser(id: 1) { success } }`,
	}
	
	client := utils.NewHTTPClient(10 * time.Second)
	
	for _, queryStr := range sensitiveQueries {
		payload := map[string]string{"query": queryStr}
		jsonData, _ := json.Marshal(payload)
		
		req, _ := http.NewRequest("POST", endpoint.URL, bytes.NewBuffer(jsonData))
		req.Header.Set("Content-Type", "application/json")
		// NO AUTH HEADERS!
		
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		
		if resp.StatusCode == 200 {
			bodyBytes := make([]byte, 4096)
			n, _ := resp.Body.Read(bodyBytes)
			resp.Body.Close()
			body := string(bodyBytes[:n])
			
			// If we get data (not just errors), it's a vulnerability
			if !strings.Contains(body, "Unauthorized") && !strings.Contains(body, "Forbidden") {
				vulns = append(vulns, models.Vulnerability{
					Type:        "GraphQL Authorization Bypass",
					Severity:    "CRITICAL",
					Title:       "GraphQL Query Accessible Without Authentication",
					Description: fmt.Sprintf("Sensitive query executed without authentication: %s", queryStr),
					Endpoint:    endpoint.URL,
					Method:      "POST",
					Proof:       fmt.Sprintf("Query: %s returned data without auth", queryStr),
					Timestamp:   time.Now(),
					CWE:         "CWE-306",
					CVSSScore:   9.1,
					CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
					Confidence:  "High",
					Remediation: "Implement field-level authorization in resolvers",
				})
				break
			}
		} else {
			resp.Body.Close()
		}
	}
	
	return vulns
}
