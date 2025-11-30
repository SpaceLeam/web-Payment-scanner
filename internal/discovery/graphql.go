package discovery

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/SpaceLeam/web-Payment-scanner/internal/models"
	"github.com/SpaceLeam/web-Payment-scanner/internal/utils"
)

// GraphQLScanner discovers GraphQL endpoints
type GraphQLScanner struct {
	BaseURL string
	Client  *http.Client
	logger  *utils.Logger
}

// NewGraphQLScanner creates a new scanner
func NewGraphQLScanner(baseURL string) *GraphQLScanner {
	return &GraphQLScanner{
		BaseURL: baseURL,
		Client:  utils.NewHTTPClient(10 * time.Second),
		logger:  utils.NewLogger(true),
	}
}

// Discover finds GraphQL endpoints
func (g *GraphQLScanner) Discover() ([]models.Endpoint, error) {
	endpoints := []models.Endpoint{}
	
	// Common GraphQL paths
	commonPaths := []string{
		"/graphql",
		"/api/graphql",
		"/v1/graphql",
		"/query",
		"/api",
		"/gql",
		"/playground",
		"/graphiql",
		"/console",
	}
	
	for _, path := range commonPaths {
		url := g.BaseURL + path
		
		// Test for GraphQL endpoint with introspection query
		introspectionQuery := map[string]string{
			"query": `query { __schema { types { name } } }`,
		}
		
		jsonData, _ := json.Marshal(introspectionQuery)
		req, _ := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
		req.Header.Set("Content-Type", "application/json")
		
		resp, err := g.Client.Do(req)
		if err != nil {
			continue
		}
		
		// Check if it's a GraphQL endpoint
		if resp.StatusCode == 200 {
			bodyBytes := make([]byte, 4096)
			n, _ := resp.Body.Read(bodyBytes)
			resp.Body.Close()
			body := string(bodyBytes[:n])
			
			// Look for GraphQL signatures
			if strings.Contains(body, "__schema") || strings.Contains(body, "__type") || strings.Contains(body, "data") {
				g.logger.Success("GraphQL endpoint found: %s", url)
				
				endpoints = append(endpoints, models.Endpoint{
					URL:          url,
					Method:       "POST",
					Type:         "graphql",
					Source:       "graphql_discovery",
					DiscoveredAt: time.Now(),
				})
			}
		} else {
			resp.Body.Close()
		}
	}
	
	return endpoints, nil
}
