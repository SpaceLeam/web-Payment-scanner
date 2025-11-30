package discovery

import (
	"github.com/SpaceLeam/web-Payment-scanner/internal/models"
)

// DeduplicateEndpoints removes duplicate endpoints from the list
func DeduplicateEndpoints(endpoints []models.Endpoint) []models.Endpoint {
	seen := make(map[string]bool)
	unique := make([]models.Endpoint, 0)
	
	for _, ep := range endpoints {
		// Create a unique key based on URL and Method
		key := ep.Method + ":" + ep.URL
		
		if !seen[key] {
			seen[key] = true
			unique = append(unique, ep)
		}
	}
	
	return unique
}

// MergeEndpoints merges multiple slices of endpoints and deduplicates them
func MergeEndpoints(endpointSlices ...[]models.Endpoint) []models.Endpoint {
	var allEndpoints []models.Endpoint
	for _, slice := range endpointSlices {
		allEndpoints = append(allEndpoints, slice...)
	}
	return DeduplicateEndpoints(allEndpoints)
}
