package discovery

import (
	"bufio"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/SpaceLeam/web-Payment-scanner/internal/models"
	"github.com/SpaceLeam/web-Payment-scanner/internal/utils"
)

// PathBruteForcer handles common path discovery
type PathBruteForcer struct {
	BaseURL     string
	WordlistPath string
	Client      *http.Client
	logger      *utils.Logger
	concurrency int
}

// NewPathBruteForcer creates a new brute forcer
func NewPathBruteForcer(baseURL, wordlistPath string) *PathBruteForcer {
	return &PathBruteForcer{
		BaseURL:      strings.TrimRight(baseURL, "/"),
		WordlistPath: wordlistPath,
		logger:       utils.NewLogger(true),
		concurrency:  10,
	}
}

// Start begins the brute force process
func (p *PathBruteForcer) Start() ([]models.Endpoint, error) {
	p.logger.Info("Starting common path discovery on %s", p.BaseURL)
	
	paths, err := p.loadWordlist()
	if err != nil {
		return nil, err
	}
	
	p.logger.Info("Loaded %d paths from wordlist", len(paths))
	
	endpoints := make([]models.Endpoint, 0)
	
	// Worker pool
	jobs := make(chan string, len(paths))
	results := make(chan *models.Endpoint, len(paths))
	var wg sync.WaitGroup
	
	// Start workers
	for i := 0; i < p.concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			client := utils.NewHTTPClient(10 * time.Second)
			
			for path := range jobs {
				url := fmt.Sprintf("%s%s", p.BaseURL, path)
				
				// Use HEAD request first for speed
				resp, err := client.Head(url)
				if err != nil {
					// Fallback to GET if HEAD fails (some servers block HEAD)
					resp, err = client.Get(url)
					if err != nil {
						continue
					}
				}
				defer resp.Body.Close()
				
				// Check for valid status codes (200, 401, 403, 302, etc)
				// 404 usually means not found, but sometimes custom 404s exist. 
				// For now, assume 404 is not found.
				if resp.StatusCode != 404 {
					p.logger.Debug("Found: %s [%d]", url, resp.StatusCode)
					
					results <- &models.Endpoint{
						URL:          url,
						Method:       "GET", // Default assumption
						Type:         "common_path",
						Source:       "wordlist",
						DiscoveredAt: time.Now(),
					}
				}
			}
		}()
	}
	
	// Send jobs
	for _, path := range paths {
		jobs <- path
	}
	close(jobs)
	
	// Wait for workers in separate goroutine
	go func() {
		wg.Wait()
		close(results)
	}()
	
	// Collect results
	for ep := range results {
		if ep != nil {
			endpoints = append(endpoints, *ep)
		}
	}
	
	p.logger.Success("Common path discovery found %d endpoints", len(endpoints))
	return endpoints, nil
}

func (p *PathBruteForcer) loadWordlist() ([]string, error) {
	file, err := os.Open(p.WordlistPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open wordlist: %w", err)
	}
	defer file.Close()
	
	var paths []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			if !strings.HasPrefix(line, "/") {
				line = "/" + line
			}
			paths = append(paths, line)
		}
	}
	
	return paths, scanner.Err()
}
