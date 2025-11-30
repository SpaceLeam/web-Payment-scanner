package discovery

import (
	"sync"
	"time"

	"github.com/SpaceLeam/web-Payment-scanner/internal/browser"
	"github.com/SpaceLeam/web-Payment-scanner/internal/models"
	"github.com/SpaceLeam/web-Payment-scanner/internal/utils"
)

// Crawler handles website crawling to discover endpoints
type Crawler struct {
	BaseURL     string
	MaxDepth    int
	Concurrency int
	Browser     *browser.Browser
	visited     sync.Map
	endpoints   []models.Endpoint
	mu          sync.Mutex
	logger      *utils.Logger
}

// NewCrawler creates a new crawler instance
func NewCrawler(baseURL string, maxDepth int, br *browser.Browser) *Crawler {
	return &Crawler{
		BaseURL:     baseURL,
		MaxDepth:    maxDepth,
		Concurrency: 5,
		Browser:     br,
		logger:      utils.NewLogger(true), // Default to verbose for now
		endpoints:   make([]models.Endpoint, 0),
	}
}

// Start begins the crawling process
func (c *Crawler) Start() ([]models.Endpoint, error) {
	c.logger.Info("Starting crawl on %s (Depth: %d)", c.BaseURL, c.MaxDepth)
	
	// Normalize base URL
	baseURL := utils.NormalizeURL(c.BaseURL)
	
	// Start crawling from base URL
	c.crawlURL(baseURL, 0)
	
	return c.endpoints, nil
}

func (c *Crawler) crawlURL(targetURL string, depth int) {
	// Check depth limit
	if depth > c.MaxDepth {
		return
	}
	
	// Check if already visited
	if _, loaded := c.visited.LoadOrStore(targetURL, true); loaded {
		return
	}
	
	c.logger.Debug("Crawling: %s", targetURL)
	
	// Navigate to page
	// Note: In a real concurrent crawler, we'd need multiple browser contexts/pages
	// For this single-browser implementation, we crawl sequentially or need a pool
	err := c.Browser.Navigate(targetURL)
	if err != nil {
		c.logger.Error("Failed to navigate to %s: %v", targetURL, err)
		return
	}
	
	// Add current page as endpoint
	c.addEndpoint(targetURL, "GET", "page")
	
	// Extract links
	links, err := c.extractLinks()
	if err != nil {
		c.logger.Error("Failed to extract links from %s: %v", targetURL, err)
		return
	}
	
	// Process links
	for _, link := range links {
		// Normalize
		link = utils.NormalizeURL(link)
		
		// Only follow links in same domain
		if utils.IsSameDomain(c.BaseURL, link) {
			// Check if payment related
			if utils.IsPaymentRelated(link) {
				c.addEndpoint(link, "GET", "payment_page")
			}
			
			// Recurse
			c.crawlURL(link, depth+1)
		}
	}
}

func (c *Crawler) extractLinks() ([]string, error) {
	page := c.Browser.GetPage()
	
	// Execute JS to get all hrefs
	result, err := page.Evaluate(`() => {
		const links = Array.from(document.querySelectorAll('a'));
		return links.map(a => a.href).filter(href => href.startsWith('http'));
	}`)
	
	if err != nil {
		return nil, err
	}
	
	var links []string
	if linkList, ok := result.([]interface{}); ok {
		for _, l := range linkList {
			if strLink, ok := l.(string); ok {
				links = append(links, strLink)
			}
		}
	}
	
	return links, nil
}

func (c *Crawler) addEndpoint(urlStr, method, eType string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	// Check if payment related if type is generic
	if eType == "page" && utils.IsPaymentRelated(urlStr) {
		eType = "payment_page"
	}
	
	endpoint := models.Endpoint{
		URL:          urlStr,
		Method:       method,
		Type:         eType,
		Source:       "crawl",
		DiscoveredAt: time.Now(),
	}
	
	c.endpoints = append(c.endpoints, endpoint)
}

// Helper to get all discovered endpoints
func (c *Crawler) GetEndpoints() []models.Endpoint {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.endpoints
}
