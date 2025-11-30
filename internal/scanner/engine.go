package scanner

import (
	"sync"
	"time"

	"github.com/SpaceLeam/web-Payment-scanner/internal/browser"
	"github.com/SpaceLeam/web-Payment-scanner/internal/discovery"
	"github.com/SpaceLeam/web-Payment-scanner/internal/models"
	"github.com/SpaceLeam/web-Payment-scanner/internal/utils"
)

// Engine orchestrates the scanning process
type Engine struct {
	Config    models.ScanConfig
	Session   *models.Session
	Browser   *browser.Browser
	Endpoints []models.Endpoint
	Vulns     []models.Vulnerability
	Logger    *utils.Logger
	mu        sync.Mutex
}

// NewEngine creates a new scanner engine
func NewEngine(config models.ScanConfig, session *models.Session, br *browser.Browser) *Engine {
	return &Engine{
		Config:  config,
		Session: session,
		Browser: br,
		Logger:  utils.NewLogger(config.Verbose),
		Vulns:   make([]models.Vulnerability, 0),
	}
}

// StartDiscovery runs the discovery phase
func (e *Engine) StartDiscovery() error {
	e.Logger.Section("Phase 1: Discovery")
	
	var allEndpoints []models.Endpoint
	var mu sync.Mutex
	var wg sync.WaitGroup
	
	// 1. Crawler
	if e.Config.EnableCrawl {
		wg.Add(1)
		go func() {
			defer wg.Done()
			crawler := discovery.NewCrawler(e.Config.TargetURL, e.Config.MaxDepth, e.Browser)
			eps, err := crawler.Start()
			if err != nil {
				e.Logger.Error("Crawler failed: %v", err)
				return
			}
			mu.Lock()
			allEndpoints = append(allEndpoints, eps...)
			mu.Unlock()
		}()
	}
	
	// 2. Wayback Machine
	if e.Config.EnableWayback {
		wg.Add(1)
		go func() {
			defer wg.Done()
			wb := discovery.NewWaybackMachine()
			eps, err := wb.Search(e.Config.Domain)
			if err != nil {
				e.Logger.Error("Wayback search failed: %v", err)
				return
			}
			mu.Lock()
			allEndpoints = append(allEndpoints, eps...)
			mu.Unlock()
		}()
	}
	
	// 3. Common Paths
	if e.Config.EnableCommonPaths {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// TODO: Make wordlist path configurable
			bf := discovery.NewPathBruteForcer(e.Config.TargetURL, "configs/wordlists/payment_paths.txt")
			eps, err := bf.Start()
			if err != nil {
				e.Logger.Error("Path discovery failed: %v", err)
				return
			}
			mu.Lock()
			allEndpoints = append(allEndpoints, eps...)
			mu.Unlock()
		}()
	}
	
	// 4. JS Analysis
	if e.Config.EnableJSAnalysis {
		// JS analysis needs browser, so run it sequentially or with care
		// For now, let's skip parallel execution for this one or assume browser is thread-safe enough
		// (Browser instance is not thread safe for navigation, so we skip for now or run after)
	}
	
	wg.Wait()
	
	// Deduplicate
	e.Endpoints = discovery.DeduplicateEndpoints(allEndpoints)
	e.Logger.Success("Discovery complete. Found %d unique endpoints.", len(e.Endpoints))
	
	return nil
}

// StartScanning runs the vulnerability scanning phase
func (e *Engine) StartScanning() error {
	e.Logger.Section("Phase 2: Vulnerability Scanning")
	
	// Filter for relevant endpoints
	targetEndpoints := e.filterTargetEndpoints()
	e.Logger.Info("Targeting %d payment-related endpoints", len(targetEndpoints))
	
	for _, ep := range targetEndpoints {
		e.Logger.Info("Scanning %s (%s)", ep.URL, ep.Type)
		
		// Race Condition
		if e.Config.EnableRaceCondition {
			vulns := TestRaceCondition(ep, e.Session, e.Config.ConcurrentReqs)
			e.addVulnerabilities(vulns)
		}
		
		// Price Manipulation
		if e.Config.EnablePriceManipulation {
			vulns := TestPriceManipulation(ep, e.Session)
			e.addVulnerabilities(vulns)
		}
		
		// IDOR
		if e.Config.EnableIDOR {
			vulns := TestIDOR(ep, e.Session)
			e.addVulnerabilities(vulns)
		}
	}
	
	return nil
}

func (e *Engine) filterTargetEndpoints() []models.Endpoint {
	var targets []models.Endpoint
	for _, ep := range e.Endpoints {
		if utils.IsPaymentRelated(ep.URL) || ep.Type == "payment_page" || ep.Type == "payment_related" {
			targets = append(targets, ep)
		}
	}
	return targets
}

func (e *Engine) addVulnerabilities(vulns []models.Vulnerability) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.Vulns = append(e.Vulns, vulns...)
}

// GetResults returns the scan results
func (e *Engine) GetResults() models.ScanResult {
	return models.ScanResult{
		Target:          e.Config.TargetURL,
		StartTime:       time.Now(), // Should be set at start
		EndTime:         time.Now(),
		Endpoints:       e.Endpoints,
		Vulnerabilities: e.Vulns,
		Config:          e.Config,
	}
}
