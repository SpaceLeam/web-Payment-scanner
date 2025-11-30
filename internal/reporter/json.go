package reporter

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/SpaceLeam/web-Payment-scanner/internal/models"
)

// GenerateJSONReport generates a JSON report
func GenerateJSONReport(result models.ScanResult, outputDir string) (string, error) {
	// Create output directory if not exists
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return "", err
	}
	
	// Generate filename
	timestamp := time.Now().Format("20060102_150405")
	filename := filepath.Join(outputDir, fmt.Sprintf("scan_report_%s.json", timestamp))
	
	// Marshal to JSON
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return "", err
	}
	
	// Write to file
	if err := os.WriteFile(filename, data, 0644); err != nil {
		return "", err
	}
	
	return filename, nil
}
