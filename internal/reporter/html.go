package reporter

import (
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"time"

	"github.com/SpaceLeam/web-Payment-scanner/internal/models"
)

const htmlTemplate = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Payment Security Scan Report - {{.Target}}</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; line-height: 1.6; color: #333; max-width: 1200px; margin: 0 auto; padding: 20px; background-color: #f5f5f5; }
        .header { background: #fff; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); margin-bottom: 20px; }
        .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 20px; }
        .card { background: #fff; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .vuln-card { background: #fff; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); margin-bottom: 15px; border-left: 5px solid #ccc; }
        .severity-CRITICAL { border-left-color: #d32f2f; }
        .severity-HIGH { border-left-color: #f57c00; }
        .severity-MEDIUM { border-left-color: #fbc02d; }
        .severity-LOW { border-left-color: #388e3c; }
        h1, h2, h3 { margin-top: 0; }
        .badge { display: inline-block; padding: 4px 8px; border-radius: 4px; color: #fff; font-weight: bold; font-size: 0.8em; }
        .bg-CRITICAL { background-color: #d32f2f; }
        .bg-HIGH { background-color: #f57c00; }
        .bg-MEDIUM { background-color: #fbc02d; }
        .bg-LOW { background-color: #388e3c; }
        code { background: #f0f0f0; padding: 2px 5px; border-radius: 3px; font-family: monospace; }
        pre { background: #f0f0f0; padding: 10px; border-radius: 5px; overflow-x: auto; }
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 10px; text-align: left; border-bottom: 1px solid #eee; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ Payment Security Scan Report</h1>
        <p><strong>Target:</strong> {{.Target}}</p>
        <p><strong>Date:</strong> {{.StartTime.Format "Jan 02, 2006 15:04:05"}}</p>
        <p><strong>Duration:</strong> {{.Duration}}</p>
    </div>

    <div class="summary">
        <div class="card">
            <h3>Endpoints Scanned</h3>
            <h1>{{len .Endpoints}}</h1>
        </div>
        <div class="card">
            <h3>Vulnerabilities Found</h3>
            <h1>{{len .Vulnerabilities}}</h1>
        </div>
    </div>

    <h2>🚨 Vulnerabilities</h2>
    {{range .Vulnerabilities}}
    <div class="vuln-card severity-{{.Severity}}">
        <h3><span class="badge bg-{{.Severity}}">{{.Severity}}</span> {{.Type}}</h3>
        <p><strong>Endpoint:</strong> <code>{{.Method}} {{.Endpoint}}</code></p>
        <p>{{.Description}}</p>
        {{if .Payload}}
        <h4>Payload:</h4>
        <pre>{{.Payload}}</pre>
        {{end}}
    </div>
    {{else}}
    <div class="card">
        <p>✅ No vulnerabilities found.</p>
    </div>
    {{end}}

    <h2>🔍 Discovered Endpoints</h2>
    <div class="card">
        <table>
            <thead>
                <tr>
                    <th>Method</th>
                    <th>URL</th>
                    <th>Type</th>
                    <th>Source</th>
                </tr>
            </thead>
            <tbody>
                {{range .Endpoints}}
                <tr>
                    <td>{{.Method}}</td>
                    <td>{{.URL}}</td>
                    <td>{{.Type}}</td>
                    <td>{{.Source}}</td>
                </tr>
                {{end}}
            </tbody>
        </table>
    </div>
</body>
</html>
`

// GenerateHTMLReport generates an HTML report
func GenerateHTMLReport(result models.ScanResult, outputDir string) (string, error) {
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return "", err
	}
	
	timestamp := time.Now().Format("20060102_150405")
	filename := filepath.Join(outputDir, fmt.Sprintf("scan_report_%s.html", timestamp))
	
	tmpl, err := template.New("report").Parse(htmlTemplate)
	if err != nil {
		return "", err
	}
	
	file, err := os.Create(filename)
	if err != nil {
		return "", err
	}
	defer file.Close()
	
	if err := tmpl.Execute(file, result); err != nil {
		return "", err
	}
	
	return filename, nil
}
