package reporter

import (
	"fmt"
	"os"
	"sort"

	"github.com/SpaceLeam/web-Payment-scanner/internal/models"
	"github.com/fatih/color"
	"github.com/olekukonko/tablewriter"
)

// PrintConsoleSummary prints a summary to the console
func PrintConsoleSummary(result models.ScanResult) {
	fmt.Println()
	color.Cyan("═══════════════════════════════════════════════════════════")
	color.Cyan("  SCAN SUMMARY")
	color.Cyan("═══════════════════════════════════════════════════════════")
	fmt.Println()
	
	fmt.Printf("Target:   %s\n", result.Target)
	fmt.Printf("Duration: %s\n", result.Duration)
	fmt.Printf("Endpoints: %d\n", len(result.Endpoints))
	fmt.Printf("Vulns:     %d\n", len(result.Vulnerabilities))
	fmt.Println()
	
	if len(result.Vulnerabilities) > 0 {
		color.Red("🚨 VULNERABILITIES FOUND:")
		fmt.Println()
		
		table := tablewriter.NewWriter(os.Stdout)
		table.SetHeader([]string{"Severity", "Type", "Endpoint", "Description"})
		table.SetBorder(false)
		table.SetHeaderColor(
			tablewriter.Colors{tablewriter.Bold, tablewriter.FgWhiteColor},
			tablewriter.Colors{tablewriter.Bold, tablewriter.FgWhiteColor},
			tablewriter.Colors{tablewriter.Bold, tablewriter.FgWhiteColor},
			tablewriter.Colors{tablewriter.Bold, tablewriter.FgWhiteColor},
		)
		
		// Sort by severity
		sort.Slice(result.Vulnerabilities, func(i, j int) bool {
			return severityWeight(result.Vulnerabilities[i].Severity) > severityWeight(result.Vulnerabilities[j].Severity)
		})
		
		for _, v := range result.Vulnerabilities {
			severityColor := tablewriter.Colors{}
			switch v.Severity {
			case "CRITICAL":
				severityColor = tablewriter.Colors{tablewriter.Bold, tablewriter.FgRedColor}
			case "HIGH":
				severityColor = tablewriter.Colors{tablewriter.FgRedColor}
			case "MEDIUM":
				severityColor = tablewriter.Colors{tablewriter.FgYellowColor}
			case "LOW":
				severityColor = tablewriter.Colors{tablewriter.FgGreenColor}
			}
			
			table.Rich([]string{v.Severity, v.Type, v.Endpoint, truncate(v.Description, 50)}, []tablewriter.Colors{
				severityColor,
				{},
				{},
				{},
			})
		}
		table.Render()
	} else {
		color.Green("✅ No vulnerabilities found.")
	}
	
	fmt.Println()
}

func severityWeight(severity string) int {
	switch severity {
	case "CRITICAL":
		return 4
	case "HIGH":
		return 3
	case "MEDIUM":
		return 2
	case "LOW":
		return 1
	default:
		return 0
	}
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
