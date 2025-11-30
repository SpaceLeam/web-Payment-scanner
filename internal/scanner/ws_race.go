package scanner

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/SpaceLeam/web-Payment-scanner/internal/browser"
	"github.com/SpaceLeam/web-Payment-scanner/internal/models"
	"github.com/playwright-community/playwright-go"
)

// TestWebSocketRaceCondition tests race conditions via WebSocket
func TestWebSocketRaceCondition(page playwright.Page, wsi *browser.WSInterceptor, concurrency int) []models.Vulnerability {
	vulns := make([]models.Vulnerability, 0)
	
	// Get last payment message as template
	paymentMsgs := wsi.GetPaymentMessages()
	if len(paymentMsgs) == 0 {
		return vulns
	}
	
	// Use last sent payment message
	var templateMsg *browser.WSMessage
	for i := len(paymentMsgs) - 1; i >= 0; i-- {
		if paymentMsgs[i].Direction == "sent" {
			templateMsg = &paymentMsgs[i]
			break
		}
	}
	
	if templateMsg == nil {
		return vulns
	}
	
	// Fire concurrent WebSocket messages
	var wg sync.WaitGroup
	startSignal := make(chan struct{})
	results := make(chan bool, concurrency)
	
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-startSignal
			
			// Send message via WS
			success := sendWSMessage(page, templateMsg.Data)
			results <- success
		}()
	}
	
	close(startSignal)
	wg.Wait()
	close(results)
	
	// Analyze
	successCount := 0
	for success := range results {
		if success {
			successCount++
		}
	}
	
	if successCount > 1 {
		vulns = append(vulns, models.Vulnerability{
			Type:        "WebSocket Race Condition",
			Severity:    "CRITICAL",
			Title:       "WebSocket Race Condition",
			Description: fmt.Sprintf("WebSocket accepted %d concurrent identical messages", successCount),
			Proof:       fmt.Sprintf("Template: %s", templateMsg.Data),
			Timestamp:   time.Now(),
		})
	}
	
	return vulns
}

func sendWSMessage(page playwright.Page, data string) bool {
	result, err := page.Evaluate(fmt.Sprintf(`() => {
		if (!window._ws || window._ws.readyState !== 1) {
			return false;
		}
		
		try {
			window._ws.send('%s');
			return true;
		} catch(e) {
			return false;
		}
	}`, escapeJS(data)))
	
	if err != nil {
		return false
	}
	
	if success, ok := result.(bool); ok {
		return success
	}
	
	return false
}

// TestWebSocketReplay tests message replay attacks
func TestWebSocketReplay(page playwright.Page, wsi *browser.WSInterceptor) []models.Vulnerability {
	vulns := make([]models.Vulnerability, 0)
	
	paymentMsgs := wsi.GetPaymentMessages()
	
	for _, msg := range paymentMsgs {
		if msg.Direction == "sent" {
			// Replay the message
			time.Sleep(2 * time.Second) // Delay to simulate replay
			
			success := sendWSMessage(page, msg.Data)
			if success {
				// Check if server accepted it (by monitoring responses)
				time.Sleep(1 * time.Second)
				
				newMsgs := wsi.GetMessages()
				lastMsg := newMsgs[len(newMsgs)-1]
				
				// If we got a success response
				if lastMsg.Direction == "received" && isSuccessResponse(lastMsg) {
					vulns = append(vulns, models.Vulnerability{
						Type:        "WebSocket Replay Attack",
						Severity:    "HIGH",
						Title:       "WebSocket Message Replay Vulnerability",
						Description: "Server accepted replayed WebSocket message",
						Proof:       fmt.Sprintf("Original: %s", msg.Data),
						Timestamp:   time.Now(),
					})
				}
			}
		}
	}
	
	return vulns
}

// TestWebSocketAmountManipulation tests amount manipulation in WS
func TestWebSocketAmountManipulation(page playwright.Page, wsi *browser.WSInterceptor) []models.Vulnerability {
	vulns := make([]models.Vulnerability, 0)
	
	paymentMsgs := wsi.GetPaymentMessages()
	
	for _, msg := range paymentMsgs {
		if msg.Direction == "sent" && msg.Parsed != nil {
			// Find amount field
			amountFields := []string{"amount", "price", "total", "value"}
			
			for _, field := range amountFields {
				if originalAmount, ok := msg.Parsed[field]; ok {
					// Test manipulated amounts
					testAmounts := []interface{}{
						-100.0,
						0.0,
						0.01,
						"0",
					}
					
					for _, testAmount := range testAmounts {
						// Clone and modify
						manipulated := cloneMap(msg.Parsed)
						manipulated[field] = testAmount
						
						manipulatedJSON, _ := json.Marshal(manipulated)
						success := sendWSMessage(page, string(manipulatedJSON))
						
						if success {
							// Wait for response
							time.Sleep(1 * time.Second)
							
							newMsgs := wsi.GetMessages()
							if len(newMsgs) > 0 {
								lastMsg := newMsgs[len(newMsgs)-1]
								
								if lastMsg.Direction == "received" && isSuccessResponse(lastMsg) {
									vulns = append(vulns, models.Vulnerability{
										Type:        "WebSocket Amount Manipulation",
										Severity:    "CRITICAL",
										Title:       fmt.Sprintf("Amount Manipulation Accepted (%v → %v)", originalAmount, testAmount),
										Description: "Server accepted manipulated amount via WebSocket",
										Proof:       fmt.Sprintf("Manipulated message: %s", string(manipulatedJSON)),
										Timestamp:   time.Now(),
									})
									break
								}
							}
						}
					}
					
					break
				}
			}
		}
	}
	
	return vulns
}

func isSuccessResponse(msg browser.WSMessage) bool {
	if msg.Parsed != nil {
		// Check for success indicators
		if status, ok := msg.Parsed["status"].(string); ok {
			successStatuses := []string{"success", "ok", "completed", "paid", "confirmed"}
			for _, s := range successStatuses {
				if status == s {
					return true
				}
			}
		}
		
		if success, ok := msg.Parsed["success"].(bool); ok && success {
			return true
		}
	}
	
	// Check string
	successKeywords := []string{"success", "completed", "confirmed"}
	for _, kw := range successKeywords {
		if contains(msg.Data, kw) {
			return true
		}
	}
	
	return false
}

func cloneMap(original map[string]interface{}) map[string]interface{} {
	clone := make(map[string]interface{})
	for k, v := range original {
		clone[k] = v
	}
	return clone
}

func escapeJS(s string) string {
	// Escape single quotes for JS
	return s // TODO: proper escaping
}
