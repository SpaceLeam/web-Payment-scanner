package browser

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/SpaceLeam/web-Payment-scanner/internal/models"
	"github.com/playwright-community/playwright-go"
)

// WSMessage represents a WebSocket message
type WSMessage struct {
	Direction string                 // "sent" or "received"
	Timestamp time.Time
	Type      string                 // text, binary, ping, pong, close
	Data      string
	Parsed    map[string]interface{} // JSON parsed if possible
}

// WSInterceptor captures WebSocket traffic
type WSInterceptor struct {
	messages []WSMessage
	mu       sync.RWMutex // Changed to RWMutex for read/write operations
	active   bool
	wsURL    string // NEW: Track WebSocket URL for security checks
}

// NewWSInterceptor creates a new WebSocket interceptor
func NewWSInterceptor() *WSInterceptor {
	return &WSInterceptor{
		messages: make([]WSMessage, 0),
		active:   false,
	}
}

// Enable starts intercepting WebSocket traffic
func (wsi *WSInterceptor) Enable(page playwright.Page) error {
	wsi.active = true
	
	// Inject WebSocket interceptor via CDP (Chrome DevTools Protocol) or JS shim
	// This captures all WebSocket frames
	_, err := page.Evaluate(`() => {
		// Store original WebSocket
		if (window._wsInterceptorInjected) return;
		const OriginalWebSocket = window.WebSocket;
		
		// Create interceptor
		window.WebSocket = function(url, protocols) {
			console.log('[WS] New connection:', url);
			
			// Create real WebSocket
			const ws = new OriginalWebSocket(url, protocols);
			
			// Store reference globally
			window._ws = ws;
			window._wsURL = url; // Store URL
			window._wsConnected = false;
			
			// Intercept send
			const originalSend = ws.send.bind(ws);
			ws.send = function(data) {
				// console.log('[WS] SEND:', data);
				window._lastWSSend = {
					timestamp: Date.now(),
					data: data
				};
				return originalSend(data);
			};
			
			// Intercept receive
			ws.addEventListener('message', function(event) {
				// console.log('[WS] RECV:', event.data);
				window._lastWSRecv = {
					timestamp: Date.now(),
					data: event.data
				};
			});
			
			// Track connection state
			ws.addEventListener('open', () => {
				console.log('[WS] Connected');
				window._wsConnected = true;
			});
			
			ws.addEventListener('close', () => {
				console.log('[WS] Disconnected');
				window._wsConnected = false;
			});
			
			ws.addEventListener('error', (err) => {
				console.log('[WS] Error:', err);
			});
			
			return ws;
		};
		
		// Copy static properties
		window.WebSocket.CONNECTING = OriginalWebSocket.CONNECTING;
		window.WebSocket.OPEN = OriginalWebSocket.OPEN;
		window.WebSocket.CLOSING = OriginalWebSocket.CLOSING;
		window.WebSocket.CLOSED = OriginalWebSocket.CLOSED;
		window.WebSocket.prototype = OriginalWebSocket.prototype;
		
		window._wsInterceptorInjected = true;
	}`)
	
	if err != nil {
		return fmt.Errorf("failed to inject WS interceptor: %w", err)
	}
	
	// Extract WebSocket URL if connection already exists
	if urlInfo, err := page.Evaluate(`() => window._wsURL || ''`); err == nil {
		if url, ok := urlInfo.(string); ok && url != "" {
			wsi.wsURL = url
		}
	}
	
	// Start polling for messages
	go wsi.pollMessages(page)
	
	return nil
}

// pollMessages continuously polls for new WebSocket messages
func (wsi *WSInterceptor) pollMessages(page playwright.Page) {
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	
	for wsi.active {
		<-ticker.C
		
		// Check if page is closed
		if page.IsClosed() {
			wsi.active = false
			return
		}

		// Get sent messages
		if sent, err := page.Evaluate(`() => {
			const msg = window._lastWSSend;
			window._lastWSSend = null;
			return msg;
		}`); err == nil && sent != nil {
			if msgMap, ok := sent.(map[string]interface{}); ok {
				wsi.addMessage("sent", msgMap)
			}
		}
		
		// Get received messages
		if recv, err := page.Evaluate(`() => {
			const msg = window._lastWSRecv;
			window._lastWSRecv = null;
			return msg;
		}`); err == nil && recv != nil {
			if msgMap, ok := recv.(map[string]interface{}); ok {
				wsi.addMessage("received", msgMap)
			}
		}
	}
}

func (wsi *WSInterceptor) addMessage(direction string, msgMap map[string]interface{}) {
	wsi.mu.Lock()
	defer wsi.mu.Unlock()
	
	dataStr := ""
	if data, ok := msgMap["data"].(string); ok {
		dataStr = data
	}
	
	msg := WSMessage{
		Direction: direction,
		Timestamp: time.Now(),
		Type:      "text",
		Data:      dataStr,
	}
	
	// Try parse JSON
	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(dataStr), &parsed); err == nil {
		msg.Parsed = parsed
	}
	
	wsi.messages = append(wsi.messages, msg)
}

// Stop stops the interceptor
func (wsi *WSInterceptor) Stop() {
	wsi.active = false
}

// GetMessages returns all captured messages
func (wsi *WSInterceptor) GetMessages() []WSMessage {
	wsi.mu.Lock()
	defer wsi.mu.Unlock()
	
	// Return copy
	messages := make([]WSMessage, len(wsi.messages))
	copy(messages, wsi.messages)
	return messages
}

// GetPaymentMessages filters messages related to payment
func (wsi *WSInterceptor) GetPaymentMessages() []WSMessage {
	wsi.mu.Lock()
	defer wsi.mu.Unlock()
	
	var paymentMsgs []WSMessage
	for _, msg := range wsi.messages {
		if isPaymentMessage(msg) {
			paymentMsgs = append(paymentMsgs, msg)
		}
	}
	return paymentMsgs
}

func isPaymentMessage(msg WSMessage) bool {
	if msg.Parsed == nil {
		// Check string
		keywords := []string{"payment", "pay", "transaction", "amount", "status", "confirm", "balance"}
		for _, kw := range keywords {
			if contains(msg.Data, kw) {
				return true
			}
		}
		return false
	}
	
	// Check JSON keys
	for key := range msg.Parsed {
		keywords := []string{"payment", "transaction", "amount", "status", "balance"}
		for _, kw := range keywords {
			if contains(key, kw) {
				return true
			}
		}
	}
	return false
}

// GetConnectionInfo returns current WebSocket connection details
func (wsi *WSInterceptor) GetConnectionInfo(page playwright.Page) map[string]interface{} {
	info, err := page.Evaluate(`() => {
		return {
			url: window._wsURL || '',
			connected: window._wsConnected || false,
			readyState: window._ws?.readyState || -1,
			protocol: window._ws?.protocol || '',
			extensions: window._ws?.extensions || ''
		};
	}`)
	
	if err != nil {
		return nil
	}
	
	if infoMap, ok := info.(map[string]interface{}); ok {
		return infoMap
	}
	
	return nil
}

// ExtractSessionToken attempts to extract session token from WS messages
func (wsi *WSInterceptor) ExtractSessionToken() string {
	wsi.mu.Lock()
	defer wsi.mu.Unlock()
	
	for _, msg := range wsi.messages {
		if msg.Parsed != nil {
			// Common token field names
			tokenFields := []string{"token", "session_token", "sessionToken", "auth_token", "authToken", "access_token"}
			for _, field := range tokenFields {
				if token, ok := msg.Parsed[field].(string); ok && token != "" {
					return token
				}
			}
		}
	}
	
	return ""
}

// PrintSummary prints a summary of captured WebSocket traffic
func (wsi *WSInterceptor) PrintSummary() {
	wsi.mu.Lock()
	defer wsi.mu.Unlock()
	
	fmt.Printf("\n[WebSocket Traffic Summary]\n")
	fmt.Printf("Total messages: %d\n", len(wsi.messages))
	
	sent := 0
	recv := 0
	for _, msg := range wsi.messages {
		if msg.Direction == "sent" {
			sent++
		} else {
			recv++
		}
	}
	
	fmt.Printf("Sent: %d | Received: %d\n", sent, recv)
	
	// Show last 5 messages
	fmt.Printf("\nLast 5 messages:\n")
	start := len(wsi.messages) - 5
	if start < 0 {
		start = 0
	}
	
	for i := start; i < len(wsi.messages); i++ {
		msg := wsi.messages[i]
		direction := "←"
		if msg.Direction == "sent" {
			direction = "→"
		}
		
		preview := msg.Data
		if len(preview) > 60 {
			preview = preview[:60] + "..."
		}
		
		fmt.Printf("%s [%s] %s\n", direction, msg.Timestamp.Format("15:04:05"), preview)
	}
}


// CheckSecurity performs security analysis on WebSocket connection
func (wsi *WSInterceptor) CheckSecurity() []models.Vulnerability {
	wsi.mu.Lock()
	defer wsi.mu.Unlock()
	
	vulns := []models.Vulnerability{}
	
	// 1. WSS vs WS check (Cleartext Transmission)
	if wsi.wsURL != "" && strings.HasPrefix(wsi.wsURL, "ws://") {
		vulns = append(vulns, models.Vulnerability{
			Type:        "WebSocket Security",
			Severity:    "HIGH",
			Title:       "Unencrypted WebSocket Connection (ws://)",
			Description: "WebSocket connection uses unencrypted ws:// protocol instead of secure wss://. This exposes payment data in transit.",
			Endpoint:    wsi.wsURL,
			Proof:       fmt.Sprintf("WebSocket URL: %s", wsi.wsURL),
			Timestamp:   time.Now(),
			CWE:         "CWE-319", // Cleartext Transmission of Sensitive Information
			CVSSScore:   7.5,
			CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
			Confidence:  "High",
			Remediation: `Use WSS (wss://) instead of WS (ws://) for all WebSocket connections:

// JavaScript example:
const ws = new WebSocket('wss://example.com/socket'); // Secure
// NOT: const ws = new WebSocket('ws://example.com/socket'); // Insecure`,
			References: []string{
				"https://cwe.mitre.org/data/definitions/319.html",
				"https://owasp.org/www-community/vulnerabilities/Insecure_Transport",
			},
		})
	}
	
	// 2. Check authentication token presence in messages
	hasAuth := false
	for _, msg := range wsi.messages {
		if containsAuthToken(msg) {
			hasAuth = true
			break
		}
	}
	
	if len(wsi.messages) > 0 && !hasAuth {
		vulns = append(vulns, models.Vulnerability{
			Type:        "WebSocket Authentication",
			Severity:    "HIGH",
			Title:       "WebSocket Messages Missing Authentication Token",
			Description: "WebSocket messages do not contain authentication tokens. This could allow unauthorized access to payment operations.",
			Proof:       fmt.Sprintf("Analyzed %d messages, none contain auth tokens", len(wsi.messages)),
			Timestamp:   time.Now(),
			CWE:         "CWE-306", // Missing Authentication for Critical Function
			CVSSScore:   8.1,
			CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
			Confidence:  "Medium",
			Remediation: `Include authentication token in WebSocket messages:

// JavaScript example:
ws.send(JSON.stringify({
    action: 'payment.create',
    token: sessionToken, // Authentication token
    amount: 100
}));`,
			References: []string{
				"https://cwe.mitre.org/data/definitions/306.html",
			},
		})
	}
	
	// 3. Check message size (buffer overflow risk)
	const maxMessageSize = 10 * 1024 * 1024 // 10MB
	for _, msg := range wsi.messages {
		if len(msg.Data) > maxMessageSize {
			vulns = append(vulns, models.Vulnerability{
				Type:        "WebSocket Message Size",
				Severity:    "MEDIUM",
				Title:       "Excessive WebSocket Message Size",
				Description: fmt.Sprintf("WebSocket message exceeds safe size limit (%d bytes > 10MB). This could indicate lack of server-side validation.", len(msg.Data)),
				Proof:       fmt.Sprintf("Message size: %d bytes at %s", len(msg.Data), msg.Timestamp.Format(time.RFC3339)),
				Timestamp:   time.Now(),
				CWE:         "CWE-770", // Allocation of Resources Without Limits
				CVSSScore:   5.3,
				CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
				Confidence:  "Low",
				Remediation: "Implement message size validation on server (max 10MB recommended)",
			})
			break // Only report once
		}
	}
	
	// 4. Check for message injection without session
	// (This would require actually testing, not just analyzing intercepted traffic)
	// Leaving as TODO for future enhancement
	
	return vulns
}

// GetWebSocketURL returns the current WebSocket URL
func (wsi *WSInterceptor) GetWebSocketURL() string {
	wsi.mu.RLock()
	defer wsi.mu.RUnlock()
	return wsi.wsURL
}

// SetWebSocketURL sets the WebSocket URL (called when connection detected)
func (wsi *WSInterceptor) SetWebSocketURL(url string) {
	wsi.mu.Lock()
	defer wsi.mu.Unlock()
	wsi.wsURL = url
}

func containsAuthToken(msg WSMessage) bool {
	// Check for common auth token field names
	if msg.Parsed != nil {
		tokenFields := []string{"token", "authToken", "auth_token", "sessionToken", "session_token", "accessToken", "access_token", "jwt", "bearer"}
		for _, field := range tokenFields {
			if _, ok := msg.Parsed[field]; ok {
				return true
			}
		}
	}
	
	// Check in string data
	authKeywords := []string{"token", "authtoken", "sessiontoken", "bearer"}
	dataLower := strings.ToLower(msg.Data)
	for _, kw := range authKeywords {
		if contains(dataLower, kw) {
			return true
		}
	}
	
	return false
}


