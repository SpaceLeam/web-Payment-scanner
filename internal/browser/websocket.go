package browser

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"

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
	mu       sync.Mutex
	active   bool
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
			window._wsURL = url;
			
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


