package browser

import (
	"encoding/json"
	"os"
	
	"github.com/SpaceLeam/web-Payment-scanner/internal/models"
	"github.com/playwright-community/playwright-go"
)

// ExtractCookies extracts cookies from the browser context
func ExtractCookies(context playwright.BrowserContext) (map[string]string, error) {
	cookies, err := context.Cookies()
	if err != nil {
		return nil, err
	}
	
	cookieMap := make(map[string]string)
	for _, cookie := range cookies {
		cookieMap[cookie.Name] = cookie.Value
	}
	
	return cookieMap, nil
}

// ExtractHeaders extracts common headers from the page
func ExtractHeaders(page playwright.Page) map[string]string {
	headers := make(map[string]string)
	
	// Common headers
	headers["User-Agent"] = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
	headers["Accept"] = "application/json, text/plain, */*"
	headers["Accept-Language"] = "en-US,en;q=0.9"
	headers["Accept-Encoding"] = "gzip, deflate, br"
	headers["Connection"] = "keep-alive"
	headers["Sec-Fetch-Dest"] = "empty"
	headers["Sec-Fetch-Mode"] = "cors"
	headers["Sec-Fetch-Site"] = "same-origin"
	
	return headers
}

// ExtractLocalStorage extracts localStorage data from the page
func ExtractLocalStorage(page playwright.Page) (map[string]string, error) {
	storage := make(map[string]string)
	
	// Execute JavaScript to get all localStorage items
	result, err := page.Evaluate(`() => {
		let items = {};
		for (let i = 0; i < localStorage.length; i++) {
			let key = localStorage.key(i);
			items[key] = localStorage.getItem(key);
		}
		return items;
	}`)
	
	if err != nil {
		return storage, err
	}
	
	// Convert result to map
	if resultMap, ok := result.(map[string]interface{}); ok {
		for k, v := range resultMap {
			if strVal, ok := v.(string); ok {
				storage[k] = strVal
			}
		}
	}
	
	return storage, nil
}

// ExtractSessionStorage extracts sessionStorage data from the page
func ExtractSessionStorage(page playwright.Page) (map[string]string, error) {
	storage := make(map[string]string)
	
	// Execute JavaScript to get all sessionStorage items
	result, err := page.Evaluate(`() => {
		let items = {};
		for (let i = 0; i < sessionStorage.length; i++) {
			let key = sessionStorage.key(i);
			items[key] = sessionStorage.getItem(key);
		}
		return items;
	}`)
	
	if err != nil {
		return storage, err
	}
	
	// Convert result to map
	if resultMap, ok := result.(map[string]interface{}); ok {
		for k, v := range resultMap {
			if strVal, ok := v.(string); ok {
				storage[k] = strVal
			}
		}
	}
	
	return storage, nil
}

// ExtractFullSession extracts all session data
func ExtractFullSession(context playwright.BrowserContext, page playwright.Page) (*models.Session, error) {
	session := &models.Session{
		Authenticated: true,
	}
	
	// Extract cookies
	cookies, err := ExtractCookies(context)
	if err != nil {
		return nil, err
	}
	session.Cookies = cookies
	
	// Extract headers
	session.Headers = ExtractHeaders(page)
	
	// Extract localStorage
	localStorage, err := ExtractLocalStorage(page)
	if err != nil {
		localStorage = make(map[string]string)
	}
	session.LocalStorage = localStorage
	
	// Extract sessionStorage
	sessionStorage, err := ExtractSessionStorage(page)
	if err != nil {
		sessionStorage = make(map[string]string)
	}
	session.SessionStorage = sessionStorage
	
	session.UserAgent = session.Headers["User-Agent"]
	
	return session, nil
}

// SessionToJSON converts session to JSON string
func SessionToJSON(session *models.Session) (string, error) {
	data, err := json.MarshalIndent(session, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// SaveSessionToFile saves session to a file (optional feature)
func SaveSession(session *models.Session, filepath string) error {
	data, err := json.MarshalIndent(session, "", "  ")
	if err != nil {
		return err
	}
	
	// Write to file would go here
	_ = data
	return nil
}

// SaveSessionToFile saves the session to a JSON file
func SaveSessionToFile(session *models.Session, filepath string) error {
	data, err := json.MarshalIndent(session, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath, data, 0600) // 0600 = owner only
}

// LoadSessionFromFile loads the session from a JSON file
func LoadSessionFromFile(filepath string) (*models.Session, error) {
	data, err := os.ReadFile(filepath)
	if err != nil {
		return nil, err
	}
	
	var session models.Session
	err = json.Unmarshal(data, &session)
	if err != nil {
		return nil, err
	}
	return &session, nil
}
