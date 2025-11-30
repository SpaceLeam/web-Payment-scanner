package utils

import (
	"crypto/tls"
	"io"
	"net/http"
	"time"
)

// NewHTTPClient creates a new HTTP client with custom settings
func NewHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 100,
			IdleConnTimeout:     90 * time.Second,
			TLSHandshakeTimeout: 10 * time.Second,
			// Allow self-signed certificates for testing
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
		// Don't follow redirects automatically
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// MakeRequest performs an HTTP request with custom headers
func MakeRequest(client *http.Client, method, url string, headers map[string]string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, err
	}
	
	// Set headers
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	
	// Set default headers if not provided
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
	}
	
	return client.Do(req)
}

// MakeRequestWithCookies performs an HTTP request with cookies
func MakeRequestWithCookies(client *http.Client, method, url string, headers, cookies map[string]string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, err
	}
	
	// Set headers
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	
	// Set cookies
	for k, v := range cookies {
		req.AddCookie(&http.Cookie{
			Name:  k,
			Value: v,
		})
	}
	
	// Set default User-Agent if not provided
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
	}
	
	return client.Do(req)
}

// ReadResponseBody reads and closes the response body
func ReadResponseBody(resp *http.Response) ([]byte, error) {
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}
