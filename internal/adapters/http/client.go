package http

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Rambeboy/blockstreet-testnet-bot/internal/domain/model"
	"github.com/Rambeboy/blockstreet-testnet-bot/internal/platform/logger"
	"github.com/Rambeboy/blockstreet-testnet-bot/pkg/utils"
)

type HTTPError struct {
	StatusCode int
	Status     string
	Body       []byte
}

func (e *HTTPError) Error() string {
	return fmt.Sprintf("HTTP Error %d: %s", e.StatusCode, e.Status)
}

type FetchOptions struct {
	Method            string
	Token             string
	Body              interface{}
	RawBody           []byte
	AdditionalHeaders map[string]string
}

type APIClient struct {
	Proxy      string
	UserAgent  string
	HTTPClient *http.Client
	Log        *logger.ClassLogger
}

func NewAPIClient(proxy, cookieFile string, session *model.Session) (*APIClient, error) {
	transport := &http.Transport{}

	if proxy != "" {
		proxyURL, err := url.Parse(proxy)
		if err != nil {
			return nil, fmt.Errorf("invalid proxy url: %w", err)
		}
		transport.Proxy = http.ProxyURL(proxyURL)
	}

	jar, err := newFileCookieJar(cookieFile)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize cookie jar: %w", err)
	}

	apiClient := &APIClient{
		Proxy:     proxy,
		UserAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
		HTTPClient: &http.Client{
			Transport: transport,
			Timeout:   120 * time.Second,
			Jar:       jar,
		},
	}
	apiClient.Log = logger.NewLogger(apiClient, session)

	return apiClient, nil
}

func (c *APIClient) HasCookies() bool {
	if jar, ok := c.HTTPClient.Jar.(*fileCookieJar); ok {
		return jar.HasCookies()
	}
	return false
}

func (c *APIClient) ClearCookies() error {
	if jar, ok := c.HTTPClient.Jar.(*fileCookieJar); ok {
		return jar.Clear()
	}
	return nil
}

func (c *APIClient) _generateHeaders(token string) map[string]string {
	headers := map[string]string{
		"Accept":             "application/json, text/plain, */*",
		"Accept-Language":    "en-US,en;q=0.9,id;q=0.8",
		"Content-Type":       "application/json",
		"User-Agent":         c.UserAgent,
		"Cache-Control":      "no-cache",
		"Pragma":             "no-cache",
		"Origin":             "https://blockstreet.money",
		"Referer":            "https://blockstreet.money/",
		"Sec-Ch-Ua":          "\"Google Chrome\";v=\"128\", \"Not?A_Brand\";v=\"8\", \"Chromium\";v=\"128\"",
		"Sec-Ch-Ua-Mobile":   "?0",
		"Sec-Ch-Ua-Platform": "\"macOS\"",
		"Sec-Fetch-Dest":     "empty",
		"Sec-Fetch-Mode":     "cors",
		"Sec-Fetch-Site":     "same-site",
	}
	if token != "" {
		if !strings.HasPrefix(strings.ToLower(token), "bearer ") {
			token = "Bearer " + token
		}
		headers["Authorization"] = token
	}
	return headers
}

func (c *APIClient) Fetch(endpoint string, opts *FetchOptions) (interface{}, error) {
	if opts == nil {
		opts = &FetchOptions{}
	}

	if opts.Method == "" {
		opts.Method = "GET"
	}

	var reqBody io.Reader = nil
	if opts.RawBody != nil && opts.Body != nil {
		return nil, fmt.Errorf("cannot specify both Body and RawBody")
	}

	useRawBody := opts.RawBody != nil
	hasBody := useRawBody || (opts.Method != "GET" && opts.Body != nil)

	if hasBody {
		if useRawBody {
			reqBody = bytes.NewReader(opts.RawBody)
		} else {
			jsonBody, err := json.Marshal(opts.Body)
			if err != nil {
				return nil, fmt.Errorf("failed to marshal request body: %w", err)
			}
			reqBody = bytes.NewBuffer(jsonBody)
		}
	}

	req, err := http.NewRequest(opts.Method, endpoint, reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	baseHeaders := c._generateHeaders(opts.Token)
	for key, value := range baseHeaders {
		req.Header.Set(key, value)
	}
	for key, value := range opts.AdditionalHeaders {
		req.Header.Set(key, value)
	}

	if !hasBody {
		req.Header.Del("Content-Type")
	}

	headerSummary := make(map[string]string, len(req.Header))
	for key, values := range req.Header {
		headerSummary[key] = strings.Join(values, ", ")
	}
	headerJSON, _ := json.MarshalIndent(headerSummary, "", "  ")

	if hasBody {
		bodyCopy, _ := io.ReadAll(req.Body)
		req.Body = io.NopCloser(bytes.NewBuffer(bodyCopy))
		c.Log.JustLog(fmt.Sprintf("%s %s\nHeaders:\n%s\nBody:\n%s", opts.Method, endpoint, string(headerJSON), utils.BeautifyJSON(bodyCopy)))
	} else {
		c.Log.JustLog(fmt.Sprintf("%s %s\nHeaders:\n%s", opts.Method, endpoint, string(headerJSON)))
	}

	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request error: %w", err)
	}
	defer res.Body.Close()

	resBodyBytes, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	c.Log.JustLog(fmt.Sprintf("Response Body:\n%s", utils.BeautifyJSON(resBodyBytes)))

	if res.StatusCode >= 200 && res.StatusCode < 300 {
		var data interface{}
		if strings.Contains(res.Header.Get("Content-Type"), "application/json") {
			if err := json.Unmarshal(resBodyBytes, &data); err == nil {
				return data, nil
			}
		}
		return string(resBodyBytes), nil
	}

	return nil, &HTTPError{
		StatusCode: res.StatusCode,
		Status:     res.Status,
		Body:       resBodyBytes,
	}
}
