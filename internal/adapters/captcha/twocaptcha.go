package captcha

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

const (
	baseURL         = "https://api.2captcha.com"
	createTaskPath  = "/createTask"
	getResultPath   = "/getTaskResult"
	turnstileType   = "TurnstileTaskProxyless"
	recaptchaType   = "RecaptchaV2TaskProxyless"
	defaultPollWait = 5 * time.Second
)

type TwoCaptcha struct {
	client       *http.Client
	apiKey       string
	waitInterval time.Duration
}

func NewTwoCaptcha(apiKey string) *TwoCaptcha {
	return &TwoCaptcha{
		client:       &http.Client{Timeout: 30 * time.Second},
		apiKey:       apiKey,
		waitInterval: defaultPollWait,
	}
}

type createTaskRequest struct {
	ClientKey string      `json:"clientKey"`
	Task      interface{} `json:"task"`
}

type turnstileTask struct {
	Type       string `json:"type"`
	WebsiteURL string `json:"websiteURL"`
	WebsiteKey string `json:"websiteKey"`
}

type recaptchaTask struct {
	Type        string `json:"type"`
	WebsiteURL  string `json:"websiteURL"`
	WebsiteKey  string `json:"websiteKey"`
	IsInvisible bool   `json:"isInvisible,omitempty"`
}

type createTaskResponse struct {
	ErrorID          int    `json:"errorId"`
	TaskID           int64  `json:"taskId"`
	ErrorCode        string `json:"errorCode"`
	ErrorDescription string `json:"errorDescription"`
}

type resultRequest struct {
	ClientKey string `json:"clientKey"`
	TaskID    int64  `json:"taskId"`
}

type getResultResponse struct {
	ErrorID  int    `json:"errorId"`
	Status   string `json:"status"`
	Solution struct {
		Token string `json:"token"`
	} `json:"solution"`
	ErrorCode        string `json:"errorCode"`
	ErrorDescription string `json:"errorDescription"`
}

func (tc *TwoCaptcha) SolveTurnstile(siteKey, pageURL string) (string, error) {
	if tc.apiKey == "" {
		return "", errors.New("2captcha api key not provided")
	}
	if siteKey == "" {
		return "", errors.New("2captcha site key required")
	}
	if pageURL == "" {
		return "", errors.New("2captcha page url required")
	}

	task := turnstileTask{
		Type:       turnstileType,
		WebsiteURL: pageURL,
		WebsiteKey: siteKey,
	}
	return tc.solve(task)
}

func (tc *TwoCaptcha) SolveRecaptchaV2(siteKey, pageURL string, invisible bool) (string, error) {
	if tc.apiKey == "" {
		return "", errors.New("2captcha api key not provided")
	}
	if siteKey == "" {
		return "", errors.New("2captcha site key required")
	}
	if pageURL == "" {
		return "", errors.New("2captcha page url required")
	}

	task := recaptchaTask{
		Type:        recaptchaType,
		WebsiteURL:  pageURL,
		WebsiteKey:  siteKey,
		IsInvisible: invisible,
	}
	return tc.solve(task)
}

func (tc *TwoCaptcha) solve(task interface{}) (string, error) {
	createPayload := createTaskRequest{
		ClientKey: tc.apiKey,
		Task:      task,
	}
	var createResp createTaskResponse
	if err := tc.postJSON(createTaskPath, createPayload, &createResp); err != nil {
		return "", err
	}
	if createResp.ErrorID != 0 {
		if strings.EqualFold(createResp.ErrorCode, TwoErrZeroBalance) {
			return "", ErrZeroBalance
		}
		return "", fmt.Errorf("2captcha createTask error: %s - %s", createResp.ErrorCode, createResp.ErrorDescription)
	}

	for {
		time.Sleep(tc.waitInterval)

		var result getResultResponse
		req := resultRequest{ClientKey: tc.apiKey, TaskID: createResp.TaskID}
		if err := tc.postJSON(getResultPath, req, &result); err != nil {
			return "", err
		}

		if result.ErrorID != 0 {
			if strings.EqualFold(result.ErrorCode, TwoErrZeroBalance) {
				return "", ErrZeroBalance
			}
			return "", fmt.Errorf("2captcha getTaskResult error: %s - %s", result.ErrorCode, result.ErrorDescription)
		}

		switch strings.ToLower(result.Status) {
		case "processing":
			continue
		case "ready":
			if result.Solution.Token == "" {
				return "", errors.New("2captcha returned empty token")
			}
			return result.Solution.Token, nil
		default:
			return "", fmt.Errorf("unexpected 2captcha status: %s", result.Status)
		}
	}
}

func (tc *TwoCaptcha) postJSON(path string, payload interface{}, out interface{}) error {
	endpoint := fmt.Sprintf("%s%s", baseURL, path)
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to encode request: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewBuffer(body))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	res, err := tc.client.Do(req)
	if err != nil {
		return fmt.Errorf("request error: %w", err)
	}
	defer res.Body.Close()

	if res.StatusCode >= 400 {
		return fmt.Errorf("2captcha http error: %s", res.Status)
	}

	if err := json.NewDecoder(res.Body).Decode(out); err != nil {
		return fmt.Errorf("failed to decode response: %w", err)
	}

	return nil
}
