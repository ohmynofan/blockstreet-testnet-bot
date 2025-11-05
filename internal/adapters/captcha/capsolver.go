package captcha

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const (
	capsolverBaseURL         = "https://api.capsolver.com"
	capsolverCreateTask      = "/createTask"
	capsolverGetResult       = "/getTaskResult"
	capsolverTurnstileType   = "AntiTurnstileTaskProxyLess"
	capsolverRecaptchaV2Type = "ReCaptchaV2TaskProxyLess"
	defaultPollDelay         = 5 * time.Second
)

type CapSolver struct {
	client       *http.Client
	apiKey       string
	pollInterval time.Duration
}

func NewCapSolver(apiKey string) *CapSolver {
	return &CapSolver{
		client:       &http.Client{Timeout: 30 * time.Second},
		apiKey:       strings.TrimSpace(apiKey),
		pollInterval: defaultPollDelay,
	}
}

type capCreateTaskReq struct {
	ClientKey string      `json:"clientKey"`
	Task      interface{} `json:"task"`
}

type capTurnstileTask struct {
	Type       string `json:"type"`
	WebsiteURL string `json:"websiteURL"`
	WebsiteKey string `json:"websiteKey"`
}

type capRecaptchaTask struct {
	Type        string `json:"type"`
	WebsiteURL  string `json:"websiteURL"`
	WebsiteKey  string `json:"websiteKey"`
	IsInvisible bool   `json:"isInvisible,omitempty"`
}

type capCreateTaskResp struct {
	ErrorCode string `json:"errorCode"`
	TaskID    string `json:"taskId"`
}

type capResultReq struct {
	ClientKey string `json:"clientKey"`
	TaskID    string `json:"taskId"`
}

type capResultResp struct {
	ErrorCode string `json:"errorCode"`
	Status    string `json:"status"`
	Solution  struct {
		Token string `json:"token"`
	} `json:"solution"`
}

func (c *CapSolver) SolveTurnstile(siteKey, pageURL string) (string, error) {
	if c.apiKey == "" {
		return "", errors.New("capsolver api key not provided")
	}
	if strings.TrimSpace(siteKey) == "" {
		return "", errors.New("capsolver site key required")
	}
	if strings.TrimSpace(pageURL) == "" {
		return "", errors.New("capsolver page url required")
	}

	task := capTurnstileTask{
		Type:       capsolverTurnstileType,
		WebsiteURL: pageURL,
		WebsiteKey: siteKey,
	}
	return c.solve(task)
}

func (c *CapSolver) SolveRecaptchaV2(siteKey, pageURL string, invisible bool) (string, error) {
	if c.apiKey == "" {
		return "", errors.New("capsolver api key not provided")
	}
	if strings.TrimSpace(siteKey) == "" {
		return "", errors.New("capsolver site key required")
	}
	if strings.TrimSpace(pageURL) == "" {
		return "", errors.New("capsolver page url required")
	}

	task := capRecaptchaTask{
		Type:        capsolverRecaptchaV2Type,
		WebsiteURL:  pageURL,
		WebsiteKey:  siteKey,
		IsInvisible: invisible,
	}
	return c.solve(task)
}

func (c *CapSolver) solve(task interface{}) (string, error) {
	createPayload := capCreateTaskReq{
		ClientKey: c.apiKey,
		Task:      task,
	}
	var createResp capCreateTaskResp
	if err := c.postJSON(capsolverCreateTask, createPayload, &createResp); err != nil {
		return "", err
	}
	if createResp.ErrorCode != "" {
		if strings.EqualFold(createResp.ErrorCode, CapErrZeroBalance) {
			return "", ErrZeroBalance
		}
		return "", fmt.Errorf("capsolver createTask error: %s", createResp.ErrorCode)
	}
	if strings.TrimSpace(createResp.TaskID) == "" {
		return "", errors.New("capsolver returned empty task id")
	}

	for {
		time.Sleep(c.pollInterval)
		var result capResultResp
		if err := c.postJSON(capsolverGetResult, capResultReq{ClientKey: c.apiKey, TaskID: createResp.TaskID}, &result); err != nil {
			return "", err
		}
		if result.ErrorCode != "" {
			if strings.EqualFold(result.ErrorCode, CapErrZeroBalance) {
				return "", ErrZeroBalance
			}
			return "", fmt.Errorf("capsolver getTaskResult error: %s", result.ErrorCode)
		}
		switch strings.ToLower(strings.TrimSpace(result.Status)) {
		case "processing", "queued":
			continue
		case "ready", "completed":
			if strings.TrimSpace(result.Solution.Token) == "" {
				return "", errors.New("capsolver returned empty token")
			}
			return result.Solution.Token, nil
		default:
			return "", fmt.Errorf("unexpected capsolver status: %s", result.Status)
		}
	}
}

func (c *CapSolver) postJSON(path string, payload interface{}, out interface{}) error {
	endpoint := fmt.Sprintf("%s%s", capsolverBaseURL, path)
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("capsolver encode error: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewBuffer(body))
	if err != nil {
		return fmt.Errorf("capsolver request build error: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	res, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("capsolver http error: %w", err)
	}
	defer res.Body.Close()

	resBody, err := io.ReadAll(res.Body)
	if err != nil {
		return fmt.Errorf("capsolver read error: %w", err)
	}

	if res.StatusCode >= 400 {
		return fmt.Errorf("capsolver status %s body=%s", res.Status, strings.TrimSpace(string(resBody)))
	}

	if err := json.Unmarshal(resBody, out); err != nil {
		return fmt.Errorf("capsolver decode error: %w", err)
	}
	return nil
}
