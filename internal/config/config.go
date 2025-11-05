package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"

	"github.com/joho/godotenv"
)

type Config struct {
	AccountsPath     string
	TwoCaptchaAPIKey string
	CapSolverAPIKey  string
	InviteMin        int
	InviteMax        int
	InviteDelayMin   int
	InviteDelayMax   int
}

type Account struct {
	PrivateKey string `json:"pk"`
}

func Load() Config {
	err := godotenv.Load()
	if err != nil {
		log.Println("No .env file found, using default values")
	}

	inviteMin := parseIntWithDefault(os.Getenv("DAILY_MIN_INVITE"), 1)
	inviteMax := parseIntWithDefault(os.Getenv("DAILY_MAX_INVITE"), inviteMin)
	if inviteMax < inviteMin {
		inviteMax = inviteMin
	}

	delayMinRaw := strings.TrimSpace(os.Getenv("DELAY_MIN_INVITE_MINUTES"))
	delayMaxRaw := strings.TrimSpace(os.Getenv("DELAY_MAX_INVITE_MINUTES"))
	delaySpecified := delayMinRaw != "" || delayMaxRaw != ""

	delayMin := parseIntWithDefault(delayMinRaw, 0)
	delayMax := parseIntWithDefault(delayMaxRaw, delayMin)

	if delayMin < 0 {
		delayMin = 0
	}
	if delayMax < delayMin {
		delayMax = delayMin
	}

	if !delaySpecified {
		delayMin = 1
		delayMax = 5
	}

	return Config{
		AccountsPath:     "configs/accounts.json",
		TwoCaptchaAPIKey: strings.TrimSpace(os.Getenv("TWO_CAPTCHA_API_KEY")),
		CapSolverAPIKey:  strings.TrimSpace(os.Getenv("CAPSOLVER_API_KEY")),
		InviteMin:        inviteMin,
		InviteMax:        inviteMax,
		InviteDelayMin:   delayMin,
		InviteDelayMax:   delayMax,
	}
}

func parseIntWithDefault(value string, defaultVal int) int {
	value = strings.TrimSpace(value)
	if value == "" {
		return defaultVal
	}
	if v, err := strconv.Atoi(value); err == nil && v >= 0 {
		return v
	}
	return defaultVal
}

func (c Config) Validate() error {
	if strings.TrimSpace(c.TwoCaptchaAPIKey) == "" && strings.TrimSpace(c.CapSolverAPIKey) == "" {
		return errors.New("captcha solver API key required (provide TWO_CAPTCHA_API_KEY or CAPSOLVER_API_KEY)")
	}
	return nil
}

func (c Config) LoadAccounts() ([]Account, error) {
	b, err := os.ReadFile(c.AccountsPath)
	if err != nil {
		return nil, err
	}

	var rawAccounts []string
	if err := json.Unmarshal(b, &rawAccounts); err == nil {
		accounts := make([]Account, 0, len(rawAccounts))
		for idx, entry := range rawAccounts {
			pk := strings.TrimSpace(entry)
			if pk == "" {
				return nil, fmt.Errorf("invalid account input: empty private key at index %d", idx)
			}
			accounts = append(accounts, Account{PrivateKey: pk})
		}
		return accounts, nil
	}

	var accounts []Account
	if err := json.Unmarshal(b, &accounts); err != nil {
		return nil, fmt.Errorf("failed to unmarshal accounts: %w", err)
	}

	return accounts, nil
}
