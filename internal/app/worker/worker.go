package worker

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/ohmynofan/blockstreet-testnet-bot/internal/adapters/chain"
	 adhttp "github.com/ohmynofan/blockstreet-testnet-bot/internal/adapters/http"
	"github.com/ohmynofan/blockstreet-testnet-bot/internal/config"
	"github.com/ohmynofan/blockstreet-testnet-bot/internal/domain/model"
	"github.com/ohmynofan/blockstreet-testnet-bot/internal/platform/logger"
	"github.com/ohmynofan/blockstreet-testnet-bot/internal/storage/signlog"
)

type Worker struct {
	session *model.Session
	store   *signlog.Store
}

const (
	statusWaiting    = "WAITING"
	statusInProgress = "IN PROGRESS"
	statusDone       = "DONE"

	errorRetryDelayMs = 60_000
)

func handleError(worker *Worker, log *logger.ClassLogger, err error) (shouldStop bool) {
	errMsg := err.Error()
	fatalSubstrings := []string{
		"invalid account input",
		"failed to read from seed phrase",
		"invalid private key",
		errNoCaptchaCredit.Error(),
	}

	for _, sub := range fatalSubstrings {
		if strings.Contains(errMsg, sub) {
			if worker != nil && worker.session != nil {
				log.Log(fmt.Sprintf("FATAL: %s. Worker for accounts %d will stop.", errMsg, worker.session.AccIdx+1))
			} else {
				log.Log(fmt.Sprintf("FATAL: %s. Worker will stop.", errMsg), 0)
			}
			return true
		}
	}

	log.Log(fmt.Sprintf("%s, Retrying after 60 seconds", errMsg), errorRetryDelayMs)
	return false
}

func Run(account config.Account, index int, cfg config.Config, store *signlog.Store) {
	accountCfg := cfg

	session := model.Session{Account: account.PrivateKey, AccIdx: index, Address: "-", Role: "primary"}
	session.DailyLoginStatus = statusWaiting
	session.DailyInviteStatus = statusWaiting
	session.DailyShareStatus = statusWaiting
	session.InviteTarget = 0
	session.InviteCompleted = 0
	session.TodayEarn = "0"
	session.TotalEarn = "0"
	session.BalanceEarn = "0"
	cache := &CaptchaCache{}
	worker := Worker{
		session: &session,
		store:   store,
	}
	log := logger.NewNamed(fmt.Sprintf("Operation - Account %d", session.AccIdx+1), &session)

	cookieFile := cookieFilePath(index, account)
	if err := os.MkdirAll(filepath.Dir(cookieFile), 0o755); err != nil {
		log.Log(fmt.Sprintf("FATAL: Could not prepare cookie directory %v", err), 0)
		return
	}

	apiClient, err := adhttp.NewAPIClient("", cookieFile, &session)
	if err != nil {
		log.Log(fmt.Sprintf("FATAL: Could not Initialize API Client %v", err), 0)
		return
	}

	ec, err := chain.New(&session, accountCfg, config.MonadTestnet)
	if err != nil {
		log.Log(fmt.Sprintf("FATAL: Could not establish initial connection: %v", err), 0)
		return
	}
	defer ec.Close()

	if err := ec.ConnectWallet(); err != nil {
		log.Log(fmt.Sprintf("FATAL: Invalid wallet credentials: %v", err), 0)
		return
	}

	for {
		// TODO: re-enable balance fetch when needed for tasks requiring it
		// if err := ec.GetWalletBalance(); err != nil {
		//     ec.Close()
		//     if handleError(&worker, log, err) {
		//         return
		//     }
		//     continue
		// }

		if err := executeBlockStreetOperation(ec, apiClient, log, accountCfg, account, store, &session, creatorInviteCode, cache, false); err != nil {
			ec.Close()
			if handleError(&worker, log, err) {
				return
			}
			continue
		}

		log.Log("Account processing complete. Sleeping for 24 hours...", 86400000)
	}
}

func cookieFilePath(index int, account config.Account) string {
	baseDir := filepath.Join("data", "cookies")
	identifier := fmt.Sprintf("%d", index)
	if account.PrivateKey != "" {
		hash := sha1.Sum([]byte(account.PrivateKey))
		identifier = hex.EncodeToString(hash[:])
	}
	return filepath.Join(baseDir, identifier+".json")
}
