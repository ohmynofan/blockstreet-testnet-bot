package ui

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/pterm/pterm"
	"github.com/ohmynofan/blockstreet-testnet-bot/internal/domain/model"
)

var (
	multi    *pterm.MultiPrinter
	spinners = make(map[int]*pterm.SpinnerPrinter)
	mu       sync.Mutex
)

func StartUISystem() {
	m, _ := pterm.DefaultMultiPrinter.Start()
	multi = m
}

func StopUISystem() {
	if multi != nil {
		multi.Stop()
	}
}

func UpdateStatus(session model.Session, status string, remainingDelay time.Duration) {
	mu.Lock()
	defer mu.Unlock()

	broadcastBalances := formatBalances(session.WalletBalance)
	delayStr := FormatDelay(remainingDelay)
	inviteProgress := fmt.Sprintf("%d/%d", session.InviteCompleted, session.InviteTarget)
	earningToday := defaultString(session.TodayEarn, "0")
	earningTotal := defaultString(session.TotalEarn, "0")
	earningBalance := defaultString(session.BalanceEarn, "0")
	shareStatus := defaultString(session.DailyShareStatus, "WAITING")

	balanceSection := ""
	if broadcastBalances != "" {
		balanceSection = fmt.Sprintf("Balances : %s\n\n", broadcastBalances)
	}

	content := fmt.Sprintf(`
=============== Account %d ================
Address       : %s

Daily Login   : %s
Daily Share   : %s
Daily Invite  : %s - %s

Earning       :
- Today   %s
- Total   %s
- Balance %s

Status   : %s
Delay    : %s
===========================================`,
		session.AccIdx+1,
		session.Address,
		balanceSection,
		session.DailyLoginStatus,
		shareStatus,
		inviteProgress,
		session.DailyInviteStatus,
		earningToday,
		earningTotal,
		earningBalance,
		status,
		delayStr)

	if spinner, ok := spinners[session.AccIdx]; ok {
		spinner.UpdateText(content)
	} else {
		spinner, _ := pterm.DefaultSpinner.
			WithWriter(multi.NewWriter()).
			WithRemoveWhenDone(false).
			Start(content)
		spinners[session.AccIdx] = spinner
	}
}

func SetSpinnerSuccess(session model.Session, finalMessage string) {
	mu.Lock()
	defer mu.Unlock()
	if spinner, ok := spinners[session.AccIdx]; ok {
		UpdateStatus(session, finalMessage, 0)
		spinner.Success()
	}
}

func SetSpinnerError(session model.Session, finalMessage string) {
	mu.Lock()
	defer mu.Unlock()
	if spinner, ok := spinners[session.AccIdx]; ok {
		UpdateStatus(session, finalMessage, 0)
		spinner.Fail()
	}
}

func FormatDelay(d time.Duration) string {
	d = d.Round(time.Second)
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	s := int(d.Seconds()) % 60
	return fmt.Sprintf("%02d H %02d M %02d S", h, m, s)
}

func defaultString(val, fallback string) string {
	if strings.TrimSpace(val) == "" {
		return fallback
	}
	return val
}

func formatBalances(wallet model.WalletBalance) string {
	if len(wallet.Balances) == 0 {
		return ""
	}

	var builder strings.Builder
	for _, tb := range wallet.Balances {
		builder.WriteString(fmt.Sprintf("\n- %s : %s %s", tb.Symbol, tb.BalanceStr, tb.Symbol))
	}

	return builder.String()
}
