package model

import (
	"crypto/ecdsa"

	"github.com/ethereum/go-ethereum/common"
)

type Session struct {
	Account           string
	AccIdx            int
	Role              string
	Parent            *Session
	Address           string
	PublicKey         common.Address
	PrivateKey        *ecdsa.PrivateKey
	WalletBalance     WalletBalance
	DailyLoginStatus  string
	DailyInviteStatus string
	DailyShareStatus  string
	InviteTarget      int
	InviteCompleted   int
	TodayEarn         string
	TotalEarn         string
	BalanceEarn       string
}

func (s *Session) LoggingSession() *Session {
	if s == nil {
		return nil
	}
	if s.Parent != nil {
		return s.Parent.LoggingSession()
	}
	return s
}
