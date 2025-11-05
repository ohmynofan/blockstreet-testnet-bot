package model

import "math/big"

type TokenBalance struct {
	Symbol     string
	Balance    big.Int
	BalanceStr string
}

type WalletBalance struct {
	Balances []TokenBalance
}
