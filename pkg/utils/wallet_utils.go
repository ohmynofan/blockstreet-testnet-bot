package utils

import (
	"crypto/ecdsa"
	"errors"
	"math"
	"math/big"
	"regexp"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	gethmath "github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/crypto"
	bip32 "github.com/tyler-smith/go-bip32"
	bip39 "github.com/tyler-smith/go-bip39"
)

var pkRegex = regexp.MustCompile(`^[a-fA-F0-9]{64}$`)

func ShortenAddress(s string) string {
	if len(s) <= 12 {
		return s
	}
	return s[:6] + "..." + s[len(s)-4:]
}

func DetermineType(input string) string {
	if IsMnemonic(input) {
		return "Secret Phrase"
	}
	if IsPrivateKey(input) {
		return "Private Key"
	}
	return "Unknown"
}
func IsMnemonic(input string) bool {
	return bip39.IsMnemonicValid(strings.TrimSpace(input))
}
func IsPrivateKey(input string) bool {
	data := strings.TrimPrefix(strings.TrimSpace(input), "0x")
	return pkRegex.MatchString(data)
}
func PrivateKeyFromHex(input string) (*ecdsa.PrivateKey, error) {
	data := strings.TrimPrefix(strings.TrimSpace(input), "0x")
	return crypto.HexToECDSA(data)
}
func AddressFromMnemonic(mnemonic, passphrase string) (common.Address, *ecdsa.PrivateKey, error) {
	if !bip39.IsMnemonicValid(mnemonic) {
		return common.Address{}, nil, errors.New("invalid BIP-39 mnemonic")
	}
	seed := bip39.NewSeed(mnemonic, passphrase)
	master, err := bip32.NewMasterKey(seed)
	if err != nil {
		return common.Address{}, nil, err
	}
	h := func(i uint32) uint32 { return i + bip32.FirstHardenedChild }
	purpose, err := master.NewChildKey(h(44))
	if err != nil {
		return common.Address{}, nil, err
	}
	coin, err := purpose.NewChildKey(h(60))
	if err != nil {
		return common.Address{}, nil, err
	}
	acct, err := coin.NewChildKey(h(0))
	if err != nil {
		return common.Address{}, nil, err
	}
	change, err := acct.NewChildKey(0)
	if err != nil {
		return common.Address{}, nil, err
	}
	index0, err := change.NewChildKey(0)
	if err != nil {
		return common.Address{}, nil, err
	}
	pk, err := crypto.ToECDSA(index0.Key)
	if err != nil {
		return common.Address{}, nil, err
	}
	return crypto.PubkeyToAddress(pk.PublicKey), pk, nil
}

func ParseUnits(amount string, decimals int) (*big.Int, error) {
	value, _, err := big.ParseFloat(amount, 10, 256, big.ToNearestEven)
	if err != nil {
		return nil, err
	}

	multiplier := new(big.Float).SetInt(big.NewInt(int64(math.Pow10(decimals))))
	result := new(big.Float).Mul(value, multiplier)

	wei, _ := result.Int(nil)

	return wei, nil
}

func FormatUnits(amount *big.Int, decimals int) string {
	value := new(big.Float).SetInt(amount)
	divisor := new(big.Float).SetInt(big.NewInt(int64(math.Pow10(decimals))))
	result := new(big.Float).Quo(value, divisor)

	return result.Text('f', -1)
}

func MaxUint256() *big.Int {
	maxUint256 := new(big.Int)
	maxUint256.SetString("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 16)
	return maxUint256
}

func EncodePath(tokenIn, tokenOut common.Address, fee *big.Int) []byte {
	feeBytes := make([]byte, 3)
	fee.FillBytes(feeBytes)
	path := append(tokenIn.Bytes(), feeBytes...)
	path = append(path, tokenOut.Bytes()...)
	return path
}

func ChainIDHex256(id int) *gethmath.HexOrDecimal256 {
	return (*gethmath.HexOrDecimal256)(big.NewInt(int64(id)))
}

func MaxUint160() *big.Int {
	one := big.NewInt(1)
	max := new(big.Int).Lsh(one, 160)
	return max.Sub(max, one)
}
