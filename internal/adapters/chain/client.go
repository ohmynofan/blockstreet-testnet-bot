package chain

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"strings"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ohmynofan/blockstreet-testnet-bot/internal/config"
	"github.com/ohmynofan/blockstreet-testnet-bot/internal/domain/model"
	"github.com/ohmynofan/blockstreet-testnet-bot/internal/platform/logger"
	"github.com/ohmynofan/blockstreet-testnet-bot/pkg/utils"
)

type EthersClient struct {
	client     *ethclient.Client
	network    config.Network
	session    *model.Session
	log        *logger.ClassLogger
	ownsClient bool
}

func New(session *model.Session, _ config.Config, network config.Network) (*EthersClient, error) {
	scope := "[New EtherClient] Error :"
	ec := &EthersClient{network: network, session: session, ownsClient: true}
	ec.log = logger.NewLogger(ec, session)
	ec.log.Log(fmt.Sprintf("Initializing Ethers Client on %s...", network.Name))

	client, err := ethclient.Dial(network.RPCURL)
	if err != nil {
		return nil, fmt.Errorf("%s failed to connect RPC (%s): %w", scope, network.Name, err)
	}
	ec.client = client
	return ec, nil
}

func (e *EthersClient) Close() {
	if e.client != nil && e.ownsClient {
		e.client.Close()
	}
}

func (e *EthersClient) CloneForSession(session *model.Session) *EthersClient {
	clone := &EthersClient{
		client:     e.client,
		network:    e.network,
		session:    session,
		ownsClient: false,
	}
	clone.log = logger.NewLogger(clone, session)
	return clone
}

func (e *EthersClient) ConnectWallet() error {
	scope := "[ConnectWallet] Error :"
	data := strings.TrimSpace(e.session.Account)
	if data == "" {
		e.session.Address = ""
		return fmt.Errorf("%s invalid account input (seed or private key)", scope)
	}

	roleLabel := "Account"
	if e.session != nil {
		role := strings.ToLower(strings.TrimSpace(e.session.Role))
		switch role {
		case "child":
			roleLabel = "Child account (invite)"
		case "primary":
			roleLabel = "Primary account"
		}
	}

	e.log.Log(fmt.Sprintf("Connecting to %s : %d", roleLabel, e.session.AccIdx+1))

	typ := utils.DetermineType(data)
	var addr common.Address
	var privateKey *ecdsa.PrivateKey

	switch typ {
	case "Secret Phrase":
		a, pk, err := utils.AddressFromMnemonic(data, "")
		if err != nil {
			e.session.Address = ""
			return fmt.Errorf("%s failed to read from seed phrase: %w", scope, err)
		}
		addr = a
		privateKey = pk
	case "Private Key":
		pk, err := utils.PrivateKeyFromHex(data)
		if err != nil {
			e.session.Address = ""
			return fmt.Errorf("%s invalid private key: %w", scope, err)
		}
		addr = crypto.PubkeyToAddress(pk.PublicKey)
		privateKey = pk
	default:
		e.session.Address = ""
		return fmt.Errorf("%s invalid account: Secret Phrase or Private Key required", scope)
	}

	e.session.Address = addr.Hex()
	e.session.PublicKey = addr
	e.session.PrivateKey = privateKey
	e.log.Log(fmt.Sprintf("Wallet connected %s", e.session.Address))
	return nil
}

func (e *EthersClient) Address() string {
	if e.session == nil {
		return ""
	}
	return e.session.Address
}

func (e *EthersClient) Session() *model.Session {
	return e.session
}

func (e *EthersClient) GetWalletBalance(update ...bool) error {
	if e.client == nil || e.session == nil {
		return fmt.Errorf("wallet client not initialized")
	}

	if (e.session.PublicKey == common.Address{}) {
		return fmt.Errorf("wallet not connected")
	}

	balance, err := e.client.BalanceAt(context.Background(), e.session.PublicKey, nil)
	if err != nil {
		return fmt.Errorf("failed to fetch wallet balance: %w", err)
	}

	balanceCopy := *balance
	e.session.WalletBalance.Balances = []model.TokenBalance{
		{
			Symbol:     e.network.Symbol,
			Balance:    balanceCopy,
			BalanceStr: utils.FormatUnits(balance, e.network.Decimals),
		},
	}

	e.log.Log(fmt.Sprintf("Wallet balance fetched: %s %s", utils.FormatUnits(balance, e.network.Decimals), e.network.Symbol))
	return nil
}

func (e *EthersClient) SignMessage(message string) (string, error) {
	scope := "[SignMessage] Error :"
	if e.session.PrivateKey == nil {
		return "", fmt.Errorf("%s wallet is not connected", scope)
	}

	msgHash := accounts.TextHash([]byte(message))
	signature, err := crypto.Sign(msgHash, e.session.PrivateKey)
	if err != nil {
		return "", fmt.Errorf("%s failed to sign message: %w", scope, err)
	}

	if signature[64] < 27 {
		signature[64] += 27
	}

	encodedSignature := hexutil.Encode(signature)
	e.log.Log("Message successfully signed")
	return encodedSignature, nil
}

func GeneratePrivateKeyHex() (string, error) {
	pk, err := crypto.GenerateKey()
	if err != nil {
		return "", err
	}
	return hexutil.Encode(crypto.FromECDSA(pk)), nil
}
