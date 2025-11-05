package config

type Network struct {
	Name     string
	ChainID  int
	RPCURL   string
	Explorer string
	Symbol   string
	Decimals int
}

var MonadTestnet = Network{
	Name:     "Monad Testnet",
	ChainID:  10143,
	RPCURL:   "https://rpc.ankr.com/monad_testnet",
	Explorer: "https://testnet.monadexplorer.com/",
	Symbol:   "MON",
	Decimals: 18,
}
