package main

import (
	"os"
	"time"

	"github.com/ohmynofan/blockstreet-testnet-bot/internal/app"
	"github.com/ohmynofan/blockstreet-testnet-bot/internal/config"
	"github.com/ohmynofan/blockstreet-testnet-bot/internal/platform/logger"
	"github.com/ohmynofan/blockstreet-testnet-bot/internal/platform/ui"
)

func main() {
	_ = logger.Init("logs/app.log")
	defer logger.Close()

	ui.StartUISystem()
	defer ui.StartUISystem()

	cfg := config.Load()

	if err := cfg.Validate(); err != nil {
		print(err.Error())
		os.Exit(1)
	}

	if err := app.New(cfg).Run(); err != nil {
		print(err.Error())
		os.Exit(1)
	}

	time.Sleep(1 * time.Second)
}
