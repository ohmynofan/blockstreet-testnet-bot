package app

import (
	"sync"

	"github.com/ohmynofan/blockstreet-testnet-bot/internal/app/worker"
	"github.com/ohmynofan/blockstreet-testnet-bot/internal/config"
	"github.com/ohmynofan/blockstreet-testnet-bot/internal/storage/signlog"
)

type App struct{ cfg config.Config }

func New(cfg config.Config) *App { return &App{cfg: cfg} }

func (app *App) Run() error {
	accounts, err := app.cfg.LoadAccounts()
	if err != nil {
		return err
	}

	store, err := signlog.NewStore("data/blockstreet.db")
	if err != nil {
		return err
	}
	defer store.Close()

	var wg sync.WaitGroup
	for idx, acc := range accounts {
		wg.Add(1)
		go func(i int, a config.Account) {
			defer wg.Done()
			worker.Run(a, i, app.cfg, store)
		}(idx, acc)
	}
	wg.Wait()
	return nil
}
