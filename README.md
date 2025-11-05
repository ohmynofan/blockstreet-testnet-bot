### BLOCKSTREET TESTNET BOT

Automates the daily Blockstreet Testnet routine (login, share, invite) for multiple wallets. The bot signs in through the official API, solves Cloudflare Turnstile challenges using the solver keys you provide, and keeps lightweight logs so you can monitor progress.

---

## FEATURES

- Multi-account support (seed phrase or private key)
- Automatically completes:
- Daily login (SIWE signature)
- Daily share
- Daily invite workflow with auto-generated child wallets
- Turnstile captcha solving via CapSolver and/or 2Captcha
- Persistent session cookies and invite tracking
- Console + log-file output for each account

---

## PREREQUISITES

- **Go** 1.24.5 or newer
- A **CapSolver** or **2Captcha** API key
- Blockstreet wallet accounts (new/burner wallets recommended)
- Git (optional, but recommended)

---

## BLOCKSTREET TESTNET

- Visit: [Blockstreet](https://blockstreet.money/dashboard?)
- Connect with an EVM wallet (preferably new/burner)
- Complete the tasks manually at least once to confirm access:
- Daily Login
- Daily Share
- Daily Invite

The bot automates these actions daily for every account you configure.

---

## QUICK START

```bash
# 1. Clone and enter the project
git clone https://github.com/Rambeboy/blockstreet-testnet-bot.git
cd blockstreet-testnet-bot

# 2. Prepare templates
cp .env.example .env
cp configs/accounts_tmp.json configs/accounts.json

# 3. Install dependencies
go mod tidy

# 4. Configure .env and accounts.json (see below)
nano .env
nano configs/accounts.json

# 5. Run the bot
go run cmd/bot/main.go
```

---

## CONFIGURATION

### `.env` variables

| Variable | Description |
| --- | --- |
| `TWO_CAPTCHA_API_KEY` | API key for 2Captcha. Leave blank to disable. |
| `CAPSOLVER_API_KEY` | API key for CapSolver. Leave blank to disable. |
| `DAILY_MIN_INVITE` | Minimum number of invites the bot should attempt per day. |
| `DAILY_MAX_INVITE` | Maximum number of invites the bot should attempt per day. |
| `DELAY_MIN_INVITE_MINUTES` | Minimum waiting time (minutes) between invite attempts (default 1 if unset). |
| `DELAY_MAX_INVITE_MINUTES` | Maximum waiting time (minutes) between invite attempts (default 5 if unset). |

> ⚠️ Provide at least one solver key (CapSolver or 2Captcha). Set both if you want automatic fallback.

### `configs/accounts.json`

This file is a JSON array of strings. Each entry can be either a private key (`0x...`) or a full seed phrase. Example:

```json
[
  "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "twelve word seed phrase goes here ..."
]
```

Accounts are processed in the order they appear. You can mix private keys and seed phrases in the same file.

---

## RUNNING THE BOT

- **LINUX / MAC OS**
  ```bash
  go run cmd/bot/main.go
  ```
- **WINDOWS (POWERSHELL)**
  ```powershell
  go run cmd/bot/main.go
  ```

The bot prints account status to the console and writes detailed logs to `logs/app.log` (configurable via `.env`).

Stop the bot with `CTRL+C`. It automatically respects the invite target and daily run limits from your `.env` values.

---

## BUILD FROM SOURCE

To build platform-specific binaries:

```bash
mkdir -p release

GOOS=linux   GOARCH=amd64 go build -o release/blockstreet-bot-linux-amd64 ./cmd/bot
GOOS=linux   GOARCH=arm64 go build -o release/blockstreet-bot-linux-arm64 ./cmd/bot
GOOS=windows GOARCH=amd64 go build -o release/blockstreet-bot-windows-amd64.exe ./cmd/bot
GOOS=windows GOARCH=arm64 go build -o release/blockstreet-bot-windows-arm64.exe ./cmd/bot
GOOS=darwin  GOARCH=amd64 go build -o release/blockstreet-bot-darwin-amd64 ./cmd/bot
GOOS=darwin  GOARCH=arm64 go build -o release/blockstreet-bot-darwin-arm64 ./cmd/bot
```

Distribute the binary together with `.env` / `.env.example` and `configs/accounts.json` templates for easier setup.

---

## UPDATING

```bash
git pull --rebase
go mod tidy
```

If you have local changes you want to keep:

```bash
git stash
git pull --rebase
git stash pop
go mod tidy
```

---

## TEOUBLESHOOTING

| Issue | Possible fix |
| --- | --- |
| `ERROR_ZERO_BALANCE` from CapSolver/2Captcha | Top up the solver balance or disable that solver in `.env`. |
| `Session cookies appear invalid` | The bot will auto-refresh via signVerify. Ensure solver keys are valid so it can solve Turnstile when needed. |
| `invite code empty` errors | Confirm your main account has a valid invite code (viewable from the Blockstreet dashboard). |
| Bot stuck on `WAITING` | Check `logs/app.log` for solver errors or API rate limits, adjust retry delays if needed. |

---

## Contributing & Support

Contributions are welcome—fork the repo, open issues or PRs, and help improve the automation.

Enjoy automating your Blockstreet Testnet routine!

---
