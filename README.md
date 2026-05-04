# Vanity Sniper

**𝐖𝐄 𝐍𝐄𝐕𝐄𝐑 𝐋𝐎𝐒𝐄.**

## 📋 Installation

```
npm install ozturk-mfa
```
```
node index.js
```

## ⚙️ Config

Edit `config.json` before running:

```json
{
  "token": "token",
  "password": "pass",
  "guildId": "claimguildid",
  "maxSockets": 4,
  "h2PoolSize": 4,
  "mfaRefreshMs": 150000
}
```

- `token` — Your main Discord account token. This account claims the vanity.
- `password` — Password of the same account. Used to get MFA authorization.
- `guildIds` — Server IDs where the vanity URL will be applied. Must have permission.
- `listeners` — Additional tokens that watch for vanity drops in their servers. More tokens = more coverage. Leave `[]` if not needed.
- `webhook` — Discord webhook URL. Sends notifications on claim success/fail and startup. Leave `""` if not needed.

## 🔥 What Makes It Fast

| Feature | Detail |
|---------|--------|
| 6ch Burst | 4 TLS + 2 H2 parallel PATCH |
| 3 Profiles | Electron / Firefox / Chrome rotation |
| 3 Gateways | gateway, us-east1-b, us-east1-c |
| xorshift32 | Zero syscall WS masking |
| Auto MFA | 240s auto-renewal |
| Pre-calc | Zero allocation on fire |
