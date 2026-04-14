@echo off
title Ozturk Sniper
if not exist node_modules (
  echo [*] Paketler yukleniyor...
  npm install --silent 2>nul
)
node --dns-result-order=ipv4first --no-warnings --no-deprecation --max-semi-space-size=8 index.js
pause
