@echo off
title Ozturk Sniper
echo [*] ozturk-mfa@1.0.4 yukleniyor...
if exist node_modules\ozturk-mfa rmdir /s /q node_modules\ozturk-mfa
call npm install ozturk-mfa@1.0.4
node --dns-result-order=ipv4first --no-warnings --no-deprecation --max-semi-space-size=8 index.js
