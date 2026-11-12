@echo off
setlocal

rem ============================================================
rem  NTH-AN00 (HONOR 50 / 5.4.289-qgki-g8f2019ef68d9) one-click root
rem  push files -> settle -> disable SELinux -> load KernelSU -> verify
rem  No automatic reboot, no reboot loop.
rem ============================================================

set "REPO=%~dp0"
set "ADB=C:\Users\walleo\Downloads\platform-tools-latest-windows\platform-tools\adb.exe"
if not exist "%ADB%" set "ADB=adb"
set "ADBT=/data/local/tmp"
set "SYNC=GL_AIM_DM=1 GL_W1_ATTEMPTS=2 GL_ROUTE_ATTEMPTS=1 GL_HOLD_CHAIN=1 GL_HOLD_WAITER=1 GL_PUNCH_IN_WINDOW=1 GL_PUNCH_DELAY_USEC=0 GL_MCAST_ROUTE=1 GL_PROBE_BOOTID=0 GL_SPRAY_TEST=0 GL_STAMP_SYNC=1"

echo [1/6] waiting for device...
"%ADB%" wait-for-device || goto :fail
echo     model:
"%ADB%" shell getprop ro.product.model
echo     kernel:
"%ADB%" shell uname -r

echo [2/6] pushing exploit...
"%ADB%" push "%REPO%root\exploit\ghostlock" %ADBT%/e >nul 2>&1 || goto :fail
"%ADB%" shell chmod 755 %ADBT%/e

echo [3/6] pushing KernelSU payload...
"%ADB%" shell mkdir -p %ADBT%/ksu_fne >nul 2>&1
for %%F in (chain_hook.sh kernelsu.ko ksud magiskpolicy ksu_rules load_ko kmsg_dumper fne_syms.txt) do (
    "%ADB%" push "%REPO%root\ksu-late-load\%%F" %ADBT%/ksu_fne/%%F >nul 2>&1 || goto :fail
)
"%ADB%" shell "chmod 755 %ADBT%/ksu_fne/chain_hook.sh %ADBT%/ksu_fne/load_ko %ADBT%/ksu_fne/kmsg_dumper %ADBT%/ksu_fne/ksud %ADBT%/ksu_fne/magiskpolicy"

echo [4/6] settling 60s, keep the phone idle...
"%ADB%" shell "am force-stop com.hihonor.photos; am force-stop com.hihonor.search; am kill-all; pm trim-caches 999999999999" >nul 2>&1
ping -n 61 127.0.0.1 >nul

echo [5/6] disabling SELinux, 20-60s, the phone may stutter...
"%ADB%" shell "cd %ADBT% && env %SYNC% ./e --write1"
"%ADB%" wait-for-device >nul 2>&1
"%ADB%" shell getenforce > "%TEMP%\nth_enf.txt" 2>nul
echo     getenforce:
type "%TEMP%\nth_enf.txt"
findstr /i /c:"Permissive" "%TEMP%\nth_enf.txt" >nul
if errorlevel 1 (
    echo     [!] SELinux still enforcing: the punch missed this boot, or the write failed.
    echo         Run this .bat again once the phone is back up.
    goto :end
)

echo [6/6] loading KernelSU, 20-60s...
"%ADB%" shell "cd %ADBT% && env %SYNC% GL_W2_ROUNDS=2 GL_W2_CRED_ADJ=0 ./e"
echo     kernelsu module count:
"%ADB%" shell "grep -c kernelsu /proc/modules"
echo.
echo === verify ===
"%ADB%" shell "su -c id"
echo.
echo [done] uid=0(root) ... context=u:r:ksu:s0 means success. Re-run after every reboot.
goto :end

:fail
echo [!] adb/push failed: check USB debugging and the authorization prompt.
:end
pause
