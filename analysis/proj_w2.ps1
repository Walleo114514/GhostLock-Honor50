$ErrorActionPreference = "Continue"
$adb = "C:\Users\walleo\Downloads\platform-tools-latest-windows\platform-tools\adb.exe"
$SYNC = "GL_AIM_DM=1 GL_W1_ATTEMPTS=2 GL_ROUTE_ATTEMPTS=1 GL_HOLD_CHAIN=1 GL_HOLD_WAITER=1 GL_PUNCH_IN_WINDOW=1 GL_PUNCH_DELAY_USEC=0 GL_MCAST_ROUTE=1 GL_PROBE_BOOTID=0 GL_SPRAY_TEST=0 GL_STAMP_SYNC=1"
$log = "C:\Users\walleo\Downloads\GhostLock-HonorFne\analysis\proj-w2.log"

Write-Output "=== pre ==="
& $adb shell "cat /proc/sys/kernel/random/boot_id; getenforce" 2>$null

$p = Start-Process -FilePath $adb -ArgumentList @("shell", "cd /data/local/tmp && env $SYNC GL_W2_ROUNDS=2 GL_W2_CRED_ADJ=0 ./e") `
    -RedirectStandardOutput $log -RedirectStandardError "$log.err" -PassThru -NoNewWindow
$done = $p.WaitForExit(900000)
if (-not $done) { Write-Output "watchdog: killing after 900s"; $p.Kill() } else { Write-Output "rc=$($p.ExitCode)" }

Start-Sleep -Seconds 5
Write-Output "=== verdict ==="
& $adb shell "cat /proc/sys/kernel/random/boot_id; getenforce; id 2>/dev/null; grep -c kernelsu /proc/modules" 2>$null
Write-Output "=== log tail ==="
Get-Content $log -Tail 25 | ForEach-Object { $_ -replace "\x1b\[[0-9;]*m", "" }
