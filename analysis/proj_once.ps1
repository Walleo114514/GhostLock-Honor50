$ErrorActionPreference = "Continue"
$adb = "C:\Users\walleo\Downloads\platform-tools-latest-windows\platform-tools\adb.exe"
$SYNC = "GL_AIM_DM=1 GL_W1_ATTEMPTS=2 GL_ROUTE_ATTEMPTS=1 GL_HOLD_CHAIN=1 GL_HOLD_WAITER=1 GL_PUNCH_IN_WINDOW=1 GL_PUNCH_DELAY_USEC=0 GL_MCAST_ROUTE=1 GL_PROBE_BOOTID=0 GL_SPRAY_TEST=0 GL_STAMP_SYNC=1"
$log = "C:\Users\walleo\Downloads\GhostLock-HonorFne\analysis\proj-once.log"

Write-Output "=== boot_id before ==="
& $adb shell "cat /proc/sys/kernel/random/boot_id" 2>$null
& $adb shell getenforce 2>$null

Write-Output "=== settle (project run_w2.sh lines 58-61) ==="
& $adb shell "am force-stop com.hihonor.photos" 2>$null | Out-Null
& $adb shell "am force-stop com.hihonor.searchservice" 2>$null | Out-Null
& $adb shell "am kill-all" 2>$null | Out-Null
& $adb shell "pm trim-caches 999999999999" 2>$null | Out-Null
Start-Sleep -Seconds 60

# idle gate, up to ~5 min, proceed anyway (same as script)
$idleOk = $false
for ($i = 0; $i -lt 60; $i++) {
    $a = (& $adb shell "awk '/^cpu /{print `$5+`$6}' /proc/stat" 2>$null | Out-String).Trim()
    Start-Sleep -Seconds 5
    $b = (& $adb shell "awk '/^cpu /{print `$5+`$6}' /proc/stat" 2>$null | Out-String).Trim()
    if ($a -match '^\d+$' -and $b -match '^\d+$') {
        $id = [int](([int64]$b - [int64]$a) / 40)
        if ($id -ge 85) { Write-Output "settled: idle=$id%"; $idleOk = $true; break }
    }
}
if (-not $idleOk) { Write-Output "settle timeout - proceeding anyway" }

Write-Output "=== [W1] project SYNC, one try ==="
$p = Start-Process -FilePath $adb -ArgumentList @("shell", "cd /data/local/tmp && env $SYNC ./e --write1") `
    -RedirectStandardOutput $log -RedirectStandardError "$log.err" -PassThru -NoNewWindow
$done = $p.WaitForExit(420000)
if (-not $done) { Write-Output "W1 watchdog: killing after 420s"; $p.Kill() } else { Write-Output "W1 rc=$($p.ExitCode)" }

Start-Sleep -Seconds 5
Write-Output "=== verdict ==="
& $adb shell "cat /proc/sys/kernel/random/boot_id; uptime; getenforce; grep -c kernelsu /proc/modules" 2>$null
Write-Output "=== log tail ==="
Get-Content $log -Tail 8 | ForEach-Object { $_ -replace "\x1b\[[0-9;]*m", "" }
