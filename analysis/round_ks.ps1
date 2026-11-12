param([int]$rounds = 4)

$ErrorActionPreference = "Continue"
$adb = "C:\Users\walleo\Downloads\platform-tools-latest-windows\platform-tools\adb.exe"
$logdir = "C:\Users\walleo\Downloads\GhostLock-HonorFne\analysis"

$ENVSTR = "GL_W1_ATTEMPTS=2 GL_ROUTE_ATTEMPTS=1 GL_HOLD_CHAIN=1 GL_HOLD_WAITER=1 GL_PUNCH_IN_WINDOW=1 GL_PUNCH_DELAY_USEC=0 GL_MCAST_ROUTE=1 GL_PROBE_BOOTID=0 GL_SPRAY_TEST=0 GL_STAMP_SYNC=1 GL_MEMSTART_PROBE=0"

function Get-Enforce {
    $v = & $adb shell getenforce 2>$null
    if ($null -eq $v) { return "UNKNOWN" }
    return ($v | Out-String).Trim()
}

for ($r = 1; $r -le $rounds; $r++) {
    Write-Output "==== ROUND $r / $rounds  $(Get-Date -Format 'HH:mm:ss') ===="

    & $adb reboot 2>$null | Out-Null
    Start-Sleep -Seconds 8
    & $adb wait-for-device 2>$null | Out-Null

    $booted = $false
    for ($i = 0; $i -lt 60; $i++) {
        Start-Sleep -Seconds 3
        $b = (& $adb shell getprop sys.boot_completed 2>$null | Out-String).Trim()
        if ($b -eq "1") { $booted = $true; break }
    }
    if (-not $booted) {
        Write-Output "!! boot_completed never reached; waiting extra"
        Start-Sleep -Seconds 30
    }
    Start-Sleep -Seconds 15

    $bid = (& $adb shell cat /proc/sys/kernel/random/boot_id 2>$null | Out-String).Trim()
    $en0 = Get-Enforce
    Write-Output "boot_id=$bid enforce_before=$en0"

    $sw = [Diagnostics.Stopwatch]::StartNew()
    $out = & $adb shell "cd /data/local/tmp && env $ENVSTR ./e --write1 2>&1"
    $sw.Stop()
    $out | Out-File -FilePath "$logdir\round$r.log" -Encoding utf8
    Write-Output ("run took {0:N0}s, {1} lines" -f $sw.Elapsed.TotalSeconds, ($out | Measure-Object).Count)

    $en1 = Get-Enforce
    $bid2 = (& $adb shell cat /proc/sys/kernel/random/boot_id 2>$null | Out-String).Trim()
    Write-Output "enforce_after=$en1 boot_id_after=$bid2 rebooted=$($bid -ne $bid2)"

    $tail = ($out | Select-Object -Last 6) -join " | "
    Write-Output "tail: $tail"

    if ($en1 -match "Permissive") {
        Write-Output "SUCCESS: SELinux is Permissive after round $r"
        break
    }
}
Write-Output "==== DONE $(Get-Date -Format 'HH:mm:ss') ===="
