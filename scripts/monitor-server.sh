#!/bin/bash
# Monitor Glitch server health during scanner tests
# Usage: ./scripts/monitor-server.sh [output_file] [interval_seconds]

OUTPUT="${1:-/tmp/glitch-monitor.log}"
INTERVAL="${2:-30}"
HEALTH_URL="http://localhost:8765/_internal/research-health-2026/healthz"

echo "Monitoring Glitch server every ${INTERVAL}s -> ${OUTPUT}"
echo "Press Ctrl+C to stop"

while true; do
    TS=$(date '+%Y-%m-%d %H:%M:%S')

    # Health check
    HEALTH=$(curl -sf -o /dev/null -w "%{http_code}" "$HEALTH_URL" --max-time 5 2>/dev/null)

    # Process stats
    GLITCH_PID=$(pgrep -f './glitch$' | head -1)
    if [ -n "$GLITCH_PID" ]; then
        MEM=$(ps -o rss= -p "$GLITCH_PID" 2>/dev/null | tr -d ' ')
        CPU=$(ps -o %cpu= -p "$GLITCH_PID" 2>/dev/null | tr -d ' ')
        THREADS=$(ls /proc/$GLITCH_PID/task 2>/dev/null | wc -l)
    else
        MEM="N/A"
        CPU="N/A"
        THREADS="N/A"
    fi

    # System memory
    SYS_FREE=$(free -m | awk '/^Mem:/{print $4}')
    SYS_AVAIL=$(free -m | awk '/^Mem:/{print $7}')

    # Disk
    DISK_USED=$(df -h / | awk 'NR==2{print $5}')

    echo "$TS | health=$HEALTH | pid=$GLITCH_PID | mem_kb=$MEM | cpu=$CPU% | threads=$THREADS | sys_free=${SYS_FREE}M | sys_avail=${SYS_AVAIL}M | disk=$DISK_USED" | tee -a "$OUTPUT"

    sleep "$INTERVAL"
done
