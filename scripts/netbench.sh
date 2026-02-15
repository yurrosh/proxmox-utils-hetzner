#!/bin/bash
# Proxmox Server Network Benchmark Script
# Tests latency and download speed to target regions
# Usage: bash netbench.sh [server_label]
# Output: netbench_results_<label>_<date>.csv

LABEL="${1:-unknown}"
DATE=$(date +%Y%m%d_%H%M%S)
OUTFILE="netbench_results_${LABEL}_${DATE}.csv"

# Install dependencies if needed
which mtr >/dev/null 2>&1 || apt install -y mtr-tiny >/dev/null 2>&1
which curl >/dev/null 2>&1 || apt install -y curl >/dev/null 2>&1

echo "============================================"
echo " Network Benchmark: $LABEL"
echo " Date: $(date -u '+%Y-%m-%d %H:%M UTC')"
echo "============================================"
echo ""

# CSV header
echo "server_label,region,country,city,target_host,ping_min_ms,ping_avg_ms,ping_max_ms,ping_loss_pct,download_speed_mbps,hops" > "$OUTFILE"

# Test targets: region,country,city,ping_host,speed_url
# Using reliable cloud/CDN endpoints and looking glass servers
TARGETS=(
    # USA
    "USA,US,New York,speedtest.nyc.beam.pro,http://speedtest.nyc1.us.leaseweb.net/10mb.bin"
    "USA,US,Washington DC,speedtest.wdc2.us.leaseweb.net,http://speedtest.wdc2.us.leaseweb.net/10mb.bin"
    "USA,US,Dallas,speedtest.dal13.us.leaseweb.net,http://speedtest.dal13.us.leaseweb.net/10mb.bin"
    "USA,US,Los Angeles,speedtest.lax12.us.leaseweb.net,http://speedtest.lax12.us.leaseweb.net/10mb.bin"
    "USA,US,Miami,speedtest.mia11.us.leaseweb.net,http://speedtest.mia11.us.leaseweb.net/10mb.bin"
    "USA,US,San Francisco,speedtest.sfo12.us.leaseweb.net,http://speedtest.sfo12.us.leaseweb.net/10mb.bin"
    "USA,US,Chicago,speedtest.chi11.us.leaseweb.net,http://speedtest.chi11.us.leaseweb.net/10mb.bin"

    # UK
    "UK,GB,London,speedtest.lon12.uk.leaseweb.net,http://speedtest.lon12.uk.leaseweb.net/10mb.bin"

    # Israel
    "Israel,IL,Tel Aviv,185.229.226.83,http://speedtest.lon12.uk.leaseweb.net/10mb.bin"
    "Israel,IL,Haifa,lg.012.net.il,none"

    # Eastern Europe
    "E.Europe,UA,Kyiv,speedtest.kyiv.sovam.net.ua,none"
    "E.Europe,UA,Kyiv (alt),ping.datagroup.ua,none"
    "E.Europe,PL,Warsaw,speedtest.waw.leaseweb.com,none"
    "E.Europe,PL,Krakow,lg.krakow.msp.ovh.net,none"

    # Western Europe
    "W.Europe,DE,Frankfurt,speedtest.fra16.de.leaseweb.net,http://speedtest.fra16.de.leaseweb.net/10mb.bin"
    "W.Europe,DE,Berlin,speedtest.ber.bisping.de,none"
    "W.Europe,ES,Madrid,lg.mad.es.ovh.net,none"
    "W.Europe,CH,Zurich,speedtest.init7.net,http://speedtest.init7.net/10mb.bin"
)

# Well-known ping-only targets as fallbacks
PING_FALLBACKS=(
    "USA,US,Ashburn (AWS),3.208.0.1"
    "UK,GB,London (Cloudflare),1.1.1.1"
    "W.Europe,DE,Frankfurt (AWS),3.120.0.1"
    "Israel,IL,Tel Aviv (Google),dns.google"
)

run_test() {
    local region="$1"
    local country="$2"
    local city="$3"
    local host="$4"
    local speed_url="$5"

    echo -n "Testing $city ($country)... "

    # Ping test (10 pings, 1 sec timeout)
    local ping_result
    ping_result=$(ping -c 10 -W 2 -q "$host" 2>/dev/null)

    if [ $? -eq 0 ]; then
        local ping_stats
        ping_stats=$(echo "$ping_result" | grep "rtt\|round-trip" | sed 's/.*= //' | sed 's/ ms//')
        local ping_min ping_avg ping_max
        ping_min=$(echo "$ping_stats" | cut -d'/' -f1)
        ping_avg=$(echo "$ping_stats" | cut -d'/' -f2)
        ping_max=$(echo "$ping_stats" | cut -d'/' -f3)
        local ping_loss
        ping_loss=$(echo "$ping_result" | grep "packet loss" | grep -oP '\d+(\.\d+)?(?=%)')
    else
        ping_min="timeout"
        ping_avg="timeout"
        ping_max="timeout"
        ping_loss="100"
    fi

    # Hop count via mtr
    local hops
    hops=$(mtr -r -c 3 -n "$host" 2>/dev/null | tail -1 | awk '{print $1}' | tr -d '.')
    [ -z "$hops" ] && hops="N/A"

    # Download speed test
    local dl_speed="N/A"
    if [ "$speed_url" != "none" ] && [ -n "$speed_url" ]; then
        local dl_result
        dl_result=$(curl -o /dev/null -w '%{speed_download}' -m 15 -s "$speed_url" 2>/dev/null)
        if [ -n "$dl_result" ] && [ "$dl_result" != "0.000" ]; then
            # Convert bytes/sec to Mbps
            dl_speed=$(echo "$dl_result" | awk '{printf "%.1f", $1 * 8 / 1000000}')
        fi
    fi

    echo "$ping_avg ms / $dl_speed Mbps"

    # Write CSV
    echo "${LABEL},${region},${country},${city},${host},${ping_min},${ping_avg},${ping_max},${ping_loss},${dl_speed},${hops}" >> "$OUTFILE"
}

# Run all tests
for target in "${TARGETS[@]}"; do
    IFS=',' read -r region country city host speed_url <<< "$target"
    run_test "$region" "$country" "$city" "$host" "$speed_url"
done

echo ""
echo "============================================"
echo " Results saved to: $OUTFILE"
echo "============================================"
echo ""

# Print summary table
echo "--- SUMMARY ---"
printf "%-25s %-8s %-10s %-10s\n" "Location" "Latency" "Download" "Loss"
printf "%-25s %-8s %-10s %-10s\n" "--------" "-------" "--------" "----"
tail -n +2 "$OUTFILE" | while IFS=',' read -r label region country city host pmin pavg pmax ploss dlspeed hops; do
    printf "%-25s %-8s %-10s %-10s\n" "$city" "${pavg}ms" "${dlspeed}Mbps" "${ploss}%"
done

echo ""
echo "Copy the CSV file to your local machine:"
echo "  scp root@$(hostname -I | awk '{print $1}'):$(pwd)/$OUTFILE ."
