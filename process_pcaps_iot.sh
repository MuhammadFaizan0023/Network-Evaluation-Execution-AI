#!/bin/sh
# IoT-lane CICFlowMeter runner for the `cicflowmeter_iot` container.
# Converts pcaps_iot -> flows_iot and pcaps_iot_test -> flows_iot_test, then
# NORMALIZES each produced CSV (normalize_iot_flows.sh) so feature values match
# the new model's training dataset. The website lane is handled by the separate
# `cicflowmeter` container (process_pcaps.sh); this script never touches it.

IOT_PCAP_DIR="/pcaps_iot"
IOT_FLOW_DIR="/flows_iot"
TEST_PCAP_DIR="/pcaps_iot_test"
TEST_FLOW_DIR="/flows_iot_test"
NORMALIZER="${NORMALIZER:-/app/normalize_iot_flows.sh}"

SCAN_INTERVAL=5
FLOW_TIMEOUT=300
IOT_SETTLE_SECONDS=20
IOT_ATTEMPTED="|"

process_directory() {
  dir="$1"
  label="$2"          # always "iot" here (same processing logic for both IoT lanes)
  output_dir="$3"
  settle="${4:-$IOT_SETTLE_SECONDS}"

  if [ ! -d "$dir" ]; then
    echo "Directory $dir not found — skipping"
    return
  fi

  echo "Scanning for PCAP files in $dir ..."
  for f in "$dir"/*.pcap; do
    [ -f "$f" ] || continue

    filesize=$(stat -c%s "$f" 2>/dev/null || stat -f%z "$f" 2>/dev/null || echo "0")

    packet_count=$(capinfos -c "$f" 2>/dev/null | awk -F': ' '/Number of packets/ {print $2; exit}')
    echo "IoT capture: $f | ${filesize} bytes | ${packet_count:-packet count unavailable} packets"

    file_mtime=$(stat -c %Y "$f" 2>/dev/null || stat -f %m "$f" 2>/dev/null || echo "0")
    current_time=$(date +%s)
    if [ "$file_mtime" -gt 0 ] && [ $((current_time - file_mtime)) -lt "$settle" ]; then
      echo "Waiting for IoT capture to stop growing: $f"
      continue
    fi

    capture_signature="${f}|${filesize}|${file_mtime}"
    case "$IOT_ATTEMPTED" in
      *"|${capture_signature}|"*) continue ;;
    esac
    IOT_ATTEMPTED="${IOT_ATTEMPTED}${capture_signature}|"

    base=$(basename "$f" .pcap)
    csv_name="flows_${base#capture_}"          # capture_00001_X -> flows_00001_X
    final_csv="$output_dir/${csv_name}.csv"
    legacy_csv="$output_dir/${base}.csv"
    mkdir -p "$output_dir"

    # Skip already completed files
    if [ -f "$final_csv" ] || [ -f "$legacy_csv" ]; then
      continue
    fi

    echo "=== Processing (iot): $f (${filesize} bytes) ==="

    # CICFlowMeter only accepts classic pcap; dumpcap (camera) writes pcapng, so
    # convert with tcpdump (reads pcapng via libpcap, writes classic pcap).
    input_file="$f"
    converted_file=""
    magic=$(od -An -tx1 -N4 "$f" 2>/dev/null | tr -d ' \n')
    if [ "$magic" = "0a0d0d0a" ]; then
      mkdir -p /tmp/pcap_convert
      converted_file="/tmp/pcap_convert/${base}.pcap"
      if tcpdump -r "$f" -w "$converted_file" 2>/dev/null; then
        input_file="$converted_file"
        echo "Converted pcapng to pcap: $f"
      else
        echo "ERROR: Could not convert pcapng file $f"
        rm -f "$converted_file"
        continue
      fi
    fi

    timeout "$FLOW_TIMEOUT" java -Djava.library.path=/app/lib/native \
      -cp "/app/CICFlowMeter-4.0.jar:/app/libs/*:/app/lib/native/jnetpcap.jar" \
      cic.cs.unb.ca.ifm.Cmd "$input_file" "$output_dir"

    status=$?
    [ -n "$converted_file" ] && rm -f "$converted_file"

    if [ "$status" -eq 0 ]; then
      generated_csv=$(ls "$output_dir"/${base}*.csv 2>/dev/null | grep -v "\.tmp$" | grep -v "\.skip$" | head -n 1)
      if [ -n "$generated_csv" ] && [ -f "$generated_csv" ]; then
        if [ "$generated_csv" != "$final_csv" ]; then
          mv "$generated_csv" "$final_csv"
        fi
        # Make feature values dataset-consistent BEFORE the producer sees them.
        sh "$NORMALIZER" "$final_csv"
        echo "SUCCESS: Completed (normalized) $final_csv"
      else
        echo "IoT capture retained: no flow extracted from $f"
      fi
    elif [ "$status" -eq 124 ]; then
      echo "TIMEOUT: CICFlowMeter hung on $f"
    else
      echo "ERROR: Failed processing $f (exit code: $status)"
    fi
  done
}

echo "cicflowmeter_iot started — IoT + test lanes only, with dataset normalization"
while true; do
  process_directory "$IOT_PCAP_DIR"  "iot" "$IOT_FLOW_DIR"
  process_directory "$TEST_PCAP_DIR" "iot" "$TEST_FLOW_DIR" 6
  echo "Waiting $SCAN_INTERVAL seconds before next scan..."
  sleep "$SCAN_INTERVAL"
done
