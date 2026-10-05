#!/bin/sh

PCAP_DIR="/pcaps"
IOT_PCAP_DIR="/pcaps_iot"
FLOW_DIR="/flows"
IOT_FLOW_DIR = "/flows_iot"

SCAN_INTERVAL=15          # seconds between scans
FLOW_TIMEOUT=300          # max seconds allowed per PCAP (5 min)
MIN_PCAP_SIZE=100         # minimum file size in bytes to attempt processing
IOT_SETTLE_SECONDS=20
IOT_ATTEMPTED="|"

process_directory() {
  dir="$1"
  label="$2"
  output_dir="$3"

  if [ ! -d "$dir" ]; then
    echo "Directory $dir not found — skipping $label"
    return
  fi

  echo "Scanning for PCAP files in $dir ($label) ..."
  for f in "$dir"/*.pcap; do
    [ -f "$f" ] || continue

    # Skip empty/tiny files (pcap header is ~24 bytes, need actual packets)
    filesize=$(stat -c%s "$f" 2>/dev/null || stat -f%z "$f" 2>/dev/null || echo "0")
    if [ "$label" = "website" ] && [ "$filesize" -lt "$MIN_PCAP_SIZE" ]; then
      continue
    fi

    if [ "$label" = "iot" ]; then
      packet_count=$(capinfos -c "$f" 2>/dev/null | awk -F': ' '/Number of packets/ {print $2; exit}')
      echo "IoT capture: $f | ${filesize} bytes | ${packet_count:-packet count unavailable} packets"

      file_mtime=$(stat -c %Y "$f" 2>/dev/null || stat -f %m "$f" 2>/dev/null || echo "0")
      current_time=$(date +%s)
      if [ "$file_mtime" -gt 0 ] && [ $((current_time - file_mtime)) -lt "$IOT_SETTLE_SECONDS" ]; then
        echo "Waiting for IoT capture to stop growing: $f"
        continue
      fi

      capture_signature="${f}|${filesize}|${file_mtime}"
      case "$IOT_ATTEMPTED" in
        *"|${capture_signature}|"*) continue ;;
      esac
      IOT_ATTEMPTED="${IOT_ATTEMPTED}${capture_signature}|"
    fi

    base=$(basename "$f" .pcap)
    final_csv="$output_dir/${base}.csv"
    skip_marker="$output_dir/${base}.skip"
    mkdir -p "$output_dir"

    if [ "$label" = "iot" ] && [ -f "$skip_marker" ]; then
      rm -f "$skip_marker"
      echo "Removed stale IoT skip marker: $skip_marker"
    fi

    # Skip already completed files
    if [ -f "$final_csv" ]; then
      continue
    fi

    # Skip files previously marked as failed
    if [ "$label" = "website" ] && [ -f "$skip_marker" ]; then
      continue
    fi

    echo "=== Processing ($label): $f (${filesize} bytes) ==="

    # Run CICFlowMeter with timeout protection
    timeout "$FLOW_TIMEOUT" java -Djava.library.path=/app/lib/native \
      -cp "/app/CICFlowMeter-4.0.jar:/app/libs/*:/app/lib/native/jnetpcap.jar" \
      cic.cs.unb.ca.ifm.Cmd "$f" "$output_dir"

    status=$?

    if [ "$status" -eq 0 ]; then
      # CICFlowMeter generates ${base}.pcap_Flow.csv or ${base}_Flow.csv
      generated_csv=$(ls "$output_dir"/${base}*.csv 2>/dev/null | grep -v "\.tmp$" | grep -v "\.skip$" | head -n 1)
      if [ -n "$generated_csv" ] && [ -f "$generated_csv" ]; then
        if [ "$generated_csv" != "$final_csv" ]; then
          mv "$generated_csv" "$final_csv"
        fi
        echo "SUCCESS: Completed $final_csv"
      else
        if [ "$label" = "iot" ]; then
          echo "IoT capture retained: no flow extracted from $f; no skip marker created"
        else
          echo "SKIP: No flows extracted from $f — marking as skip"
          touch "$skip_marker"
        fi
      fi
    elif [ "$status" -eq 124 ]; then
      if [ "$label" = "iot" ]; then
        echo "TIMEOUT: CICFlowMeter hung on $f — no IoT skip marker created"
      else
        echo "TIMEOUT: CICFlowMeter hung on $f — skipping"
        touch "$skip_marker"
      fi
    else
      if [ "$label" = "iot" ]; then
        echo "ERROR: Failed processing $f (exit code: $status) — no IoT skip marker created"
      else
        echo "ERROR: Failed processing $f (exit code: $status) — marking as skip"
        touch "$skip_marker"
      fi
    fi

  done
}

process_website_forever() {
  while true; do
    process_directory "$PCAP_DIR" "website" "$FLOW_DIR"
    sleep "$SCAN_INTERVAL"
  done
}

# Keep the website backlog from delaying IoT captures.
process_website_forever &
WEBSITE_PROCESSOR_PID=$!
trap 'kill "$WEBSITE_PROCESSOR_PID" 2>/dev/null; wait "$WEBSITE_PROCESSOR_PID" 2>/dev/null' EXIT INT TERM

while true; do
  process_directory "$IOT_PCAP_DIR" "iot" "$IOT_FLOW_DIR"

  echo "Waiting $SCAN_INTERVAL seconds before next scan..."
  sleep "$SCAN_INTERVAL"
done
