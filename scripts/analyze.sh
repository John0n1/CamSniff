#!/usr/bin/env bash
#
# CamSniff- Automated IP camera reconnaissance toolkit
# By John Hauger Mitander <john@on1.no>
# Copyright 2025 John Hauger Mitander
#
# CamSniff is Licensed under the MIT License.
# analyze.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
RESULTS_DIR="$ROOT_DIR/dev/results"
RUN_ID=""

print_usage() {
	cat <<'EOF'
Usage: analyze.sh [--run <timestamp>] [--help]

Without arguments the script inspects the most recent run under dev/results/
and prints high level statistics for discovery.json and credentials.json if
they exist. Provide --run <timestamp> to inspect a specific directory name.
EOF
}

while [[ $# -gt 0 ]]; do
	case "$1" in
		--run)
			RUN_ID="${2:-}"
			shift 2
			;;
		-h|--help)
			print_usage
			exit 0
			;;
		*)
			echo "Unknown argument: $1" >&2
			print_usage >&2
			exit 1
			;;
	esac
done

if [[ ! -d "$RESULTS_DIR" ]]; then
	echo "No results directory found at $RESULTS_DIR" >&2
	exit 1
fi

if [[ -z $RUN_ID ]]; then
	RUN_ID="$(find "$RESULTS_DIR" -mindepth 1 -maxdepth 1 -type d -printf '%f\n' | sort -r | head -n1 || true)"
	if [[ -z $RUN_ID ]]; then
		echo "No completed scans found under $RESULTS_DIR" >&2
		exit 1
	fi
fi

RUN_DIR="$RESULTS_DIR/$RUN_ID"
DISCOVERY_JSON="$RUN_DIR/discovery.json"
CREDS_JSON="$RUN_DIR/credentials.json"

if [[ ! -d "$RUN_DIR" ]]; then
	echo "Run directory $RUN_DIR was not found" >&2
	exit 1
fi

echo "Inspecting run: $RUN_ID"

if command -v jq >/dev/null 2>&1; then
	if [[ -f "$DISCOVERY_JSON" ]]; then
		printf "\n[discovery.json]\n"
		jq '{
			hosts: (.hosts // [] | length),
			vendors: (.hosts // [] | map(.profile_match?.vendor // "unknown") | unique | length),
			protocols: (.hosts // [] | map(.additional_protocols // []) | add? // [] | map(.protocol) | unique | length),
			protocol_hits: (.hosts // [] | map(.additional_protocols // []) | add? // [] | length),
			rtsp_discovered: (.hosts // [] | map(.rtsp_bruteforce.discovered // []) | add? // [] | length)
		}' "$DISCOVERY_JSON"
	else
		printf "\n[discovery.json] missing\n"
	fi

	if [[ -f "$CREDS_JSON" ]]; then
		printf "\n[credentials.json]\n"
		jq '{
			total: length,
			successes: (map(select(.success != false)) | length),
			failures: (map(select(.success == false)) | length),
			methods: (map(.method // empty) | unique | sort)
		}' "$CREDS_JSON"
	else
		printf "\n[credentials.json] missing\n"
	fi
else
	echo "jq not available; listing artifacts instead"
	ls -1 "$RUN_DIR"
fi

if [[ -d "$RUN_DIR/thumbnails" ]]; then
	thumb_count=$(find "$RUN_DIR/thumbnails" -type f \( -name '*.jpg' -o -name '*.png' \) | wc -l | tr -d ' ')
	printf "\nThumbnail count: %s\n" "$thumb_count"
fi

if [[ -d "$RUN_DIR/logs" ]]; then
	log_count=$(find "$RUN_DIR/logs" -type f | wc -l | tr -d ' ')
	printf "Log files: %s\n" "$log_count"
fi
