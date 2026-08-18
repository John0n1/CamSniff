#!/usr/bin/env bash
# Structured summary helpers for scanner output files.

nmap_hosts_up_count() {
  local input="$1"
  local count
  count=$(sed -nE 's/.*\(([0-9]+) hosts? up\).*/\1/p' "$input" | tail -n1)
  printf '%s' "${count:-0}"
}

nmap_open_port_count() {
  local input="$1"
  awk '$1 ~ /^[0-9]+\/(tcp|udp)$/ && $2 == "open" { count++ }
       END { print count + 0 }' "$input"
}

masscan_host_count() {
  local input="$1"
  jq -r '[.[]? | .ip // empty] | unique | length' "$input"
}

masscan_open_port_count() {
  local input="$1"
  jq -r '[.[]? | .ports[]?] | length' "$input"
}
