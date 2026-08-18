#!/usr/bin/env bash
# IPv4 target validation and containment helpers.
# The caller owns the scan_targets array consumed by is_authorized_ip.

is_valid_ipv4() {
  local ip="$1"
  local o1 o2 o3 o4 extra
  IFS='.' read -r o1 o2 o3 o4 extra <<< "$ip"
  [[ -n $extra || -z $o1 || -z $o2 || -z $o3 || -z $o4 ]] && return 1
  for octet in "$o1" "$o2" "$o3" "$o4"; do
    [[ $octet =~ ^[0-9]{1,3}$ ]] || return 1
    ((10#$octet >= 0 && 10#$octet <= 255)) || return 1
  done
  return 0
}

is_valid_ipv4_cidr() {
  local value="$1"
  local ip="$value"
  local mask=""
  if [[ $value == */* ]]; then
    ip="${value%%/*}"
    mask="${value#*/}"
  fi
  is_valid_ipv4 "$ip" || return 1
  if [[ -n $mask ]]; then
    [[ $mask =~ ^[0-9]{1,2}$ ]] || return 1
    ((10#$mask >= 0 && 10#$mask <= 32)) || return 1
  fi
  return 0
}

ipv4_to_int() {
  local ip="$1"
  local o1 o2 o3 o4
  is_valid_ipv4 "$ip" || return 1
  IFS='.' read -r o1 o2 o3 o4 <<< "$ip"
  printf '%u' "$(((10#$o1 << 24) | (10#$o2 << 16) | (10#$o3 << 8) | 10#$o4))"
}

ip_in_target() {
  local ip="$1"
  local target="$2"
  local target_ip="$target"
  local prefix=32
  if [[ $target == */* ]]; then
    target_ip=${target%%/*}
    prefix=${target#*/}
  fi
  is_valid_ipv4 "$ip" || return 1
  is_valid_ipv4_cidr "$target" || return 1
  prefix=$((10#$prefix))

  local ip_num target_num mask
  ip_num=$(ipv4_to_int "$ip") || return 1
  target_num=$(ipv4_to_int "$target_ip") || return 1
  if ((prefix == 0)); then
    mask=0
  else
    mask=$(((0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF))
  fi
  (((ip_num & mask) == (target_num & mask)))
}

is_authorized_ip() {
  local ip="$1"
  local target
  # shellcheck disable=SC2154  # scan_targets is supplied by the sourcing caller.
  for target in "${scan_targets[@]}"; do
    if ip_in_target "$ip" "$target"; then
      return 0
    fi
  done
  return 1
}
