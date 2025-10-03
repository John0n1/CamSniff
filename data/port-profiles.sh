#!/usr/bin/env bash
# CamSniff- Automated IP camera reconnaissance toolkit
# By John Hauger Mitander <john@on1.no>
# Copyright 2025 John Hauger Mitander
#
# SPDX-License-Identifier: MIT
#

# This file is sourced for variable definitions. It is not meant to be executed
# directly, so we provide a no-op interpreter line to appease lintian.

# shellcheck disable=SC2034

# Mapping of logical profile names to Nmap port lists.
declare -A CAM_PORT_PROFILES_NMAP=(
  [minimal]="80,554"
  [core]="80,443,554"
  [standard]="80,81,88,443,554,8000,8080,8081,8554,37777"
  [extended]="80,81,88,443,554,1935,2000,37777,5000,5001,5540,7070,7447,8000,8001,8002,8080,8081,8082,8554,9000,9001,9002,9554"
  [war]="80,81,82,88,443,554,1935,2000,3702,37777,5000,5001,5540,7070,7447,7654,7777,8000-8100,8200,8300,8400,8443,8554,8600,8800,9000-9200,9554,10554"
  [total]="1-65535"
  [fallback]="80,443,554,8000,8080,8081,8554,9000,37777"
)

# Mapping of logical profile names to Masscan specifications.
declare -A CAM_PORT_PROFILES_MASSCAN=(
  [minimal]="80,554"
  [core]="80,443,554"
  [standard]="80,81,88,443,554,8000-8081,8554,37777"
  [extended]="80,81,88,443,554,1935,2000,37777,5000-5001,5540,7070,7447,8000-8082,8554,9000-9002,9554"
  [war]="80-82,88,443,554,1935,2000,3702,37777,5000-5010,5540,7070,7447,7654,7777,8000-8200,8300,8400,8443,8554,8600,8800,9000-9400,9554,10554"
  [total]="1-65535"
  [fallback]="80,443,554,8000-8100,9000-9100,37777"
)

# Human friendly labels for reporting.
declare -A CAM_PORT_PROFILE_LABELS=(
  [minimal]="Minimal (HTTP/RTSP core)"
  [core]="Core camera services"
  [standard]="Standard vendor mix"
  [extended]="Extended vendor/service sweep"
  [war]="War footing (broad sweep)"
  [total]="Total spectrum (1-65535)"
  [fallback]="Fallback standard"
)

# Suggested RTSP brute-force thread counts per mode.
declare -A CAM_RTSP_THREAD_PROFILE=(
  [stealth]=4
  [stealth+]=6
  [medium]=10
  [aggressive]=16
  [war]=24
  [nuke]=32
  [total]=32
)
