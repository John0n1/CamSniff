#!/usr/bin/env bash
#
# https://github.com/John0n1/CamSniff
#
# Copyright (c) 2026 John Hauger Mitander
# License: MIT License https://opensource.org/license/MIT
#
# Shared URL template rendering used by both camsniff.sh and credential-probe.sh.
# Substitutes {{placeholder}} tokens in RTSP/HTTP URL templates.

# render_url_template <template> <ip> <username> <password> <port> <channel> <stream>
#
# Replace standard placeholders in a URL template string.
# Placeholders: {{ip_address}}, {{username}}, {{password}}, {{port}},
#               {{channel}}, {{stream}}
render_url_template() {
    local template="$1"
    local ip="$2"
    local username="$3"
    local password="$4"
    local port="$5"
    local channel="$6"
    local stream="$7"
    local result="$template"
    result="${result//\{\{ip_address\}\}/$ip}"
    result="${result//\{\{username\}\}/$username}"
    result="${result//\{\{password\}\}/$password}"
    result="${result//\{\{port\}\}/$port}"
    result="${result//\{\{channel\}\}/$channel}"
    result="${result//\{\{stream\}\}/$stream}"
    echo "$result"
}
