#!/usr/bin/env bash
#
# https://github.com/John0n1/CamSniff
#
# Copyright (c) 2026 John Hauger Mitander
# License: MIT License https://opensource.org/license/MIT

cam_ui_visible_length() {
    local text="$1"
    text=$(printf "%s" "$text" | sed $'s/\e\[[0-9;]*m//g')
    echo "${#text}"
}

cam_ui_center_line() {
    local width="${1:-80}"
    local text="${2:-}"
    local prefix="${3:-}"
    local suffix="${4:-}"
    local -i width_int="${width}"
    local -i length
    length=$(cam_ui_visible_length "$text")

    if (( width_int <= length )); then
        printf "%s%s%s\n" "${prefix}" "${text}" "${suffix}"
        return
    fi

    local -i padding_left=$(( (width_int - length) / 2 ))
    local -i padding_right=$(( width_int - length - padding_left ))
    printf "%s%${padding_left}s%s%${padding_right}s%s\n" "${prefix}" "" "${text}" "" "${suffix}"
}

cam_ui_build_centered() {
    local width="${1:-80}"
    local text="${2:-}"
    local -i width_int="${width}"
    local -i length
    length=$(cam_ui_visible_length "$text")

    if (( width_int <= length )); then
        printf "%s" "${text}"
        return
    fi

    local -i padding_left=$(( (width_int - length) / 2 ))
    printf "%${padding_left}s%s" "" "${text}"
}

cam_ui_matrix_rain() {
    local width="${1:-$(tput cols 2>/dev/null || echo 80)}"
    local height="${2:-12}"
    local frames="${3:-20}"
    local delay="${4:-0.04}"
    local reset="${6:-"\033[31m"}"
    local hide_cursor=false
    local color="\033[31m"

    if command -v tput >/dev/null 2>&1 && tput civis >/dev/null 2>&1; then
        hide_cursor=true
    fi

    for ((frame=0; frame<frames; frame++)); do
        local output=""
        for ((row=0; row<height; row++)); do
            local line=""
            for ((col=0; col<width; col++)); do
                case $(( RANDOM % 10 )) in
                    0) line+=$(printf '%X' $((RANDOM % 16))) ;;
                    1) line+='│' ;;
                    *) line+=' ' ;;
                esac
            done
            output+="${line}\n"
        done
        printf "%b%s%b" "${color}" "${output}" "${reset}"
        sleep "${delay}"
        printf '\033[%dA' "${height}"
    done
    printf '\033[%dB' "${height}"
    printf "%b" "${reset}"

    [[ "${hide_cursor}" == true ]] && tput cnorm >/dev/null 2>&1
}

cam_ui_render_banner() {
    local width="${1:-$(tput cols 2>/dev/null || echo 80)}"
    local color_cyan="${2:-"\033[36m"}"
    local color_green="${3:-"\033[32m"}"
    local color_yellow="${4:-"\033[33m"}"
    local color_blue="${5:-"\033[34m"}"
    local color_reset="${6:-"\033[0m"}"
    local mode="${7:-unknown}"
    local port_label="${8:-Ports}"
    local run_dir="${9:-"./dev/results"}"
    local extras_label="${10:-None}"
    local color_orange="${color_yellow}"

    local ascii_lines=(
        "▐▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▌"
        "▐  ██████╗ █████╗ ███╗   ███╗███████╗███╗   ██╗██╗███████╗███████╗ ▌"
        "▐ ██╔════╝██╔══██╗████╗ ████║██╔════╝████╗  ██║██║██╔════╝██╔════╝ ▌"
        "▐ ██║     ███████║██╔████╔██║███████╗██╔██╗ ██║██║█████╗  █████╗   ▌"
        "▐ ██║     ██╔══██║██║╚██╔╝██║╚════██║██║╚██╗██║██║██╔══╝  ██╔══╝   ▌"
        "▐ ╚██████╗██║  ██║██║ ╚═╝ ██║███████║██║ ╚████║██║██║     ██║      ▌"
        "▐  ╚═════╝╚═╝  ╚═╝╚═╝     ╚═╝╚══════╝╚═╝  ╚═══╝╚═╝╚═╝     ╚═╝      ▌"
        "▐                          Version 2.2.3                           ▌"
        "▐▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▌"
    )

    for line in "${ascii_lines[@]}"; do
        cam_ui_center_line "${width}" "${line}" "${color_cyan}" "${color_reset}"
    done
    cam_ui_center_line "${width}" ""
    printf "\n"
    cam_ui_center_line "${width}" "${color_cyan}CamSniff - IP Camera Reconnaissance${color_reset}"
    cam_ui_center_line "${width}" ""
    cam_ui_center_line "${width}" "Automated IP-camera reconnaissance toolkit"
    cam_ui_center_line "${width}" "Performs multi-stage sweeps with advanced scanning"
    cam_ui_center_line "${width}" "Attempts to access and display video streams from identified devices."
    printf "\n"
    cam_ui_center_line "${width}" "     ${color_blue}//////////////////////////////${color_reset}"
    cam_ui_center_line "${width}" "     ${color_blue}Use only on authorized networks.${color_reset}"
    cam_ui_center_line "${width}" "     ${color_blue}//////////////////////////////${color_reset}"
    printf "\n"
    cam_ui_center_line "${width}" "Mode: ${color_green}${mode}${color_reset} (${port_label})"
    cam_ui_center_line "${width}" "Run artifacts: ${color_green}${run_dir}${color_reset}"
    cam_ui_center_line "${width}" "Extras enabled: ${color_green}${extras_label}${color_reset}"
    printf "\n\n"

    cam_ui_center_line "${width}" "Happens Next:" "${color_blue}" "${color_reset}"
    cam_ui_center_line "${width}" "${color_orange}1.${color_reset} dependencies check/install"
    cam_ui_center_line "${width}" "${color_orange}2.${color_reset} Scans local network configuration"
    cam_ui_center_line "${width}" "${color_orange}3.${color_reset} Main scan phase initialization (${color_green}${mode}${color_reset})"
    cam_ui_center_line "${width}" "${color_orange}4.${color_reset} Service detection and camera identification"
    printf "\n"
}
