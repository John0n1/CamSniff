<#
.SYNOPSIS
  Cleanup ffplay/nmap/tshark on exit.
#>
function Cleanup {
  Log "🧹 Cleaning up…"
  Get-Process ffplay,tshark,nmap -ErrorAction SilentlyContinue |
    Stop-Process -Force -ErrorAction SilentlyContinue
}
# ensure we catch CTRL-C / exit
Register-EngineEvent PowerShell.Exiting -Action { Cleanup } | Out-Null
