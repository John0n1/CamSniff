<#
.SYNOPSIS
  PowerShell-native CamSniff entrypoint.
#>
[CmdletBinding()]
param(
  [switch]$Headless
)

. .\setup.ps1
. .\install_deps.ps1
. .\env_setup.ps1
. .\scan_analyze.ps1
. .\cleanup.ps1

# pre-scan prompt
while($true){
  $yn = Read-Host "Start scanning? (Y/N)"
  if($yn -match '^[Yy]'){ break }
  if($yn -match '^[Nn]'){
    Log "Abort—cleanup & exit"
    Cleanup
    Remove-Item "$PSScriptRoot\camcfg.json" -ErrorAction SilentlyContinue
    exit 0
  }
}

Log "Scanning… Ctrl-C to stop"
Sweep

# keep sweeping
while($true){
  Log "Sleeping ${SS}s…"
  Start-Sleep -Seconds $SS
  Sweep
}
