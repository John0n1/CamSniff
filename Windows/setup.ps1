<#
.SYNOPSIS
  Core logging & prerequisite check.
#>
function Log {
  param([string]$Msg)
  $t = Get-Date -Format "HH:mm:ss"
  Write-Host "[$t]" $Msg -ForegroundColor Yellow
}

# Ensure jq, curl, nc, ffprobe, ffplay exist (warn/install)
$tools = @{ jq="jq"; curl="curl"; nc="ncat"; ffprobe="ffmpeg"; ffplay="ffmpeg" }
foreach($t in $tools.Keys){
  if(-not (Get-Command $t -ErrorAction SilentlyContinue)){
    if($t -eq "jq"){ 
      Log "‘jq’ missing → installing via choco…"
      choco install jq -y | Out-Null
    } else {
      Log "⚠️  '$t' not found; some features may not work."
    }
  }
}
