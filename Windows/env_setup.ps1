<#
.SYNOPSIS
  Generate/load camcfg.json + detect network.
#>
. .\setup.ps1

# default config
$def = @'
{
  "sleep_seconds": 45,
  "nmap_ports": "1-65535",
  "masscan_rate": 20000,
  "hydra_rate": 16,
  "max_streams": 4,
  "cve_db": "C:\\cve\\cve-2025.json",
  "dynamic_rtsp_url": "https://raw.githubusercontent.com/maaaaz/michelle/master/rtsp.txt"
}
'@

if(-not (Test-Path "$PSScriptRoot\camcfg.json")){
  Log "Creating default camcfg.json"
  $def | Out-File -Encoding UTF8 "$PSScriptRoot\camcfg.json"
}

# load it
Log "Loading config…"
$cfg = Get-Content "$PSScriptRoot\camcfg.json" | ConvertFrom-Json
$SS            = $cfg.sleep_seconds
$PORTS         = $cfg.nmap_ports
$MASSCAN_RATE  = $cfg.masscan_rate
$HYDRA_RATE    = $cfg.hydra_rate
$MAX_STREAMS   = $cfg.max_streams
$CVE_DB        = $cfg.cve_db
$RTSP_LIST_URL = $cfg.dynamic_rtsp_url

# network interface + subnet (via default route)
$r = Get-NetRoute -DestinationPrefix "0.0.0.0/0" |
     Sort-Object RouteMetric | Select-Object -First 1
$ifObj = Get-NetIPConfiguration -InterfaceIndex $r.InterfaceIndex
$IF     = $ifObj.InterfaceAlias
$IP     = $ifObj.IPv4Address.IPAddress
$PL     = $ifObj.IPv4Address.PrefixLength
$SUBNET = "$IP/$PL"

Log "Interface: $IF, Subnet: $SUBNET"
