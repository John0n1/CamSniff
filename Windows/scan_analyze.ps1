<#
.SYNOPSIS
  All scanning & analysis logic.
#>
. .\env_setup.ps1; . .\cleanup.ps1

# globals
$global:STREAMS       = @()
$global:HOSTS_SCANNED = @{}
$global:FIRST_RUN     = $true

# fetch RTSP paths
try {
  Invoke-WebRequest -Uri $RTSP_LIST_URL -OutFile "$env:TEMP\rtsp_paths.txt" -UseBasicParsing
  $RTSP_PATHS = Get-Content "$env:TEMP\rtsp_paths.txt"
} catch {
  $RTSP_PATHS = "live.sdp","h264","stream1","video"
}

# prepare Hydra creds file
$HTTP_CREDS = @(
  "admin:admin","admin:123456","admin:1234","admin:password",
  "root:root","root:123456","root:toor","user:user","guest:guest",":admin","admin:"
)
$HYDRA_FILE = "$env:TEMP\hydra_creds.txt"
$HTTP_CREDS | Out-File -Encoding ascii $HYDRA_FILE

function Get-AliveHosts {
  Log "🔍 Discovering alive hosts…"
  return & nmap -sn $SUBNET -oG - |
    Where-Object { $_ -match "Up" } |
    ForEach-Object { ($_ -split '\s+')[1] }
}

function Get-OpenPorts($h){
  Log "🔎 Port-scan $h…"
  return & nmap -Pn -p $PORTS $h -oG - |
    Where-Object { $_ -match "open" } |
    ForEach-Object {
      $c = $_ -split '\s+'; "$($c[1]):$($c[-2] -replace '/open','')"
    }
}

function Test-RTSP($u){
  try {
    & ffprobe -v error -timeout 500000 -rtsp_transport tcp -i $u 2>$null
    return $LASTEXITCODE -eq 0
  } catch { return $false }
}

function Test-HTTP($h,$p){
  foreach($c in $HTTP_CREDS){
    $u,$pw = $c.Split(":")
    try {
      $r = Invoke-WebRequest "http://$h`:$p/" `
           -Credential (New-Object PSCredential($u,(ConvertTo-SecureString $pw -AsPlainText -Force))) `
           -UseBasicParsing -TimeoutSec 5
      if($r.StatusCode -eq 200){ return "$u:$pw" }
    } catch {}
  }
  return $null
}

function Add-Stream($u){
  if($global:STREAMS.Count -lt $MAX_STREAMS -and -not ($global:STREAMS -contains $u)){
    $global:STREAMS += $u
  }
}

function Launch-Mosaic {
  if($global:STREAMS.Count -eq 0){ return }
  Log "🎞️  Launching mosaic…"
  $inputs = $global:STREAMS | ForEach-Object { "-i `"$($_)`"" }
  $layout = (0..($global:STREAMS.Count-1) |
    ForEach-Object { $row=[math]::Floor($_/2);$col=$_%2; "$col*0|$row*0" }) -join "|"
  $cmd = "ffmpeg $($inputs -join ' ') -filter_complex `"xstack=inputs=$($global:STREAMS.Count):layout=$layout`" -f matroska - | ffplay -loglevel error -"
  Start-Process -FilePath "powershell" -ArgumentList "-NoExit","-Command",$cmd
  $global:STREAMS = @()
}

function Screenshot-And-Analyze($u){
  $ip = ($u -replace '.*://([\d\.]+).*','$1')
  $out = "$env:TEMP\snap_${ip}.jpg"
  & ffmpeg -rtsp_transport tcp -i $u -frames:v 1 -q:v 2 -y $out | Out-Null
  Log "[SNAP] $u → $out"
  python - <<END
import cv2
img=cv2.imread(r"$out",0)
_,th=cv2.threshold(img,200,255,cv2.THRESH_BINARY)
cnt=cv2.countNonZero(th)
if cnt>50: print(f"[AI] IR spots detected ({cnt}px)")
END
}

function CVE-Check($hdr){
  if(Test-Path $CVE_DB){
    Get-Content $CVE_DB |
      Where-Object { $_ -match [regex]::Escape($hdr) } |
      Select-Object -First 3 |
      ForEach-Object { Log "[CVE] $_" }
  }
}

function Discover-ONVIF {
  Log "🔗 Discovering ONVIF…"
  python - <<END
from wsdiscovery.discovery import ThreadedWSDiscovery as WSD
wsd=WSD(); wsd.start(); svcs=wsd.searchServices()
print(f"[ONVIF] {len(svcs)} services")
for s in svcs: print("[ONVIF]",s.getXAddrs()[0])
wsd.stop()
END
}

function Discover-SSDP {
  Log "🔍 Discovering SSDP…"
  $msg = "M-SEARCH * HTTP/1.1`r`nHOST:239.255.255.250:1900`r`nST:urn:schemas-upnp-org:device:Basic:1`r`nMAN:`"ssdp:discover`"`r`nMX:2`r`n`r`n"
  $udp = New-Object Net.Sockets.UdpClient
  $udp.Client.SendTimeout = 2000
  $bytes = [Text.Encoding]::ASCII.GetBytes($msg)
  $udp.Send($bytes,$bytes.Length,"239.255.255.250",1900) | Out-Null
  try {
    while($true){
      $ep = New-Object Net.IPEndPoint([IPAddress]::Any,0)
      $resp = $udp.Receive([ref]$ep)
      $s = [Text.Encoding]::ASCII.GetString($resp)
      $s.Split("`r`n") | Where-Object{$_ -match "^LOCATION:"} |
        ForEach-Object{Log "[SSDP] $($_ -replace '^LOCATION:\s*','')"}
    }
  } catch{}
  $udp.Close()
}

function Sweep {
  Log "===== SWEEP $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') ====="
  # Alive hosts
  $alive = & nmap -sn $SUBNET -oG - |
    Where-Object{$_ -match "Up"} | ForEach-Object{($_ -split '\s+')[1]}

  if($global:FIRST_RUN){
    Log "🚀 First-run masscan…"
    $scan = & masscan $SUBNET -p$PORTS --rate $MASSCAN_RATE -oL - 2>$null |
      Where-Object{$_ -match "open"} |
      ForEach-Object{ ($_.Split()[3]+":"+($_.Split()[2])) }
    $global:FIRST_RUN = $false
  } else {
    $new = $alive | Where-Object{ -not $global:HOSTS_SCANNED.ContainsKey($_) }
    if($new){
      Log "🆕 Masscan new: $($new -join ', ')"
      $scan = & masscan $new -p$PORTS --rate $MASSCAN_RATE -oL - 2>$null |
        Where-Object{$_ -match "open"} |
        ForEach-Object{ ($_.Split()[3]+":"+($_.Split()[2])) }
    } else { $scan = @() }
  }

  foreach($e in $scan){
    $ip,$port = $e -split ":"
    $global:HOSTS_SCANNED[$ip]=1
    switch($port){
      {$_ -in 554,8554,10554,5544,1055} { Scan-RTSP $ip $port }
      {$_ -in 80,8080,8000,81,443}       { Scan-HTTP $ip $port }
      {$_ -eq 161}                      { Scan-SNMP $ip }
    }
  }

  Discover-ONVIF; Discover-SSDP
  foreach($h in $alive){ Scan-CoAP $h }
  foreach($h in $alive){ Scan-RTMP $h }

  Log "📸 Screenshot + AI…"
  foreach($u in $global:STREAMS){ Screenshot-And-Analyze $u }

  Log "🖼️  Mosaic…"
  Launch-Mosaic

  Log "🎮 TUI…"
  if($global:STREAMS.Count -and (Get-Command fzf -ErrorAction SilentlyContinue)){
    $sel = $global:STREAMS | fzf --prompt "Select> "
    if($sel){ Start-Process ffplay -ArgumentList "`"$sel`"" }
  }

  # plugins
  Run-Plugins
}
