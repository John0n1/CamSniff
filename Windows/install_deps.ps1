<#
.SYNOPSIS
  Installs all native deps via Chocolatey + Python venv.
#>
. .\setup.ps1

Log "⏳ Installing dependencies via Chocolatey…"
$pkgs = @(
  "nmap","masscan","fping","hydra","fzf","wireshark-cli",
  "tcpdump","jq","curl","ffmpeg","snmp","python","git","rtmpdump",
  "cmake","pkg-configlite","autoconf","automake","libtool","chafa"
)
foreach($pkg in $pkgs){
  if(-not (choco list --local-only | Select-String "^$pkg ")){
    Log "→ Installing $pkg"
    choco install $pkg -y | Out-Null
  } else { Log "$pkg already installed" }
}

# Python venv & deps
$venv = "$PSScriptRoot\.camvenv"
if(-not (Test-Path $venv)){
  Log "Creating Python venv…"
  python -m venv $venv
}
Log "Activating venv & installing Py modules…"
& "$venv\Scripts\Activate.ps1"
python -m pip install --upgrade pip | Out-Null
python -m pip install wsdiscovery opencv-python | Out-Null

Log "✅ Deps ready!"
