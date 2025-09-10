<# 
  AD Full Diagnostic – DCDiag + Health + Replication + DFSR + DNS/LDAPS + Events + GPO + Disk + Hardening
  Base: scripts do Eduardo Popovici (unificados e ampliados)
  Compatível: PowerShell 5.1 e 7+

  O que faz (visão geral):
   1) DCDiag (/e /q /v /c /fix) => TXT + HTML (parser EN/PT focado em FAIL/WARN).
   2) Health por DC: ping, serviços, shares, portas TCP/UDP (ampliadas), DNS funcional, dcdiag por teste (com timeout).
   3) Replicação: repadmin /replsummary + /showrepl (csv) e destaques (Fails/Largest Delta).
   4) DFS-R SYSVOL: replicationstate + backlog entre pares (heurística).
   5) FSMO: netdom query fsmo; PDC tests; w32tm (status/peers/config).
   6) DNS: zonas AD-integradas, forwarders, root hints, quick-resolve dos forwarders.
   7) LDAPS: 636/TCP (já na matriz) + tentativa de leitura de certificado (quando possível).
   8) Eventos críticos (24h): Directory Service / DFS Replication / DNS Server.
   9) GPO Skew: divergência VersionDirectory vs VersionSysvol (se RSAT-GPO instalado).
  10) Disco: espaço livre por volume em cada DC; tamanho NTDS/SYSVOL.
  11) Hardening: LDAP signing/channel binding, SMB signing required, TLS mínimo (SChannel), AD Recycle Bin, idade krbtgt.

  Saída: HTML único (tema do script 2) + TXT do DCDiag; CSV/JSON opcionais da Matriz de Saúde.
#>

[CmdletBinding()]
param(
  [string]$Domain,                         # Detecta automaticamente, se vazio
  [Parameter(Mandatory=$true)][string]$AnalystName,
  [Parameter(Mandatory=$true)][string]$ClientName,
  [int]$TimeoutSeconds = 180,

  # Saídas
  [string]$OutputPath,                     # HTML consolidado (default: Desktop\AD-FullDiag_<dom>_<ts>.html)
  [string]$ExportCsv,                      # Export opcional da Matriz de Saúde (CSV)
  [string]$ExportJson                      # Export opcional da Matriz de Saúde (JSON)
)

$ErrorActionPreference = 'Stop'
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Unrestricted -Force

# ------------------------
# Utilidades
# ------------------------
function Escape-Html {
  param([string]$Text)
  if ($null -eq $Text) { return '' }
  $t = $Text -replace '&','&amp;'
  $t = $t -replace '<','&lt;'
  $t = $t -replace '>','&gt;'
  $t = $t -replace '"','&quot;'
  $t = $t -replace "'",'&#39;'
  return $t
}
function Get-CellClass {
  param([Parameter(Mandatory)][string]$Status)
  switch -Regex ($Status) {
    '^(Success|Running|Passed|Open|Reachable|OK)$' { 'cpass' }
    '^(Failed|Closed|PingFail|Unreachable|ERROR)$' { 'cfail' }
    default                                        { 'cwarn' } # Unknown, Timeout, ConnError, NoReply etc.
  }
}
function Safe-Run {
  param([ScriptBlock]$Script,[string]$Fallback='N/D')
  try { & $Script } catch { $Fallback }
}

# ------------------------
# Descoberta Floresta/DCs
# ------------------------
try {
  $forest = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
  $DCServers = $forest.Domains | ForEach-Object { $_.DomainControllers } | ForEach-Object { $_.Name } | Sort-Object -Unique
  if (-not $Domain -or [string]::IsNullOrWhiteSpace($Domain)) { $Domain = $forest.RootDomain.Name }
  if (-not $DCServers) { throw "Nenhum DC encontrado." }
} catch {
  throw "Falha ao enumerar DCs/Floresta: $($_.Exception.Message)"
}

# ------------------------
# Saídas/Caminhos
# ------------------------
$timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$desktop   = Join-Path $env:USERPROFILE 'Desktop'
if (-not $OutputPath -or [string]::IsNullOrWhiteSpace($OutputPath)) {
  $OutputPath = Join-Path $desktop ("AD-FullDiag_{0}_{1}.html" -f $Domain,$timestamp)
}
$outTxt = Join-Path $desktop ("DCDiag_{0}_{1}.txt" -f $Domain,$timestamp)

# ------------------------
# DCDiag completo (TXT + parser)
# ------------------------
$dcdiagCmd = Get-Command dcdiag -ErrorAction SilentlyContinue
if (-not $dcdiagCmd) { throw "dcdiag não encontrado. Instale RSAT AD DS Tools ou execute em um DC." }

Write-Host "Executando DCDIAG para o domínio $Domain ..."
$LASTEXITCODE = $null
$dcArgs = @('/e','/q','/v','/c','/fix',"/testdomain:$Domain")
$null = & dcdiag @dcArgs 2>&1 | Tee-Object -Variable dcRaw
$dcOutput = $dcRaw
$dcOutput | Out-File -FilePath $outTxt -Encoding UTF8
$exitCode = $LASTEXITCODE

# Parser EN/PT
$serverRegexEN = '^\s*Testing server:\s*(.+)$'
$serverRegexPT = '^\s*Testando servidor:\s*(.+)$'
$startRegexEN  = '^\s*Starting test:\s*(.+)$'
$startRegexPT  = '^\s*Iniciando teste:\s*(.+)$'
$rxFail = [regex]'(?i)\bfailed\b|\bfalhou\b|\bfatal\b|\berror(s)?\b|\berro\b|\bcritical\b|\bcr[ií]tico\b|n[ãa]o.*(responde|dispon[ií]vel)|cannot|could not|failed to'
$rxWarn = [regex]'(?i)\bwarn(ing)?\b|aviso(s)?'

$dcTests = New-Object System.Collections.Generic.List[object]
$currentServer = $null; $currentTest = $null
$currentLines  = New-Object System.Collections.Generic.List[string]

function Flush-DCTest {
  param([string]$Server,[string]$Test,[System.Collections.Generic.List[string]]$Lines)
  if ([string]::IsNullOrWhiteSpace($Test)) { return }
  $joined = ($Lines -join "`n")
  $isFail = $rxFail.IsMatch($joined)
  $isWarn = (-not $isFail) -and $rxWarn.IsMatch($joined)
  $status = if ($isFail) {'FAIL'} elseif ($isWarn) {'WARN'} else {'PASS'}
  $firstHit = ($Lines | Where-Object { $_ -match $rxFail.ToString() -or $_ -match $rxWarn.ToString() } | Select-Object -First 4) -join ' | '
  $dcTests.Add([pscustomobject]@{ Server=$Server; Test=$Test; Status=$status; Detail=$firstHit })
  $Lines.Clear()
}
foreach ($line in $dcOutput) {
  if ($line -match $serverRegexEN -or $line -match $serverRegexPT) {
    Flush-DCTest -Server $currentServer -Test $currentTest -Lines $currentLines
    $currentServer = $Matches[1].Trim(); $currentTest = $null; continue
  }
  if ($line -match $startRegexEN -or $line -match $startRegexPT) {
    Flush-DCTest -Server $currentServer -Test $currentTest -Lines $currentLines
    $currentTest = $Matches[1].Trim(); continue
  }
  if ($currentTest) { $currentLines.Add([string]$line) }
}
Flush-DCTest -Server $currentServer -Test $currentTest -Lines $currentLines
if ($dcTests.Count -eq 0) {
  $dcTests.Add([pscustomobject]@{
    Server='N/D'; Test='Resumo';
    Status= if ($exitCode -eq 0) {'PASS'} else {'WARN'};
    Detail="Saída minimizada por /q. Consulte o TXT: $outTxt"
  })
}

# ------------------------
# Health por DC (conectividade/serviços/portas/DNS + mini-dcdiag por teste)
# ------------------------
function Test-PingHost {
  param([Parameter(Mandatory)][string]$ComputerName,[int]$TimeoutSeconds=3)
  try {
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = "$env:SystemRoot\System32\PING.EXE"
    $psi.Arguments = "-n 1 -w $([int]($TimeoutSeconds*1000)) $ComputerName"
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError  = $true
    $p = [System.Diagnostics.Process]::Start($psi)
    $null = $p.WaitForExit(($TimeoutSeconds+1)*1000)
    if ($p.HasExited -and $p.ExitCode -eq 0) { return $true }
  } catch {}
  return $false
}
function Test-TcpPort {
  param([Parameter(Mandatory)][string]$ComputerName,[Parameter(Mandatory)][int]$Port,[int]$TimeoutSeconds=3)
  try {
    $client = New-Object System.Net.Sockets.TcpClient
    $iar = $client.BeginConnect($ComputerName,$Port,$null,$null)
    if (-not $iar.AsyncWaitHandle.WaitOne($TimeoutSeconds*1000)) { $client.Close(); return 'Closed' }
    $client.EndConnect($iar) | Out-Null
    $client.Close(); return 'Open'
  } catch { return 'Closed' }
}
function Test-UdpPort {
  param([Parameter(Mandatory)][string]$ComputerName,[Parameter(Mandatory)][int]$Port,[int]$TimeoutSeconds=3)
  try {
    $udp = New-Object System.Net.Sockets.UdpClient
    $udp.Client.ReceiveTimeout = $TimeoutSeconds*1000
    $udp.Connect($ComputerName,$Port)
    $bytes = [System.Text.Encoding]::ASCII.GetBytes("hi")
    [void]$udp.Send($bytes,$bytes.Length)
    Start-Sleep -Milliseconds 300
    if ($udp.Available -gt 0) { 
      $null = $udp.Receive([ref]([System.Net.IPEndPoint]::new([System.Net.IPAddress]::Any,0)))
      $udp.Close(); return 'Open'
    } else { $udp.Close(); return 'NoReply' }
  } catch { try { $udp.Close() } catch {}; return 'NoReply' }
}
function Get-ServiceStatusSafe {
  param([Parameter(Mandatory)][string]$ComputerName,[Parameter(Mandatory)][string]$ServiceName)
  try {
    $svc = Get-Service -ComputerName $ComputerName -Name $ServiceName -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($null -eq $svc) { return 'Unknown' }
    if ($svc.Status -eq 'Running') { 'Running' } else { [string]$svc.Status }
  } catch { 'Unknown' }
}
function Test-UncShare {
  param([Parameter(Mandatory)][string]$ComputerName,[Parameter(Mandatory)][ValidateSet('NETLOGON','SYSVOL')] [string]$ShareName)
  try {
    if (Test-Path -LiteralPath ("filesystem::\\{0}\{1}" -f $ComputerName,$ShareName) -ErrorAction SilentlyContinue) { 'Passed' }
    else { 'Failed' }
  } catch { 'Failed' }
}
function Invoke-DcDiagTest {
  param([Parameter(Mandatory)][string]$ComputerName,[Parameter(Mandatory)]
        [ValidateSet('Netlogons','Replications','Services','Advertising','FSMOCheck')] [string]$TestName,
        [int]$Timeout=180)
  try { $exe = (Get-Command -Name 'dcdiag.exe' -ErrorAction Stop).Source } catch { return 'Failed' }
  $psi = New-Object System.Diagnostics.ProcessStartInfo
  $psi.FileName = $exe
  $psi.Arguments = "/test:$TestName /s:$ComputerName"
  $psi.UseShellExecute = $false
  $psi.RedirectStandardOutput = $true
  $psi.RedirectStandardError  = $true
  $proc = New-Object System.Diagnostics.Process
  $proc.StartInfo = $psi
  try {
    $null = $proc.Start()
    $finished = $proc.WaitForExit($Timeout*1000)
    if (-not $finished) { try { $proc.Kill() | Out-Null } catch {}; return 'Timeout' }
    $output = $proc.StandardOutput.ReadToEnd() + $proc.StandardError.ReadToEnd()
  } catch { return 'Failed' }
  finally { try { $proc.Close() } catch {} }
  $lower = $output.ToLowerInvariant()
  if ($lower -match 'no longer available|cannot be contacted|rpc server is unavailable') { return 'ConnError' }
  if ($lower -match "passed\s+test\s+$($TestName.ToLowerInvariant())") { return 'Passed' }
  return 'Failed'
}

# Portas – ampliadas
$TcpPortsToCheck = [ordered]@{
  KerberosTCP = 88
  LDAPTCP     = 389
  LDAPS       = 636
  GCLDAP      = 3268
  GCLDAPS     = 3269
  NTLM_RPC135 = 135
  NTLM_139    = 139
  NTLM_445    = 445
  DNS_TCP     = 53
  WINRM_5985  = 5985
  WINRM_5986  = 5986
  RDP_3389    = 3389
}
$UdpPortsToCheck = [ordered]@{
  KerberosUDP = 88
  LDAPUDP     = 389
  DNS_UDP     = 53
  NTP_123     = 123
}

$StartDate = Get-Date
$Health = foreach ($dcFqdn in $DCServers) {
  $short = ($dcFqdn -split '\.')[0]

  $pingOkFqdn  = Test-PingHost -ComputerName $dcFqdn -TimeoutSeconds 3
  $pingOkShort = $false; if (-not $pingOkFqdn) { $pingOkShort = Test-PingHost -ComputerName $short -TimeoutSeconds 3 }
  $pingOk = $pingOkFqdn -or $pingOkShort
  $pingStatus = if ($pingOk) { 'Success' } else { 'PingFail' }
  $target = if ($pingOkShort) { $short } else { $dcFqdn }

  $netlogon = Get-ServiceStatusSafe -ComputerName $target -ServiceName 'Netlogon'
  $ntds     = Get-ServiceStatusSafe -ComputerName $target -ServiceName 'NTDS'
  $dnsSvc   = Get-ServiceStatusSafe -ComputerName $target -ServiceName 'DNS'

  $tNetlogons   = Invoke-DcDiagTest -ComputerName $target -TestName 'Netlogons'    -Timeout $TimeoutSeconds
  $tRepl        = Invoke-DcDiagTest -ComputerName $target -TestName 'Replications' -Timeout $TimeoutSeconds
  $tServices    = Invoke-DcDiagTest -ComputerName $target -TestName 'Services'     -Timeout $TimeoutSeconds
  $tAdvertising = Invoke-DcDiagTest -ComputerName $target -TestName 'Advertising'  -Timeout $TimeoutSeconds
  $tFSMO        = Invoke-DcDiagTest -ComputerName $target -TestName 'FSMOCheck'    -Timeout $TimeoutSeconds

  $tNetlogonShare = Test-UncShare -ComputerName $target -ShareName 'NETLOGON'
  $tSysvolShare   = Test-UncShare -ComputerName $target -ShareName 'SYSVOL'

  $tcpStatus = @{}
  foreach ($k in $TcpPortsToCheck.Keys) { $tcpStatus[$k] = Test-TcpPort -ComputerName $target -Port $TcpPortsToCheck[$k] -TimeoutSeconds 3 }
  $udpStatus = @{}
  foreach ($k in $UdpPortsToCheck.Keys) { $udpStatus[$k] = Test-UdpPort -ComputerName $target -Port $UdpPortsToCheck[$k] -TimeoutSeconds 3 }

  $dnsA='Unknown'; $dnsSRV='Unknown'; $dnsPTR='Unknown'
  try {
    $aRec = Resolve-DnsName -Name $target -Type A -Server $target -ErrorAction Stop
    $dnsA = if ($aRec -and ($aRec | Where-Object {$_.IPAddress})) { 'Passed' } else { 'Failed' }
  } catch { $dnsA = 'Failed' }
  try {
    $srvRec = Resolve-DnsName -Name ("_ldap._tcp.dc._msdcs.{0}" -f $Domain) -Type SRV -Server $target -ErrorAction Stop
    $dnsSRV = if ($srvRec) { 'Passed' } else { 'Failed' }
  } catch { $dnsSRV = 'Failed' }
  try {
    if ($dnsA -eq 'Passed') {
      $ip = (Resolve-DnsName -Name $target -Type A -Server $target -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty IPAddress)
      if ($ip) {
        $ptr = Resolve-DnsName -Name $ip -Type PTR -Server $target -ErrorAction Stop
        $dnsPTR = if ($ptr) { 'Passed' } else { 'Failed' }
      } else { $dnsPTR = 'Failed' }
    } else { $dnsPTR='Unknown' }
  } catch { $dnsPTR = 'Failed' }

  [pscustomobject]@{
    Identity          = $dcFqdn
    PingStatus        = $pingStatus
    NetlogonService   = $netlogon
    NTDSService       = $ntds
    DNSServiceStatus  = $dnsSvc
    NetlogonsTest     = $tNetlogons
    ReplicationTest   = $tRepl
    ServicesTest      = $tServices
    AdvertisingTest   = $tAdvertising
    NETLOGONTest      = $tNetlogonShare
    SYSVOLTest        = $tSysvolShare
    FSMOCheckTest     = $tFSMO
    KerberosTCP       = $tcpStatus.KerberosTCP
    LDAPTCP           = $tcpStatus.LDAPTCP
    LDAPS             = $tcpStatus.LDAPS
    GCLDAP            = $tcpStatus.GCLDAP
    GCLDAPS           = $tcpStatus.GCLDAPS
    NTLM_RPC135       = $tcpStatus.NTLM_RPC135
    NTLM_139          = $tcpStatus.NTLM_139
    NTLM_445          = $tcpStatus.NTLM_445
    DNS_TCP           = $tcpStatus.DNS_TCP
    WINRM_5985        = $tcpStatus.WINRM_5985
    WINRM_5986        = $tcpStatus.WINRM_5986
    RDP_3389          = $tcpStatus.RDP_3389
    KerberosUDP       = $udpStatus.KerberosUDP
    LDAPUDP           = $udpStatus.LDAPUDP
    DNS_UDP           = $udpStatus.DNS_UDP
    NTP_123           = $udpStatus.NTP_123
    DNS_A_Self        = $dnsA
    DNS_SRV_Forest    = $dnsSRV
    DNS_PTR_Self      = $dnsPTR
    AnalystName       = $AnalystName
    ClientName        = $ClientName
  }
}
$Health = $Health | Sort-Object Identity

if ($ExportCsv)  { try { $Health | Export-Csv -NoTypeInformation -Path $ExportCsv -Encoding UTF8 } catch { Write-Warning "CSV: $($_.Exception.Message)" } }
if ($ExportJson) { try { $Health | ConvertTo-Json -Depth 4 | Out-File -FilePath $ExportJson -Encoding UTF8 } catch { Write-Warning "JSON: $($_.Exception.Message)" } }

# ------------------------
# Replicação (repadmin)
# ------------------------
$repSummaryRaw = Safe-Run { (& repadmin /replsummary 2>&1) } -Fallback @("repadmin /replsummary indisponível")
$repSummary    = ($repSummaryRaw -join "`n")

$showReplCsv   = Safe-Run { (& repadmin /showrepl * /csv 2>&1) } -Fallback @("repadmin /showrepl /csv indisponível")
$showReplText  = ($showReplCsv -join "`n")
# Heurística simples
$largestDelta  = ($repSummary -split "`n" | Where-Object {$_ -match 'Largest Delta'} | Select-Object -First 1)
$failsLine     = ($repSummary -split "`n" | Where-Object {$_ -match '%\s*Errors'} | Select-Object -First 1)

# ------------------------
# DFS-R SYSVOL
# ------------------------
$dfsrState  = Safe-Run { (& dfsrdiag replicationstate 2>&1) } -Fallback @("dfsrdiag replicationstate indisponível") | Out-String
$dfsrBacklogs = New-Object System.Collections.Generic.List[string]
if ($DCServers.Count -ge 2) {
  for ($i=0; $i -lt $DCServers.Count; $i++) {
    for ($j=0; $j -lt $DCServers.Count; $j++) {
      if ($i -ne $j) {
        $src = $DCServers[$i]; $dst = $DCServers[$j]
        $b = Safe-Run { (& dfsrdiag backlog /rgname:"Domain System Volume" /rfname:"SYSVOL Share" /smember:$src /rmember:$dst 2>&1) } -Fallback @("dfsrdiag backlog $src->$dst indisponível")
        $dfsrBacklogs.Add(("SRC {0} -> DST {1}`n{2}" -f $src,$dst,($b -join "`n")))
      }
    }
  }
}

# ------------------------
# FSMO / PDC / RID Test
# ------------------------
$fsmoRaw = Safe-Run { (& netdom query fsmo 2>&1) } -Fallback @("netdom query fsmo indisponível")
$fsmo    = ($fsmoRaw -join "`n")
$pdc = Safe-Run { ([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()).PdcRoleOwner.Name } -Fallback 'N/D'
$ridTest = Safe-Run { (& dcdiag /test:ridmanager /s:$pdc /v 2>&1) } -Fallback @("dcdiag /test:ridmanager indisponível") | Out-String

# ------------------------
# Tempo (W32Time)
# ------------------------
$w32status = Safe-Run { (& w32tm /query /status 2>&1) } -Fallback @("w32tm /status indisponível") | Out-String
$w32peers  = Safe-Run { (& w32tm /query /peers  2>&1) } -Fallback @("w32tm /peers indisponível") | Out-String
$w32config = Safe-Run { (& w32tm /query /configuration 2>&1) } -Fallback @("w32tm /configuration indisponível") | Out-String

# ------------------------
# DNS (zonas, forwarders, root hints)
# ------------------------
$dnsRef = $DCServers[0]
$zones     = Safe-Run { Get-DnsServerZone -ComputerName $dnsRef -ErrorAction Stop } -Fallback @()
$forwarders= Safe-Run { Get-DnsServerForwarder -ComputerName $dnsRef -ErrorAction Stop } -Fallback @()
$rootHints = Safe-Run { Get-DnsServerRootHint -ComputerName $dnsRef -ErrorAction Stop } -Fallback @()

# Quick test dos forwarders (Resolve-DnsName)
$fwTests = @()
foreach ($fw in $forwarders) {
  $ip = $fw.IPAddress.IPAddressToString
  if ($ip) {
    $ok = $false
    try { $x = Resolve-DnsName -Name "www.microsoft.com" -Type A -Server $ip -ErrorAction Stop; $ok = $true } catch { $ok = $false }
    $resText = if ($ok) { 'OK' } else { 'Fail' }
    $fwTests += [pscustomobject]@{ Forwarder=$ip; ResolveMsCom=$resText }
  }
}

# ------------------------
# LDAPS — tentativa de leitura de certificados (localmente, se rodar em DC)
# ------------------------
$ldapsCerts = Safe-Run {
  Get-ChildItem -Path Cert:\LocalMachine\My |
    Where-Object { $_.EnhancedKeyUsageList.FriendlyName -contains 'Server Authentication' } |
    Select-Object Subject, NotBefore, NotAfter, Thumbprint
} -Fallback @()

# ------------------------
# Eventos críticos (24h)
# ------------------------
$since = (Get-Date).AddHours(-24)
$critEvents = foreach ($dc in $DCServers) {
  [pscustomobject]@{
    DC    = $dc
    AD_DS = (Safe-Run { Get-WinEvent -ComputerName $dc -FilterHashtable @{LogName='Directory Service'; Level=1,2; StartTime=$since} -MaxEvents 200 } -Fallback @())
    DFSR  = (Safe-Run { Get-WinEvent -ComputerName $dc -FilterHashtable @{LogName='DFS Replication';  Level=1,2; StartTime=$since} -MaxEvents 200 } -Fallback @())
    DNS   = (Safe-Run { Get-WinEvent -ComputerName $dc -FilterHashtable @{LogName='DNS Server';       Level=1,2; StartTime=$since} -MaxEvents 200 } -Fallback @())
  }
}

# ------------------------
# GPO Skew (se RSAT-GPO disponível)
# ------------------------
$gpoModule = Get-Module -ListAvailable -Name GroupPolicy
$gpoSkew = @()
if ($gpoModule) {
  $gpos = Safe-Run { Get-GPO -All } -Fallback @()
  if ($gpos) {
    $gpoSkew = $gpos | Where-Object { $_.GpoStatus -ne 'AllSettingsDisabled' -and $_.VersionDirectory -ne $_.VersionSysvol } |
               Select-Object DisplayName, Id, VersionDirectory, VersionSysvol
  }
}

# ------------------------
# Disco / NTDS / SYSVOL
# ------------------------
$disk = foreach ($dc in $DCServers) {
  Safe-Run {
    Get-CimInstance -ClassName Win32_LogicalDisk -ComputerName $dc -Filter "DriveType=3" |
      Select-Object @{n='DC';e={$dc}}, DeviceID, @{n='FreeGB';e={[math]::Round($_.FreeSpace/1GB,2)}}, @{n='SizeGB';e={[math]::Round($_.Size/1GB,2)}}
  } -Fallback @()
}
$pathsInfo = foreach ($dc in $DCServers) {
  $sysRoot = "\\$dc\c$"
  $ntdsP   = "$sysRoot\Windows\NTDS"
  $sysvolP = "$sysRoot\Windows\SYSVOL\domain"
  $ntdsSize = Safe-Run { (Get-ChildItem -Recurse -Force -ErrorAction Stop $ntdsP | Measure-Object Length -Sum).Sum } -Fallback $null
  $sysvSize = Safe-Run { (Get-ChildItem -Recurse -Force -ErrorAction Stop $sysvolP | Measure-Object Length -Sum).Sum } -Fallback $null
  [pscustomobject]@{
    DC=$dc
    NTDS_GB  = if ($ntdsSize){ [math]::Round($ntdsSize/1GB,2) } else { 'N/D' }
    SYSVOL_GB= if ($sysvSize){ [math]::Round($sysvSize/1GB,2) } else { 'N/D' }
  }
}

# ------------------------
# Hardening: LDAP/SMB/TLS/Recycle Bin/krbtgt
# ------------------------
$hardening = [ordered]@{}
$hardening['LDAPServerIntegrity'] = Safe-Run { (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' -Name 'LDAPServerIntegrity' -ErrorAction Stop).LDAPServerIntegrity } -Fallback 'N/D'
$hardening['LdapEnforceChannelBinding'] = Safe-Run { (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' -Name 'LdapEnforceChannelBinding' -ErrorAction Stop).LdapEnforceChannelBinding } -Fallback 'N/D'
$hardening['SMBServer_RequireSecuritySignature']  = Safe-Run { (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name 'RequireSecuritySignature' -ErrorAction Stop).RequireSecuritySignature } -Fallback 'N/D'
$hardening['SMBClient_RequireSecuritySignature']  = Safe-Run { (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' -Name 'RequireSecuritySignature' -ErrorAction Stop).RequireSecuritySignature } -Fallback 'N/D'
$hardening['TLS1.0_Server_Disabled'] = Safe-Run { (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' -Name 'Enabled' -ErrorAction Stop).Enabled -eq 0 } -Fallback 'N/D'
$hardening['TLS1.1_Server_Disabled'] = Safe-Run { (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' -Name 'Enabled' -ErrorAction Stop).Enabled -eq 0 } -Fallback 'N/D'
$hardening['TLS1.2_Server_Enabled']  = Safe-Run { (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' -Name 'Enabled' -ErrorAction Stop).Enabled -eq 1 } -Fallback 'N/D'

$recycle = Safe-Run { (Get-ADOptionalFeature 'Recycle Bin Feature').EnabledScopes } -Fallback @()
$krbAgeDays = Safe-Run {
  $u = Get-ADUser -Identity 'krbtgt' -Properties PasswordLastSet
  if ($u.PasswordLastSet) { (New-TimeSpan -Start $u.PasswordLastSet -End (Get-Date)).Days } else { 'N/D' }
} -Fallback 'N/D'

$nlDsRegDns = Safe-Run { (& nltest /dsregdns 2>&1) -join "`n" } -Fallback "nltest /dsregdns indisponível"

# ------------------------
# HTML (tema script 2) + novas seções
# ------------------------
# Totais DCDiag
$total = $dcTests.Count
$pass  = ($dcTests | Where-Object {$_.Status -eq 'PASS'}).Count
$warn  = ($dcTests | Where-Object {$_.Status -eq 'WARN'}).Count
$fail  = ($dcTests | Where-Object {$_.Status -eq 'FAIL'}).Count

# Tabelas DCDiag por servidor
$servers = ($dcTests | Select-Object -ExpandProperty Server | Sort-Object -Unique)
$serverTables = foreach ($sv in $servers) {
  $rows = foreach ($t in ($dcTests | Where-Object {$_.Server -eq $sv})) {
    $cls = switch ($t.Status) { 'FAIL' {'fail'} 'WARN' {'warn'} default {'pass'} }
    "<tr class='$cls'><td>{0}</td><td>{1}</td><td>{2}</td><td><pre>{3}</pre></td></tr>" -f (Escape-Html $t.Test),(Escape-Html $t.Status),(Escape-Html $t.Server),(Escape-Html $t.Detail)
  }
@"
  <div class='section' id='sv_$(Escape-Html $sv)'>
    <h2>Servidor: $(Escape-Html $sv)</h2>
    <table>
      <thead><tr><th>Teste</th><th>Status</th><th>Servidor</th><th>Detalhe</th></tr></thead>
      <tbody>
        $($rows -join "`n")
      </tbody>
    </table>
  </div>
"@
}

$issues = $dcTests | Where-Object {$_.Status -ne 'PASS'}
$issueBlocks = if ($issues) {
  foreach ($i in $issues) {
@"
<div class='failcard'>
  <div class='ftitle'>$(Escape-Html $i.Server) — $(Escape-Html $i.Test)</div>
  <div class='fmeta'><b>Status:</b> $(Escape-Html $i.Status)</div>
  <div class='fdetail'><b>Detalhe:</b> <pre>$(Escape-Html $i.Detail)</pre></div>
</div>
"@
  }
} else { "<p>Sem falhas/avisos detectados com os parâmetros atuais (/q). Consulte o TXT para detalhes.</p>" }

# Matriz de Saúde (conectividade/portas/DNS)
$healthHeader = @"
  <thead>
    <tr>
      <th>Identity</th>
      <th>Ping</th>
      <th>Svc Netlogon</th>
      <th>Svc NTDS</th>
      <th>Svc DNS</th>
      <th>Share NETLOGON</th>
      <th>Share SYSVOL</th>
      <th>DcDiag Netlogons</th>
      <th>DcDiag Replication</th>
      <th>DcDiag Services</th>
      <th>DcDiag Advertising</th>
      <th>DcDiag FSMO</th>
      <th>Kerb 88 (TCP)</th>
      <th>Kerb 88 (UDP)</th>
      <th>LDAP 389 (TCP)</th>
      <th>LDAP 389 (UDP)</th>
      <th>LDAPS 636</th>
      <th>GC 3268</th>
      <th>GC SSL 3269</th>
      <th>DNS 53 (TCP)</th>
      <th>DNS 53 (UDP)</th>
      <th>NTP 123 (UDP)</th>
      <th>WINRM 5985</th>
      <th>WINRM 5986</th>
      <th>RDP 3389</th>
      <th>DNS A(Self)</th>
      <th>DNS SRV(Forest)</th>
      <th>DNS PTR(Self)</th>
    </tr>
  </thead>
"@
$healthRows = foreach ($r in $Health) {
  $cells = New-Object System.Collections.Generic.List[string]
  $cells.Add("<td><b>$(Escape-Html $r.Identity)</b></td>")
  foreach ($p in @(
      'PingStatus','NetlogonService','NTDSService','DNSServiceStatus',
      'NETLOGONTest','SYSVOLTest','NetlogonsTest','ReplicationTest','ServicesTest','AdvertisingTest','FSMOCheckTest',
      'KerberosTCP','KerberosUDP','LDAPTCP','LDAPUDP','LDAPS','GCLDAP','GCLDAPS','DNS_TCP','DNS_UDP','NTP_123',
      'WINRM_5985','WINRM_5986','RDP_3389',
      'DNS_A_Self','DNS_SRV_Forest','DNS_PTR_Self'
    )) {
    $val = [string]$r.$p
    $cls = Get-CellClass -Status $val
    $cells.Add("<td class='$cls'><b>$(Escape-Html $val)</b></td>")
  }
  "<tr>$($cells -join '')</tr>"
}

$noteQ = @"
<div class='note'>
  <b>Nota:</b> O parâmetro <code>/q</code> (quiet) reduz a verbosidade do DCDiag e pode ocultar testes aprovados.
  Use este HTML para focar em falhas/avisos e o TXT para análise completa.
  <div>Arquivo TXT: <code>$outTxt</code></div>
  <div>ExitCode DCDiag: <code>$exitCode</code></div>
</div>
"@
$noteUdp = @"
<div class='note'>
  <b>Nota sobre UDP / NoReply:</b> Em UDP não existe handshake como no TCP. O teste envia um datagrama simples; 
  se o servidor não responde (comum para Kerberos/LDAP/DNS/NTP em UDP), marcamos <i>NoReply</i>. 
  Isso não significa necessariamente porta fechada — pode estar <i>aberta porém silenciosa</i> ou filtrada por firewall. 
  Quando há retorno de erro/ICMP é marcado como <i>Closed</i>. Para conectividade crítica do AD, priorize portas TCP.
</div>
"@

# CSS do tema (script 2) + classes cpass/cwarn/cfail
$css = @"
  :root { color-scheme: light dark; }
  body { font-family: Segoe UI, Roboto, Arial, sans-serif; margin: 24px; }
  h1 { margin: 0 0 4px 0; font-size: 22px; }
  .sub { color:#555; margin: 0 0 16px 0; }
  .summary { display:flex; gap:16px; margin: 16px 0 12px 0; flex-wrap: wrap; }
  .card { padding:12px 16px; border-radius:10px; box-shadow:0 1px 3px rgba(0,0,0,.08); }
  .all { background:#eef4ff; border:1px solid #c9d8ff; }
  .ok  { background:#e8fff0; border:1px solid #b6f0c9; }
  .wrn { background:#fff9e6; border:1px solid #ffe08a; }
  .bad { background:#ffecec; border:1px solid #ffb3b3; }
  table { width:100%; border-collapse: collapse; }
  th, td { border-bottom:1px solid #eee; padding:8px 10px; vertical-align: top; text-align:left; }
  th { background:#fafafa; }
  tr.pass td { background:#f7fff9; }
  tr.warn td { background:#fff9ec; }
  tr.fail td { background:#fff7f7; }
  td.cpass { background:#f7fff9; }
  td.cwarn { background:#fff9ec; }
  td.cfail { background:#fff7f7; }
  pre { margin:0; white-space: pre-wrap; word-wrap: break-word; }
  .section { margin-top:28px; }
  .failcard { border:1px solid #ffd2d2; background:#fff5f5; padding:12px; border-radius:10px; margin-bottom:12px; }
  .ftitle { font-weight:600; margin-bottom:4px; }
  .fmeta { color:#333; margin-bottom:6px; }
  .note { margin:14px 0; padding:10px; border-radius:8px; background:#fff9e6; border:1px solid #ffe08a; }
  .meta { margin-top:18px; font-size:12px; color:#666; }
  code { background:#f2f2f2; padding:2px 6px; border-radius:6px; }
  @media (prefers-color-scheme: dark) {
    body { color:#eee; background:#121212; }
    .sub { color:#bbb; }
    .card { box-shadow:none; }
    .all { background:#1b2744; border-color:#30487c; }
    .ok  { background:#14301d; border-color:#1f7a46; }
    .wrn { background:#3a2f18; border-color:#7a6d2e; }
    .bad { background:#3a1b1b; border-color:#7a2e2e; }
    th, td { border-bottom:1px solid #2a2a2a; }
    th { background:#1b1b1b; }
    tr.pass td { background:#0e2216; }
    tr.warn td { background:#2f2a18; }
    tr.fail td { background:#2a1515; }
    td.cpass { background:#0e2216; }
    td.cwarn { background:#2f2a18; }
    td.cfail { background:#2a1515; }
    .fmeta { color:#ddd; }
    code { background:#1e1e1e; }
  }
"@

# ---- Função HTML-Table (compatível PS 5.1, sem operador ternário) ----
function Html-Table {
  param(
    [string]$title,
    [string[]]$headers,
    [string]$rows
  )
  $h2 = ''
  if (-not [string]::IsNullOrWhiteSpace($title)) {
    $h2 = "<h2>$(Escape-Html $title)</h2>"
  }
@"
<div class='section'>
  $h2
  <table>
    <thead><tr>$(($headers | ForEach-Object { "<th>$(Escape-Html $_)</th>" }) -join '')</tr></thead>
    <tbody>
      $rows
    </tbody>
  </table>
</div>
"@
}

# ---- Blocos HTML auxiliares ----
# Replicação (repadmin)
$repBlock = @"
<div class='section'>
  <h2>Infra de Replicação (repadmin)</h2>
  <div class='note'><b>Destaques:</b><pre>Largest Delta: $(Escape-Html $largestDelta)
$failsLine</pre></div>
  <h3>Resumo (/replsummary)</h3>
  <pre>$(Escape-Html $repSummary)</pre>
  <h3>ShowRepl (/showrepl * /csv – recorte)</h3>
  <pre>$(Escape-Html ($showReplText.Substring(0,[Math]::Min($showReplText.Length, 20000))))</pre>
  <small>(Exibição truncada para 20k chars)</small>
</div>
"@

# DFS-R
$dfsrBlock = @"
<div class='section'>
  <h2>DFSR – SYSVOL</h2>
  <h3>Replication State</h3>
  <pre>$(Escape-Html $dfsrState)</pre>
  <h3>Backlog entre pares</h3>
  <pre>$(Escape-Html (($dfsrBacklogs -join "`n`n")))</pre>
</div>
"@

# DNS
$zoneRows = if ($zones -and $zones.Count -gt 0) {
  ($zones | ForEach-Object {
    "<tr><td>$(Escape-Html $_.ZoneName)</td><td>$($_.IsDsIntegrated)</td><td>$($_.IsAutoCreated)</td><td>$($_.IsReverseLookupZone)</td><td>$($_.Aging)</td></tr>"
  }) -join "`n"
} else { "<tr><td colspan='5'>Sem dados (perm ou RSAT DNS ausente)</td></tr>" }
$fwRows = if ($forwarders -and $forwarders.Count -gt 0) {
  ($forwarders | ForEach-Object {
    $ip = $_.IPAddress.IPAddressToString
    $test = ($fwTests | Where-Object {$_.Forwarder -eq $ip} | Select-Object -First 1)
    "<tr><td>$ip</td><td>$($_.UseRootHint)</td><td>$([string]$test.ResolveMsCom)</td></tr>"
  }) -join "`n"
} else { "<tr><td colspan='3'>Sem forwarders</td></tr>" }
$rootRows = if ($rootHints -and $rootHints.Count -gt 0) {
  ($rootHints | Select-Object -First 20 | ForEach-Object {
    "<tr><td>$(Escape-Html $_.NameServer)</td><td>$(Escape-Html ($_.IPAddress -join ', '))</td></tr>"
  }) -join "`n"
} else { "<tr><td colspan='2'>Sem root hints</td></tr>" }

$dnsBlock = @"
<div class='section'>
  <h2>DNS (Zonas, Forwarders, Root Hints)</h2>
  $(Html-Table 'Zonas AD-integradas' @('Zona','DsIntegrated','AutoCreated','Reverse','Aging') $zoneRows)
  $(Html-Table 'Forwarders' @('IP','UseRootHint','Teste www.microsoft.com') $fwRows)
  $(Html-Table 'Root Hints (Top 20)' @('NameServer','IPs') $rootRows)
</div>
"@

# LDAPS certs
$ldapsRows = if ($ldapsCerts -and $ldapsCerts.Count -gt 0) {
  ($ldapsCerts | ForEach-Object {
    "<tr><td>$(Escape-Html $_.Subject)</td><td>$($_.NotBefore)</td><td>$($_.NotAfter)</td><td>$(Escape-Html $_.Thumbprint)</td></tr>"
  }) -join "`n"
} else { "<tr><td colspan='4'>Certificados não disponíveis nesta máquina ou sem EKU de Server Authentication.</td></tr>" }
$ldapsBlock = Html-Table 'LDAPS – Certificados (LocalMachine\My com EKU de Server Authentication)' @('Subject','NotBefore','NotAfter','Thumbprint') $ldapsRows

# Eventos críticos (contagem por DC)
$evRows = foreach ($e in $critEvents) {
  $adCnt = 0;  if ($e.AD_DS) { $adCnt  = @($e.AD_DS).Count }
  $dfCnt = 0;  if ($e.DFSR)  { $dfCnt  = @($e.DFSR).Count  }
  $dnCnt = 0;  if ($e.DNS)   { $dnCnt  = @($e.DNS).Count   }
  "<tr><td>$(Escape-Html $e.DC)</td><td>$adCnt</td><td>$dfCnt</td><td>$dnCnt</td></tr>"
} -join "`n"
$eventsBlock = Html-Table 'Eventos Críticos (últimas 24h)' @('DC','Directory Service (L1-2)','DFS Replication (L1-2)','DNS Server (L1-2)') $evRows

# GPO Skew
$gpoRows = if ($gpoSkew -and $gpoSkew.Count -gt 0) {
  ($gpoSkew | ForEach-Object {
    "<tr><td>$(Escape-Html $_.DisplayName)</td><td>$($_.Id)</td><td>$($_.VersionDirectory)</td><td>$($_.VersionSysvol)</td></tr>"
  }) -join "`n"
} else { "<tr><td colspan='4'>Sem divergências detectadas ou RSAT-GPO não disponível.</td></tr>" }
$gpoBlock = Html-Table 'GPO – Divergências de versão (Directory vs SYSVOL)' @('DisplayName','GUID','VersionDirectory','VersionSysvol') $gpoRows

# Disco
$diskRows = if ($disk -and $disk.Count -gt 0) {
  ($disk | ForEach-Object {
    "<tr><td>$(Escape-Html $_.DC)</td><td>$($_.DeviceID)</td><td>$($_.FreeGB)</td><td>$($_.SizeGB)</td></tr>"
  }) -join "`n"
} else { "<tr><td colspan='4'>Sem dados</td></tr>" }
$pathsRows = ($pathsInfo | ForEach-Object {
  "<tr><td>$(Escape-Html $_.DC)</td><td>$($_.NTDS_GB)</td><td>$($_.SYSVOL_GB)</td></tr>"
}) -join "`n"
$diskBlock = @"
<div class='section'>
  <h2>Armazenamento</h2>
  $(Html-Table 'Volumes (GB)' @('DC','Drive','FreeGB','SizeGB') $diskRows)
  $(Html-Table 'Pastas Críticas (GB)' @('DC','NTDS','SYSVOL') $pathsRows)
</div>
"@

# Hardening
$recycleText = 'No'; if ($recycle -and $recycle.Count -gt 0) { $recycleText = 'Yes' }
$hardRows = @"
<tr><td>LDAPServerIntegrity (recom. 2)</td><td>$($hardening['LDAPServerIntegrity'])</td></tr>
<tr><td>LdapEnforceChannelBinding (recom. 1/2)</td><td>$($hardening['LdapEnforceChannelBinding'])</td></tr>
<tr><td>SMB Server RequireSecuritySignature (recom. 1)</td><td>$($hardening['SMBServer_RequireSecuritySignature'])</td></tr>
<tr><td>SMB Client RequireSecuritySignature (recom. 1)</td><td>$($hardening['SMBClient_RequireSecuritySignature'])</td></tr>
<tr><td>TLS 1.0 Server Disabled (true=ok)</td><td>$($hardening['TLS1.0_Server_Disabled'])</td></tr>
<tr><td>TLS 1.1 Server Disabled (true=ok)</td><td>$($hardening['TLS1.1_Server_Disabled'])</td></tr>
<tr><td>TLS 1.2 Server Enabled (true=ok)</td><td>$($hardening['TLS1.2_Server_Enabled'])</td></tr>
<tr><td>Recycle Bin habilitado?</td><td>$recycleText</td></tr>
<tr><td>krbtgt – idade senha (dias)</td><td>$krbAgeDays</td></tr>
<tr><td>NLTest /dsregdns</td><td><pre>$(Escape-Html $nlDsRegDns)</pre></td></tr>
"@
$hardBlock = Html-Table 'Hardening (valores-chaves)' @('Configuração','Valor') $hardRows

# Matriz
$healthTable = @"
<div class='section'>
  <h2>Matriz de Saúde do AD (Conectividade/Portas/DNS)</h2>
  $noteUdp
  <table>
    $healthHeader
    <tbody>
      $($healthRows -join "`n")
    </tbody>
  </table>
</div>
"@

# Resumo Executivo
# Amostra de backlog DFSR (primeira linha com "Backlog: N")
$dfsrBacklogAlert = ($dfsrBacklogs | Where-Object { $_ -match 'Backlog' -and $_ -match ':\s*\d+' } | Select-Object -First 1)
$dfsrBacklogText  = 'Sem dados/0'
if ($dfsrBacklogAlert -and $dfsrBacklogAlert.Length -gt 0) { $dfsrBacklogText = $dfsrBacklogAlert }

$execCards = @"
<div class="summary">
  <div class="card all">DCs mapeados: <b>$($DCServers.Count)</b></div>
  <div class="card ok">DCDiag PASS: <b>$pass</b></div>
  <div class="card wrn">DCDiag WARN: <b>$warn</b></div>
  <div class="card bad">DCDiag FAIL: <b>$fail</b></div>
  <div class="card wrn">Largest Delta (repl): <b>$(Escape-Html $largestDelta)</b></div>
  <div class="card bad">DFSR backlog (amostra): <b>$(Escape-Html $dfsrBacklogText)</b></div>
</div>
"@

# HTML final
$html = @"
<!DOCTYPE html>
<html lang="pt-br">
<head>
<meta charset="utf-8"/>
<title>AD Full Diagnostic – $(Escape-Html $Domain) – $timestamp</title>
<style>
$css
</style>
</head>
<body>
  <h1>Diagnóstico AD – Domínio $(Escape-Html $Domain)</h1>
  <div class="sub">Geração: $timestamp — DCDiag (itens mapeados): $total (PASS: $pass, WARN: $warn, FAIL: $fail)</div>

  $execCards
  $noteQ

  $($serverTables -join "`n")

  <div class="section">
    <h2>Falhas/Avisos detalhados (DCDiag)</h2>
    $($issueBlocks -join "`n")
  </div>

  $healthTable

  $repBlock
  $dfsrBlock

  <div class='section'>
    <h2>FSMO / PDC / Tempo</h2>
    <h3>FSMO</h3><pre>$(Escape-Html $fsmo)</pre>
    <h3>RID Manager Test (no PDC: $(Escape-Html $pdc))</h3><pre>$(Escape-Html $ridTest)</pre>
    <h3>Tempo (w32tm)</h3>
    <pre>Status:
$([string](Escape-Html $w32status))

Peers:
$([string](Escape-Html $w32peers))

Configuration:
$([string](Escape-Html $w32config))</pre>
  </div>

  $dnsBlock
  $ldapsBlock
  $eventsBlock
  $gpoBlock
  $diskBlock
  $hardBlock

  <div class="meta">
    Cliente: $(Escape-Html $ClientName) &nbsp; | &nbsp; Analista: $(Escape-Html $AnalystName) <br/>
    Início coleta: $StartDate &nbsp; | &nbsp; DCs: $($DCServers.Count)
  </div>
</body>
</html>
"@

# Grava HTML final
$dir = Split-Path -Path $OutputPath -Parent
if ($dir -and -not (Test-Path -LiteralPath $dir)) {
  New-Item -ItemType Directory -Path $dir -Force | Out-Null
}
$html | Out-File -FilePath $OutputPath -Encoding UTF8
Write-Host "Relatório HTML: $OutputPath" -ForegroundColor Green
Write-Host "TXT DCDiag: $outTxt" -ForegroundColor Green
