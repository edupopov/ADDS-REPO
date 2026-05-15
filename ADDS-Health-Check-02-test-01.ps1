#Requires -Version 5.1
<#
.SYNOPSIS
  AD Health Check (Windows PowerShell 5.1) - Relatório HTML + checagens de conectividade, portas, DNS e DCDIAG.

.DESCRIPTION
  Este script executa um conjunto de verificações comuns de saúde de Active Directory em todos os Domain Controllers da floresta atual:
  - Ping (via ping.exe)
  - Teste de portas TCP (88/389/636/3268/3269/135/139/445/53)
  - Teste UDP (DNS 53 funcional via nslookup; Kerberos/LDAP UDP opcional para reduzir ruído)
  - Testes DNS funcionais: A (self), SRV _ldap._tcp.dc._msdcs.<ForestRoot>, PTR (reverse)
  - Serviços: Netlogon, NTDS, DNS (via WMI, com fallback para sc.exe)
  - dcdiag com timeout real (executa 1 vez por DC e faz parse dos testes principais)

  Gera relatório HTML colorido (default: Desktop) e exporta CSV/JSON opcionalmente.
  Inclui "Cliente" e "Analista" no rodapé e nas exportações.

.AUTHOR
  Eduardo Popovici

.REFERENCE (ponto de partida)
  Script anterior "AD Health Check – PS 5.1/7" fornecido pelo autor nesta conversa.
  Repositório de referência inicial: https://github.com/edupopov/ADDS-REPO/tree/main

.NOTES
  - Compatível com Windows PowerShell 5.1 (sem operador ternário ? : e sem recursos do PS7).
  - Em ambientes que bloqueiam ICMP internamente, "PingFail" pode ocorrer mesmo com DC saudável.
  - UDP: Kerberos/LDAP via UDP normalmente não responde a datagramas genéricos; por padrão fica NotTested
    para evitar "amarelo" em massa. Habilite com -IncludeUdpLegacy se você realmente precisar.
#>

[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)]
  [string]$AnalystName,

  [Parameter(Mandatory = $true)]
  [string]$ClientName,

  # Timeout (segundos) para execução do dcdiag por DC
  [int]$TimeoutSeconds = 180,

  # Caminho do relatório HTML (se vazio, salva no Desktop como ADReport.html)
  [string]$OutputPath,

  # Exportações opcionais
  [string]$ExportCsv,
  [string]$ExportJson,

  # Email opcional (PS 5.1 possui Send-MailMessage)
  [string]$SmtpHost,
  [string]$EmailTo,
  [string]$EmailFrom = 'ADHealthCheck@domain.com',
  [int]$SmtpPort = 25,
  [switch]$UseSsl,

  # UDP legado (Kerberos/LDAP) desativado por padrão para reduzir ruído
  [switch]$IncludeUdpLegacy
)

# ============================================================
# 1) Definição do caminho padrão do relatório (Desktop)
# ============================================================
try {
  $desktop = [Environment]::GetFolderPath('Desktop')
  if ([string]::IsNullOrWhiteSpace($desktop)) {
    $desktop = Join-Path $env:USERPROFILE 'Desktop'
  }
}
catch {
  $desktop = Join-Path $env:USERPROFILE 'Desktop'
}

if ([string]::IsNullOrWhiteSpace($OutputPath)) {
  $OutputPath = Join-Path $desktop 'ADReport.html'
}

# ============================================================
# 2) Funções utilitárias
# ============================================================

function To-ShortName {
  param([Parameter(Mandatory)][string]$Fqdn)
  if ($Fqdn -match '\.') { return ($Fqdn -split '\.')[0] }
  return $Fqdn
}

# Ping via ping.exe (evita diferenças entre versões/ICMP libs)
function Test-PingHost {
  param(
    [Parameter(Mandatory)][string]$ComputerName,
    [int]$TimeoutSeconds = 3
  )
  try {
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = "$env:SystemRoot\System32\PING.EXE"
    $psi.Arguments = "-n 1 -w $($TimeoutSeconds * 1000) $ComputerName"
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError  = $true

    $p = [System.Diagnostics.Process]::Start($psi)
    $null = $p.WaitForExit(($TimeoutSeconds + 1) * 1000)

    if ($p.HasExited -and $p.ExitCode -eq 0) { return $true }
  }
  catch { }
  return $false
}

# Teste TCP (socket connect com timeout)
function Test-TcpPort {
  param(
    [Parameter(Mandatory)][string]$ComputerName,
    [Parameter(Mandatory)][int]$Port,
    [int]$TimeoutSeconds = 3
  )
  try {
    $client = New-Object System.Net.Sockets.TcpClient
    $iar = $client.BeginConnect($ComputerName, $Port, $null, $null)
    if (-not $iar.AsyncWaitHandle.WaitOne($TimeoutSeconds * 1000)) {
      $client.Close()
      return 'Closed'
    }
    $client.EndConnect($iar) | Out-Null
    $client.Close()
    return 'Open'
  }
  catch {
    return 'Closed'
  }
}

# Teste UDP (genérico). Por padrão não é usado para Kerberos/LDAP porque tende a gerar NoReply.
function Test-UdpPort {
  param(
    [Parameter(Mandatory)][string]$ComputerName,
    [Parameter(Mandatory)][int]$Port,
    [int]$TimeoutSeconds = 3
  )
  try {
    $udp = New-Object System.Net.Sockets.UdpClient
    $udp.Client.ReceiveTimeout = $TimeoutSeconds * 1000
    $udp.Connect($ComputerName, $Port)

    $bytes = [System.Text.Encoding]::ASCII.GetBytes("hi")
    [void]$udp.Send($bytes, $bytes.Length)

    Start-Sleep -Milliseconds 250

    if ($udp.Available -gt 0) {
      $remote = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
      $null = $udp.Receive([ref]$remote)
      $udp.Close()
      return 'Open'
    }
    else {
      $udp.Close()
      return 'NoReply'
    }
  }
  catch {
    try { $udp.Close() } catch { }
    return 'NoReply'
  }
}

# Status de serviço remoto: WMI (Win32_Service) com fallback sc.exe
function Get-ServiceStatusSafe {
  param(
    [Parameter(Mandatory)][string]$ComputerName,
    [Parameter(Mandatory)][string]$ServiceName
  )

  # 1) WMI: costuma ser a forma mais compatível em servidores legados
  try {
    $svc = Get-WmiObject -Class Win32_Service -ComputerName $ComputerName -Filter ("Name='{0}'" -f $ServiceName) -ErrorAction Stop
    if ($null -eq $svc) { return 'Unknown' }

    if ($svc.State -eq 'Running') {
      return 'Running'
    }
    else {
      return [string]$svc.State
    }
  }
  catch {
    # 2) Fallback: sc.exe (RPC)
    try {
      $out = & sc.exe "\\$ComputerName" query $ServiceName 2>$null
      if ($LASTEXITCODE -ne 0 -or -not $out) { return 'ConnError' }

      if ($out -match 'STATE\s+:\s+\d+\s+RUNNING') { return 'Running' }
      if ($out -match 'STATE\s+:\s+\d+\s+STOPPED') { return 'Stopped' }

      return 'Unknown'
    }
    catch {
      return 'ConnError'
    }
  }
}

# Teste de shares NETLOGON/SYSVOL
function Test-UncShare {
  param(
    [Parameter(Mandatory)][string]$ComputerName,
    [Parameter(Mandatory)][ValidateSet('NETLOGON', 'SYSVOL')] [string]$ShareName
  )
  try {
    $path = ("filesystem::\\{0}\{1}" -f $ComputerName, $ShareName)
    if (Test-Path -LiteralPath $path -ErrorAction SilentlyContinue) { return 'Passed' }
    return 'Failed'
  }
  catch {
    return 'Failed'
  }
}

# ============================================================
# 3) DNS compatível: Resolve-DnsName (se existir) -> nslookup
# ============================================================

function Resolve-DnsACompat {
  param(
    [Parameter(Mandatory)][string]$Name,
    [Parameter(Mandatory)][string]$Server
  )

  if (Get-Command Resolve-DnsName -ErrorAction SilentlyContinue) {
    try {
      $a = Resolve-DnsName -Name $Name -Type A -Server $Server -ErrorAction Stop
      $ip = $a | Where-Object { $_.IPAddress } | Select-Object -First 1 -ExpandProperty IPAddress
      if ($ip) { return @{ Status = 'Passed'; Value = $ip } }
    } catch { }
  }

  try {
    $out = & nslookup.exe $Name $Server 2>$null
    $m = ($out | Select-String -Pattern 'Address:\s+(\d{1,3}(\.\d{1,3}){3})' | Select-Object -First 1)
    if ($m -and $m.Matches[0].Groups[1].Value) {
      return @{ Status = 'Passed'; Value = $m.Matches[0].Groups[1].Value }
    }
  } catch { }

  return @{ Status = 'Failed'; Value = $null }
}

function Resolve-DnsSrvCompat {
  param(
    [Parameter(Mandatory)][string]$Name,
    [Parameter(Mandatory)][string]$Server
  )

  if (Get-Command Resolve-DnsName -ErrorAction SilentlyContinue) {
    try {
      $srv = Resolve-DnsName -Name $Name -Type SRV -Server $Server -ErrorAction Stop
      if ($srv) { return @{ Status = 'Passed'; Value = 'OK' } }
    } catch { }
  }

  try {
    $out = & nslookup.exe "-type=SRV" $Name $Server 2>$null
    # Heurística simples: se aparecerem linhas típicas de SRV, considera Passed
    if ($out -match 'svr hostname|service location|SRV service location') {
      return @{ Status = 'Passed'; Value = 'OK' }
    }
  } catch { }

  return @{ Status = 'Failed'; Value = $null }
}

function Resolve-DnsPtrCompat {
  param(
    [Parameter(Mandatory)][string]$Ip,
    [Parameter(Mandatory)][string]$Server
  )

  if (Get-Command Resolve-DnsName -ErrorAction SilentlyContinue) {
    try {
      $ptr = Resolve-DnsName -Name $Ip -Type PTR -Server $Server -ErrorAction Stop
      if ($ptr) { return @{ Status = 'Passed'; Value = 'OK' } }
    } catch { }
  }

  try {
    $out = & nslookup.exe "-type=PTR" $Ip $Server 2>$null
    if ($out -match 'name\s*=' -or $out -match 'PTR') {
      return @{ Status = 'Passed'; Value = 'OK' }
    }
  } catch { }

  return @{ Status = 'Failed'; Value = $null }
}

# DNS UDP funcional: nslookup usa UDP por padrão (melhor do que "send hi")
function Test-DnsUdpFunctional {
  param(
    [Parameter(Mandatory)][string]$Name,
    [Parameter(Mandatory)][string]$Server
  )

  try {
    $out = & nslookup.exe $Name $Server 2>$null
    if ($out -match 'NXDOMAIN|Non-existent domain') { return 'Failed' }
    if ($out -match 'timed out|timeout') { return 'NoReply' }
    if ($out -match 'Address:' ) { return 'Passed' }
    return 'NoReply'
  }
  catch {
    return 'NoReply'
  }
}

# ============================================================
# 4) DCDIAG com timeout real (executa 1 vez por DC e parseia)
# ============================================================

function Get-DcDiagTestStatusFromOutput {
  param(
    [Parameter(Mandatory)][string]$Output,
    [Parameter(Mandatory)][string]$TestName
  )

  # Procura "passed test <TestName>" (case-insensitive, multiline)
  if ($Output -match ("(?im)\bpassed\s+test\s+{0}\b" -f [Regex]::Escape($TestName))) { return 'Passed' }
  if ($Output -match ("(?im)\bfailed\s+test\s+{0}\b" -f [Regex]::Escape($TestName))) { return 'Failed' }
  if ($Output -match ("(?im)\bskipped\s+test\s+{0}\b" -f [Regex]::Escape($TestName))) { return 'Unknown' }

  # Se não encontrou, retorna Unknown para não gerar falso negativo
  return 'Unknown'
}

function Invoke-DcDiagSummary {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$ComputerName,
    [int]$TimeoutSeconds = 180
  )

  # Se dcdiag não estiver disponível, retorna Failed
  try { $exe = (Get-Command -Name 'dcdiag.exe' -ErrorAction Stop).Source }
  catch { return @{ _status = 'Failed'; _raw = $null } }

  $psi = New-Object System.Diagnostics.ProcessStartInfo
  $psi.FileName = $exe
  $psi.Arguments = "/s:$ComputerName /v"
  $psi.UseShellExecute = $false
  $psi.RedirectStandardOutput = $true
  $psi.RedirectStandardError  = $true

  $proc = New-Object System.Diagnostics.Process
  $proc.StartInfo = $psi

  try {
    $null = $proc.Start()

    # Timeout real
    if (-not $proc.WaitForExit($TimeoutSeconds * 1000)) {
      try { $proc.Kill() | Out-Null } catch { }
      return @{ _status = 'Timeout'; _raw = $null }
    }

    $output = $proc.StandardOutput.ReadToEnd() + $proc.StandardError.ReadToEnd()
  }
  catch {
    return @{ _status = 'Failed'; _raw = $null }
  }
  finally {
    try { $proc.Close() } catch { }
  }

  $result = @{
    NetLogons    = Get-DcDiagTestStatusFromOutput -Output $output -TestName 'NetLogons'
    Replications = Get-DcDiagTestStatusFromOutput -Output $output -TestName 'Replications'
    Services     = Get-DcDiagTestStatusFromOutput -Output $output -TestName 'Services'
    Advertising  = Get-DcDiagTestStatusFromOutput -Output $output -TestName 'Advertising'
    FSMOCheck    = Get-DcDiagTestStatusFromOutput -Output $output -TestName 'FSMOCheck'
    ReplicationErrorCode = ''
    _status      = 'OK'
    _raw         = $output
  }

  # Se Replications falhou, tenta capturar o primeiro "error (####)" para ajudar na triagem
  if ($result.Replications -eq 'Failed') {
    if ($output -match '(?im)error\s+\((\d+)\)') {
      $result.ReplicationErrorCode = $matches[1]
    }
  }

  # Indicadores clássicos de falha de contato (não inventa detalhes; apenas sinaliza ConnError)
  $lower = $output.ToLowerInvariant()
  if ($lower -match 'cannot be contacted|rpc server is unavailable|no longer available') {
    $result._status = 'ConnError'
  }

  return $result
}

# ============================================================
# 5) Status/cores e severidade geral do DC
# ============================================================

function Get-StatusColor {
  param([Parameter(Mandatory)][string]$Status)

  switch ($Status) {
    'OK'        { return 'ok' }
    'Success'   { return 'ok' }
    'Running'   { return 'ok' }
    'Passed'    { return 'ok' }
    'Open'      { return 'ok' }

    'NotTested' { return 'na' }

    'Failed'    { return 'fail' }
    'Closed'    { return 'fail' }
    'PingFail'  { return 'fail' }

    'Unknown'   { return 'warn' }
    'Timeout'   { return 'warn' }
    'ConnError' { return 'warn' }
    'NoReply'   { return 'warn' }

    default     { return 'warn' }
  }
}

function Get-OverallStatus {
  param([Parameter(Mandatory)][pscustomobject]$Row)

  # Se existe qualquer "Fail" forte => Failed
  $vals = @()
  foreach ($p in $Row.PSObject.Properties.Name) {
    if ($p -in @('Identity','OverallStatus','AnalystName','ClientName','ElapsedMs')) { continue }
    $vals += [string]$Row.$p
  }

  if ($vals -contains 'Failed' -or $vals -contains 'Closed' -or $vals -contains 'PingFail') { return 'Failed' }
  if ($vals -contains 'Timeout' -or $vals -contains 'ConnError' -or $vals -contains 'Unknown' -or $vals -contains 'NoReply') { return 'Warn' }
  return 'OK'
}

# ============================================================
# 6) Enumeração de DCs na floresta
# ============================================================

$StartDate = Get-Date
Write-Host "Iniciando AD Health Check em $StartDate" -ForegroundColor Cyan

try {
  $forest = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
  $DCServers = $forest.Domains | ForEach-Object { $_.DomainControllers } | ForEach-Object { $_.Name }
  $ForestRoot = $forest.RootDomain.Name
}
catch {
  throw "Falha ao enumerar DCs: $($_.Exception.Message)"
}

$DCServers = $DCServers | Sort-Object -Unique
if (-not $DCServers) { throw "Nenhum DC encontrado." }

Write-Host "DCs encontrados: $($DCServers -join ', ')" -ForegroundColor DarkCyan

# ============================================================
# 7) Portas alvo (TCP/UDP)
# ============================================================

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
}

$UdpPortsToCheck = [ordered]@{
  DNS_UDP     = 53
  KerberosUDP = 88
  LDAPUDP     = 389
}

# ============================================================
# 8) Execução dos testes por DC
# ============================================================

$ResultsArr = foreach ($dcFqdn in $DCServers) {
  $sw = [System.Diagnostics.Stopwatch]::StartNew()

  $short = To-ShortName -Fqdn $dcFqdn

  # ---- Ping (usa FQDN e tenta shortname como fallback) ----
  $pingOkFqdn  = Test-PingHost -ComputerName $dcFqdn -TimeoutSeconds 3
  $pingOkShort = $false
  if (-not $pingOkFqdn) {
    $pingOkShort = Test-PingHost -ComputerName $short -TimeoutSeconds 3
  }

  $pingOk = ($pingOkFqdn -or $pingOkShort)
  $pingStatus = if ($pingOk) { 'Success' } else { 'PingFail' }

  # Target para consultas remotas: se shortname funcionou, usa ele; senão FQDN
  $target = if ($pingOkShort) { $short } else { $dcFqdn }

  # ---- Serviços (WMI + fallback) ----
  $netlogon = Get-ServiceStatusSafe -ComputerName $target -ServiceName 'Netlogon'
  $ntds     = Get-ServiceStatusSafe -ComputerName $target -ServiceName 'NTDS'
  $dnsSvc   = Get-ServiceStatusSafe -ComputerName $target -ServiceName 'DNS'

  # ---- DCDIAG (1x) ----
  $dcdiag = Invoke-DcDiagSummary -ComputerName $target -TimeoutSeconds $TimeoutSeconds

  # ---- Shares ----
  $tNetlogonShare = Test-UncShare -ComputerName $target -ShareName 'NETLOGON'
  $tSysvolShare   = Test-UncShare -ComputerName $target -ShareName 'SYSVOL'

  # ---- Portas TCP ----
  $tcpStatus = @{}
  foreach ($k in $TcpPortsToCheck.Keys) {
    $tcpStatus[$k] = Test-TcpPort -ComputerName $target -Port $TcpPortsToCheck[$k] -TimeoutSeconds 3
  }

  # ---- Portas UDP ----
  $udpStatus = @{}

  foreach ($k in $UdpPortsToCheck.Keys) {
    # DNS UDP: faz teste funcional via nslookup (UDP por padrão)
    if ($k -eq 'DNS_UDP') {
      $udpStatus[$k] = Test-DnsUdpFunctional -Name $target -Server $target
      continue
    }

    # Kerberos/LDAP UDP: desabilitado por padrão (NotTested) para reduzir ruído
    if (($k -eq 'KerberosUDP' -or $k -eq 'LDAPUDP') -and -not $IncludeUdpLegacy) {
      $udpStatus[$k] = 'NotTested'
      continue
    }

    $udpStatus[$k] = Test-UdpPort -ComputerName $target -Port $UdpPortsToCheck[$k] -TimeoutSeconds 3
  }

  # ---- DNS funcional usando o próprio DC como servidor ----
  $dnsA   = 'Unknown'
  $dnsSRV = 'Unknown'
  $dnsPTR = 'Unknown'

  $aRec = Resolve-DnsACompat -Name $target -Server $target
  $dnsA = $aRec.Status

  $srvName = "_ldap._tcp.dc._msdcs.{0}" -f $ForestRoot
  $srvRec  = Resolve-DnsSrvCompat -Name $srvName -Server $target
  $dnsSRV  = $srvRec.Status

  if ($aRec.Status -eq 'Passed' -and $aRec.Value) {
    $ptrRec = Resolve-DnsPtrCompat -Ip $aRec.Value -Server $target
    $dnsPTR = $ptrRec.Status
  } else {
    $dnsPTR = 'Unknown'
  }

  $sw.Stop()

  # ---- Montagem do objeto final (uma linha por DC) ----
  $row = [pscustomobject]@{
    Identity             = $dcFqdn
    PingStatus           = $pingStatus

    NetlogonService      = $netlogon
    NTDSService          = $ntds
    DNSServiceStatus     = $dnsSvc

    NetlogonsTest        = $dcdiag.NetLogons
    ReplicationTest      = $dcdiag.Replications
    ReplicationErrorCode = $dcdiag.ReplicationErrorCode
    ServicesTest         = $dcdiag.Services
    AdvertisingTest      = $dcdiag.Advertising
    FSMOCheckTest        = $dcdiag.FSMOCheck

    NETLOGONTest         = $tNetlogonShare
    SYSVOLTest           = $tSysvolShare

    KerberosTCP          = $tcpStatus.KerberosTCP
    LDAPTCP              = $tcpStatus.LDAPTCP
    LDAPS                = $tcpStatus.LDAPS
    GCLDAP               = $tcpStatus.GCLDAP
    GCLDAPS              = $tcpStatus.GCLDAPS

    DNS_TCP              = $tcpStatus.DNS_TCP
    DNS_UDP              = $udpStatus.DNS_UDP

    DNS_A_Self           = $dnsA
    DNS_SRV_Forest       = $dnsSRV
    DNS_PTR_Self         = $dnsPTR

    NTLM_RPC135          = $tcpStatus.NTLM_RPC135
    NTLM_139             = $tcpStatus.NTLM_139
    NTLM_445             = $tcpStatus.NTLM_445

    KerberosUDP          = $udpStatus.KerberosUDP
    LDAPUDP              = $udpStatus.LDAPUDP

    ElapsedMs            = [int]$sw.ElapsedMilliseconds

    AnalystName          = $AnalystName
    ClientName           = $ClientName
  }

  # Status geral do DC para triagem rápida (OK / Warn / Failed)
  $overall = Get-OverallStatus -Row $row
  $row | Add-Member -NotePropertyName OverallStatus -NotePropertyValue $overall

  $row
}

$ResultsArr = $ResultsArr | Sort-Object Identity

# ============================================================
# 9) Exportações (CSV/JSON)
# ============================================================

if ($ExportCsv) {
  try {
    $ResultsArr | Export-Csv -NoTypeInformation -Path $ExportCsv -Encoding UTF8
    Write-Host "Export CSV: $((Resolve-Path -LiteralPath $ExportCsv).Path)" -ForegroundColor Green
  }
  catch {
    Write-Warning "CSV: $($_.Exception.Message)"
  }
}

if ($ExportJson) {
  try {
    $ResultsArr | ConvertTo-Json -Depth 6 | Out-File -FilePath $ExportJson -Encoding UTF8
    Write-Host "Export JSON: $((Resolve-Path -LiteralPath $ExportJson).Path)" -ForegroundColor Green
  }
  catch {
    Write-Warning "JSON: $($_.Exception.Message)"
  }
}

# ============================================================
# 10) HTML (cores + resumo + filtros + busca)
# ============================================================

$EndDate = Get-Date

$total = $ResultsArr.Count
$failCount = ($ResultsArr | Where-Object { $_.OverallStatus -eq 'Failed' }).Count
$warnCount = ($ResultsArr | Where-Object { $_.OverallStatus -eq 'Warn' }).Count
$okCount   = ($ResultsArr | Where-Object { $_.OverallStatus -eq 'OK' }).Count

$css = @"
<style>
  body { font-family: Segoe UI, Tahoma, Arial; margin: 12px; }
  h1 { color: #3A4FA0; margin-bottom: 6px; }
  .legend { font-size: 12px; margin: 4px 0 8px 0; }
  .legend span { display:inline-block; padding:2px 6px; border:1px solid #999; margin-right:6px; }
  .toolbar { display:flex; gap:8px; align-items:center; margin: 10px 0 10px 0; flex-wrap: wrap; }
  .toolbar button { padding:6px 10px; border:1px solid #666; background:#f2f2f2; cursor:pointer; border-radius:6px; }
  .toolbar input { padding:6px 10px; border:1px solid #666; border-radius:6px; min-width: 260px; }
  .summary { font-size: 12px; padding: 8px 10px; background:#f7f7ff; border:1px solid #c9d0ff; border-radius:10px; margin: 8px 0 10px 0; }
  table { border-collapse: collapse; width: 100%; }
  th, td { border: 1px solid #999; padding: 6px 8px; font-size: 12px; text-align: center; }
  th { background: #B04B4B; color: #fff; position: sticky; top: 0; z-index: 2; }
  tr:nth-child(even) { background: #f7f7f7; }
  .ok    { background: #7FFFD4; }
  .fail  { background: #FF6B6B; }
  .warn  { background: #FFD166; }
  .na    { background: #E0E0E0; color: #333; }
  .idcell{ background: #DCDCDC; text-align: left; font-weight: bold; }
  .meta  { font-size: 11px; color: #3A4FA0; }
  .note  { font-size: 12px; color: #333; margin: 6px 0 12px 0; }
</style>
"@

$js = @"
<script>
function applyFilter(mode){
  var rows = document.querySelectorAll('tbody tr');
  for (var i=0; i<rows.length; i++){
    var r = rows[i];
    var st = r.getAttribute('data-status') || '';
    if(mode==='all') r.style.display='';
    else if(mode==='fail') r.style.display = (st==='Failed') ? '' : 'none';
    else if(mode==='warnfail') r.style.display = (st==='Warn' || st==='Failed') ? '' : 'none';
  }
}
function applySearch(){
  var q = (document.getElementById('q').value || '').toLowerCase();
  var rows = document.querySelectorAll('tbody tr');
  for (var i=0; i<rows.length; i++){
    var r = rows[i];
    var txt = (r.innerText || '').toLowerCase();
    r.style.display = (txt.indexOf(q) >= 0) ? '' : 'none';
  }
}
</script>
"@

$htmlHeader = @"
<html>
<head><meta charset="utf-8" /><title>Active Directory Health Check</title>
$css
$js
</head>
<body>
<h1>Active Directory Health Check</h1>

<div class='legend'>
  <span class='ok'>OK</span>
  <span class='warn'>Aviso</span>
  <span class='fail'>Falha</span>
  <span class='na'>N/A</span>
</div>

<div class='summary'>
  <b>Resumo:</b> Total DCs: $total &nbsp; | &nbsp; OK: $okCount &nbsp; | &nbsp; Aviso: $warnCount &nbsp; | &nbsp; Falha: $failCount <br/>
  <b>Floresta:</b> $ForestRoot &nbsp; | &nbsp; <b>Início:</b> $StartDate &nbsp; | &nbsp; <b>Fim:</b> $EndDate &nbsp; | &nbsp; <b>Timeout:</b> ${TimeoutSeconds}s
</div>

<div class='toolbar'>
  <button onclick="applyFilter('all')">Mostrar tudo</button>
  <button onclick="applyFilter('fail')">Somente falhas</button>
  <button onclick="applyFilter('warnfail')">Avisos + falhas</button>
  <input id="q" type="text" placeholder="Buscar (DC, status, porta, etc.)" onkeyup="applySearch()" />
</div>

<div class='note'>
  <b>Nota sobre UDP:</b> Kerberos/LDAP via UDP pode não responder (silencioso), gerando <i>NoReply</i>.
  Por padrão, estes UDP legados ficam como <i>NotTested</i>. Para habilitar, use <b>-IncludeUdpLegacy</b>.
  O DNS UDP é validado com uma consulta funcional (nslookup).
</div>

<table>
  <thead>
    <tr>
      <th>Identity</th>
      <th>OverallStatus</th>
      <th>PingStatus</th>
      <th>NetlogonService</th>
      <th>NTDSService</th>
      <th>DNSServiceStatus</th>

      <th>NetlogonsTest</th>
      <th>ReplicationTest</th>
      <th>ReplErr</th>
      <th>ServicesTest</th>
      <th>AdvertisingTest</th>
      <th>FSMOCheckTest</th>

      <th>NETLOGONTest</th>
      <th>SYSVOLTest</th>

      <th>KerberosTCP:88</th>
      <th>LDAPTCP:389</th>
      <th>LDAPS:636</th>
      <th>GC:3268</th>
      <th>GC SSL:3269</th>

      <th>DNS TCP:53</th>
      <th>DNS UDP:53</th>
      <th>DNS A(Self)</th>
      <th>DNS SRV(Forest)</th>
      <th>DNS PTR(Self)</th>

      <th>NTLM RPC:135</th>
      <th>NTLM 139</th>
      <th>NTLM 445</th>

      <th>KerberosUDP:88</th>
      <th>LDAPUDP:389</th>

      <th>ElapsedMs</th>
    </tr>
  </thead>
  <tbody>
"@

$rows = foreach ($r in $ResultsArr) {
  $statusAttr = $r.OverallStatus
  $cells = @()

  $cells += "<td class='idcell'>$($r.Identity)</td>"

  $clsOverall = 'warn'
  if ($r.OverallStatus -eq 'OK') { $clsOverall = 'ok' }
  elseif ($r.OverallStatus -eq 'Failed') { $clsOverall = 'fail' }
  $cells += "<td class='$clsOverall'><b>$($r.OverallStatus)</b></td>"

  foreach ($p in @(
    'PingStatus',
    'NetlogonService',
    'NTDSService',
    'DNSServiceStatus',
    'NetlogonsTest',
    'ReplicationTest',
    'ReplicationErrorCode',
    'ServicesTest',
    'AdvertisingTest',
    'FSMOCheckTest',
    'NETLOGONTest',
    'SYSVOLTest',
    'KerberosTCP',
    'LDAPTCP',
    'LDAPS',
    'GCLDAP',
    'GCLDAPS',
    'DNS_TCP',
    'DNS_UDP',
    'DNS_A_Self',
    'DNS_SRV_Forest',
    'DNS_PTR_Self',
    'NTLM_RPC135',
    'NTLM_139',
    'NTLM_445',
    'KerberosUDP',
    'LDAPUDP',
    'ElapsedMs'
  )) {
    $val = [string]$r.$p
    if ($p -eq 'ReplicationErrorCode' -and [string]::IsNullOrWhiteSpace($val)) { $val = '-' }
    $cls = Get-StatusColor -Status $val
    $cells += "<td class='$cls'><b>$val</b></td>"
  }

  "<tr data-status='$statusAttr'>{0}</tr>" -f ($cells -join '')
}

$htmlFooter = @"
  </tbody>
</table>

<br/>
<div class='meta'>
  Cliente: $ClientName &nbsp; | &nbsp; Analista: $AnalystName <br/>
  Start Date: $StartDate &nbsp; | &nbsp; End Date: $EndDate &nbsp; | &nbsp;
  Timeout: ${TimeoutSeconds}s &nbsp; | &nbsp; DCs: $($DCServers.Count) &nbsp; | &nbsp; Floresta: $ForestRoot
</div>

</body>
</html>
"@

# Salvar HTML com criação de pasta se necessário
try {
  $dir = Split-Path -Path $OutputPath -Parent
  if ($dir -and -not (Test-Path -LiteralPath $dir)) {
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
  }

  ($htmlHeader + ($rows -join "`n") + $htmlFooter) | Out-File -FilePath $OutputPath -Encoding UTF8 -Force
  $resolved = Resolve-Path -LiteralPath $OutputPath -ErrorAction Stop
  Write-Host ("Relatório HTML salvo em: {0}" -f $resolved.Path) -ForegroundColor Green
}
catch {
  Write-Warning "Falha ao salvar HTML: $($_.Exception.Message)"
}

# ============================================================
# 11) Email opcional (PS 5.1)
# ============================================================

if ($SmtpHost -and $EmailTo) {
  try {
    $to = $EmailTo -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }
    if ($to.Count -gt 0) {
      $body = Get-Content -LiteralPath $OutputPath -Raw -Encoding UTF8
      $subject = "AD Health Monitor - $ClientName - $($StartDate.ToString('yyyy-MM-dd HH:mm'))"

      Send-MailMessage -SmtpServer $SmtpHost -Port $SmtpPort -UseSsl:$UseSsl `
        -From $EmailFrom -To $to -Subject $subject -Body $body -BodyAsHtml -ErrorAction Stop

      Write-Host "E-mail enviado para: $($to -join ', ')" -ForegroundColor Green
    }
  }
  catch {
    Write-Warning "Falha ao enviar e-mail: $($_.Exception.Message)"
  }
}
else {
  Write-Host "Envio de e-mail não configurado (SmtpHost ou EmailTo ausentes)." -ForegroundColor Yellow
}

Write-Host "Concluído em $(Get-Date)." -ForegroundColor Cyan
