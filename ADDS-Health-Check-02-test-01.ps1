#Requires -Version 5.1
<#
.SYNOPSIS
  AD DS Health Check - Windows PowerShell 5.1 (com barra de progresso e validações)

.DESCRIPTION
  Valida a saúde e conectividade dos Domain Controllers da floresta atual:
   - Ping via ping.exe
   - Portas TCP: 88/389/636/3268/3269/135/139/445/53
   - UDP: DNS 53 funcional via nslookup; Kerberos/LDAP UDP opcional (por padrão NotTested)
   - DNS funcional: A(Self), SRV _ldap._tcp.dc._msdcs.<ForestRoot>, PTR(Self)
   - Serviços: Netlogon, NTDS, DNS (WMI + fallback sc.exe)
   - DCDIAG com timeout real: executa 1x por DC e faz parse dos testes principais
   - Relatório HTML colorido (Desktop por padrão), CSV/JSON opcionais, e-mail opcional

.AUTHOR
  Eduardo Popovici

.REFERENCE (ponto de partida)
  Script anterior usado como referência inicial nesta conversa:
  "AD Health Check – PS 5.1/7" (Eduardo Popovici)
  Repositório de referência inicial: https://github.com/edupopov/ADDS-REPO/tree/main

.NOTES
  - Compatível com Windows PowerShell 5.1 (sem recursos exclusivos do PS7).
  - IMPORTANTE: no PS 5.1, Write-Progress -Completed exige -Activity; este script trata isso
    para NÃO travar pedindo entrada interativa. [2](https://github.com/PowerShell/PowerShell/issues/15252)[3](https://ss64.com/ps/write-progress.html)
#>

[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)]
  [string]$AnalystName,

  [Parameter(Mandatory = $true)]
  [string]$ClientName,

  [int]$TimeoutSeconds = 180,

  # Caminho do relatório HTML (se vazio, Desktop\ADReport.html)
  [string]$OutputPath,

  # Exportações opcionais
  [string]$ExportCsv,
  [string]$ExportJson,

  # E-mail opcional
  [string]$SmtpHost,
  [string]$EmailTo,
  [string]$EmailFrom = 'ADHealthCheck@domain.com',
  [int]$SmtpPort = 25,
  [switch]$UseSsl,

  # UDP legado (Kerberos/LDAP) - por padrão NotTested (reduz ruído)
  [switch]$IncludeUdpLegacy,

  # Exibir mensagens de validação durante a execução
  [switch]$ShowValidationMessages
)

# ============================================================
# 0) LOG / PROGRESSO (corrigido para PS 5.1)
# ============================================================

function Write-Stage {
  param(
    [Parameter(Mandatory)][string]$Dc,
    [Parameter(Mandatory)][string]$Message,
    [ConsoleColor]$Color = [ConsoleColor]::Gray
  )
  if ($ShowValidationMessages) {
    $ts = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    Write-Host ("[{0}] [{1}] {2}" -f $ts, $Dc, $Message) -ForegroundColor $Color
  }
}

function Update-ProgressSafe {
  param(
    [int]$Id,
    [int]$ParentId = -1,
    [string]$Activity,
    [string]$Status,
    [int]$Percent
  )

  # PS 5.1: Activity não pode ser nulo/vazio, senão pode disparar prompt em alguns hosts
  if ([string]::IsNullOrWhiteSpace($Activity)) { $Activity = ' ' }
  if ([string]::IsNullOrWhiteSpace($Status))   { $Status   = ' ' }

  if ($ParentId -ge 0) {
    Write-Progress -Id $Id -ParentId $ParentId -Activity $Activity -Status $Status -PercentComplete $Percent
  } else {
    Write-Progress -Id $Id -Activity $Activity -Status $Status -PercentComplete $Percent
  }
}

function Complete-ProgressSafe {
  param(
    [int]$Id,
    [string]$Activity = ' '
  )

  # ✅ PS 5.1: -Completed exige -Activity (se não, pede input "Activity:")
  # Workaround: Activity = ' ' (espaço) é suficiente. [2](https://github.com/PowerShell/PowerShell/issues/15252)[3](https://ss64.com/ps/write-progress.html)
  if ([string]::IsNullOrWhiteSpace($Activity)) { $Activity = ' ' }
  Write-Progress -Id $Id -Activity $Activity -Completed
}

# ============================================================
# 1) Caminho padrão: Desktop
# ============================================================

try {
  $desktop = [Environment]::GetFolderPath('Desktop')
  if ([string]::IsNullOrWhiteSpace($desktop)) {
    $desktop = Join-Path $env:USERPROFILE 'Desktop'
  }
} catch {
  $desktop = Join-Path $env:USERPROFILE 'Desktop'
}

if ([string]::IsNullOrWhiteSpace($OutputPath)) {
  $OutputPath = Join-Path $desktop 'ADReport.html'
}

# ============================================================
# 2) Funções de rede / serviços
# ============================================================

function To-ShortName {
  param([Parameter(Mandatory)][string]$Fqdn)
  if ($Fqdn -match '\.') { return ($Fqdn -split '\.')[0] }
  return $Fqdn
}

function Test-PingHost {
  param([Parameter(Mandatory)][string]$ComputerName,[int]$TimeoutSeconds=3)
  try {
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = "$env:SystemRoot\System32\PING.EXE"
    $psi.Arguments = "-n 1 -w $($TimeoutSeconds*1000) $ComputerName"
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
    $client.Close()
    return 'Open'
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
    Start-Sleep -Milliseconds 250
    if ($udp.Available -gt 0) {
      $remote = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any,0)
      $null = $udp.Receive([ref]$remote)
      $udp.Close()
      return 'Open'
    } else {
      $udp.Close()
      return 'NoReply'
    }
  } catch {
    try { $udp.Close() } catch {}
    return 'NoReply'
  }
}

function Get-ServiceStatusSafe {
  param([Parameter(Mandatory)][string]$ComputerName,[Parameter(Mandatory)][string]$ServiceName)

  # WMI (compatível com ambientes legados)
  try {
    $svc = Get-WmiObject -Class Win32_Service -ComputerName $ComputerName -Filter ("Name='{0}'" -f $ServiceName) -ErrorAction Stop
    if ($null -eq $svc) { return 'Unknown' }

    if ($svc.State -eq 'Running') { return 'Running' }
    else { return [string]$svc.State }
  } catch {
    # fallback sc.exe
    try {
      $out = & sc.exe "\\$ComputerName" query $ServiceName 2>$null
      if ($LASTEXITCODE -ne 0 -or -not $out) { return 'ConnError' }
      if ($out -match 'STATE\s+:\s+\d+\s+RUNNING') { return 'Running' }
      if ($out -match 'STATE\s+:\s+\d+\s+STOPPED') { return 'Stopped' }
      return 'Unknown'
    } catch {
      return 'ConnError'
    }
  }
}

function Test-UncShare {
  param([Parameter(Mandatory)][string]$ComputerName,[Parameter(Mandatory)][ValidateSet('NETLOGON','SYSVOL')] [string]$ShareName)
  try {
    $p = ("filesystem::\\{0}\{1}" -f $ComputerName,$ShareName)
    if (Test-Path -LiteralPath $p -ErrorAction SilentlyContinue) { return 'Passed' }
    return 'Failed'
  } catch {
    return 'Failed'
  }
}

# ============================================================
# 3) DNS compatível (Resolve-DnsName -> nslookup)
# ============================================================

function Resolve-DnsACompat {
  param([Parameter(Mandatory)][string]$Name,[Parameter(Mandatory)][string]$Server)

  if (Get-Command Resolve-DnsName -ErrorAction SilentlyContinue) {
    try {
      $a = Resolve-DnsName -Name $Name -Type A -Server $Server -ErrorAction Stop
      $ip = $a | Where-Object { $_.IPAddress } | Select-Object -First 1 -ExpandProperty IPAddress
      if ($ip) { return @{ Status='Passed'; Value=$ip } }
    } catch {}
  }

  try {
    $out = & nslookup.exe $Name $Server 2>$null
    $m = ($out | Select-String -Pattern 'Address:\s+(\d{1,3}(\.\d{1,3}){3})' | Select-Object -First 1)
    if ($m -and $m.Matches[0].Groups[1].Value) {
      return @{ Status='Passed'; Value=$m.Matches[0].Groups[1].Value }
    }
  } catch {}

  return @{ Status='Failed'; Value=$null }
}

function Resolve-DnsSrvCompat {
  param([Parameter(Mandatory)][string]$Name,[Parameter(Mandatory)][string]$Server)

  if (Get-Command Resolve-DnsName -ErrorAction SilentlyContinue) {
    try {
      $srv = Resolve-DnsName -Name $Name -Type SRV -Server $Server -ErrorAction Stop
      if ($srv) { return @{ Status='Passed'; Value='OK' } }
    } catch {}
  }

  try {
    $out = & nslookup.exe "-type=SRV" $Name $Server 2>$null
    if ($out -match 'svr hostname|service location|SRV service location') {
      return @{ Status='Passed'; Value='OK' }
    }
  } catch {}

  return @{ Status='Failed'; Value=$null }
}

function Resolve-DnsPtrCompat {
  param([Parameter(Mandatory)][string]$Ip,[Parameter(Mandatory)][string]$Server)

  if (Get-Command Resolve-DnsName -ErrorAction SilentlyContinue) {
    try {
      $ptr = Resolve-DnsName -Name $Ip -Type PTR -Server $Server -ErrorAction Stop
      if ($ptr) { return @{ Status='Passed'; Value='OK' } }
    } catch {}
  }

  try {
    $out = & nslookup.exe "-type=PTR" $Ip $Server 2>$null
    if ($out -match 'name\s*=' -or $out -match 'PTR') {
      return @{ Status='Passed'; Value='OK' }
    }
  } catch {}

  return @{ Status='Failed'; Value=$null }
}

function Test-DnsUdpFunctional {
  param([Parameter(Mandatory)][string]$Name,[Parameter(Mandatory)][string]$Server)

  try {
    $out = & nslookup.exe $Name $Server 2>$null
    if ($out -match 'NXDOMAIN|Non-existent domain') { return 'Failed' }
    if ($out -match 'timed out|timeout') { return 'NoReply' }
    if ($out -match 'Address:' ) { return 'Passed' }
    return 'NoReply'
  } catch {
    return 'NoReply'
  }
}

# ============================================================
# 4) DCDIAG 1x por DC + parse
# ============================================================

function Get-DcDiagTestStatusFromOutput {
  param(
    [Parameter(Mandatory)][string]$Output,
    [Parameter(Mandatory)][string]$TestName
  )
  $t = [Regex]::Escape($TestName)
  if ($Output -match ("(?im)\bpassed\s+test\s+$t\b")) { return 'Passed' }
  if ($Output -match ("(?im)\bfailed\s+test\s+$t\b")) { return 'Failed' }
  if ($Output -match ("(?im)\bskipped\s+test\s+$t\b")) { return 'Unknown' }
  return 'Unknown'
}

function Invoke-DcDiagSummary {
  [CmdletBinding()]
  param([Parameter(Mandatory)][string]$ComputerName,[int]$TimeoutSeconds=180)

  try { $exe = (Get-Command -Name 'dcdiag.exe' -ErrorAction Stop).Source }
  catch { return @{ _status='Failed'; _raw=$null } }

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
    $finished = $proc.WaitForExit($TimeoutSeconds*1000)
    if (-not $finished) {
      try { $proc.Kill() | Out-Null } catch {}
      return @{ _status='Timeout'; _raw=$null }
    }
    $output = $proc.StandardOutput.ReadToEnd() + $proc.StandardError.ReadToEnd()
  } catch {
    return @{ _status='Failed'; _raw=$null }
  } finally {
    try { $proc.Close() } catch {}
  }

  $res = @{
    NetLogons    = Get-DcDiagTestStatusFromOutput -Output $output -TestName 'NetLogons'
    Replications = Get-DcDiagTestStatusFromOutput -Output $output -TestName 'Replications'
    Services     = Get-DcDiagTestStatusFromOutput -Output $output -TestName 'Services'
    Advertising  = Get-DcDiagTestStatusFromOutput -Output $output -TestName 'Advertising'
    FSMOCheck    = Get-DcDiagTestStatusFromOutput -Output $output -TestName 'FSMOCheck'
    ReplicationErrorCode = ''
    _status      = 'OK'
    _raw         = $output
  }

  if ($res.Replications -eq 'Failed') {
    if ($output -match '(?im)error\s+\((\d+)\)') { $res.ReplicationErrorCode = $matches[1] }
  }

  $lower = $output.ToLowerInvariant()
  if ($lower -match 'cannot be contacted|rpc server is unavailable|no longer available') {
    $res._status = 'ConnError'
  }

  return $res
}

# ============================================================
# 5) Status/cores + severidade geral
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
# 6) Enumeração dos DCs (floresta atual)
# ============================================================

$StartDate = Get-Date
Write-Host ("Iniciando AD Health Check em {0}" -f $StartDate) -ForegroundColor Cyan

try {
  $forest = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
  $DCServers = $forest.Domains | ForEach-Object { $_.DomainControllers } | ForEach-Object { $_.Name }
  $ForestRoot = $forest.RootDomain.Name
} catch {
  throw "Falha ao enumerar DCs: $($_.Exception.Message)"
}

$DCServers = $DCServers | Sort-Object -Unique
if (-not $DCServers) { throw "Nenhum DC encontrado." }
Write-Host ("DCs encontrados: {0}" -f ($DCServers -join ', ')) -ForegroundColor DarkCyan

# ============================================================
# 7) Portas alvo
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
# 8) Testes por DC (com progress + validações)
# ============================================================

$totalDCs = $DCServers.Count
$index = 0

$ResultsArr = foreach ($dcFqdn in $DCServers) {

  $index++
  $pctGlobal = [int](($index / $totalDCs) * 100)

  Update-ProgressSafe -Id 0 -ParentId -1 -Activity "AD Health Check (PS 5.1)" `
    -Status "Processando $dcFqdn ($index/$totalDCs)" -Percent $pctGlobal

  $sw = [System.Diagnostics.Stopwatch]::StartNew()
  $short = To-ShortName -Fqdn $dcFqdn

  # Etapa 1/5 - Ping
  Update-ProgressSafe -Id 1 -ParentId 0 -Activity $dcFqdn -Status "Etapa 1/5: Ping" -Percent 10
  Write-Stage -Dc $dcFqdn -Message "Etapa 1/5: Ping..." -Color Cyan

  $pingOkFqdn  = Test-PingHost -ComputerName $dcFqdn -TimeoutSeconds 3
  $pingOkShort = $false
  if (-not $pingOkFqdn) { $pingOkShort = Test-PingHost -ComputerName $short -TimeoutSeconds 3 }
  $pingOk = ($pingOkFqdn -or $pingOkShort)
  $pingStatus = if ($pingOk) { 'Success' } else { 'PingFail' }
  $target = if ($pingOkShort) { $short } else { $dcFqdn }
  Write-Stage -Dc $dcFqdn -Message ("PingStatus={0} (target={1})" -f $pingStatus, $target) -Color Gray

  # Etapa 2/5 - Serviços
  Update-ProgressSafe -Id 1 -ParentId 0 -Activity $dcFqdn -Status "Etapa 2/5: Serviços" -Percent 30
  Write-Stage -Dc $dcFqdn -Message "Etapa 2/5: Serviços (Netlogon/NTDS/DNS)..." -Color Cyan

  $netlogon = Get-ServiceStatusSafe -ComputerName $target -ServiceName 'Netlogon'
  $ntds     = Get-ServiceStatusSafe -ComputerName $target -ServiceName 'NTDS'
  $dnsSvc   = Get-ServiceStatusSafe -ComputerName $target -ServiceName 'DNS'
  Write-Stage -Dc $dcFqdn -Message ("Netlogon={0} | NTDS={1} | DNS={2}" -f $netlogon, $ntds, $dnsSvc) -Color Gray

  # Etapa 3/5 - Shares + Portas
  Update-ProgressSafe -Id 1 -ParentId 0 -Activity $dcFqdn -Status "Etapa 3/5: Shares/Portas" -Percent 55
  Write-Stage -Dc $dcFqdn -Message "Etapa 3/5: Shares e Portas TCP/UDP..." -Color Cyan

  $tNetlogonShare = Test-UncShare -ComputerName $target -ShareName 'NETLOGON'
  $tSysvolShare   = Test-UncShare -ComputerName $target -ShareName 'SYSVOL'
  Write-Stage -Dc $dcFqdn -Message ("Shares: NETLOGON={0} | SYSVOL={1}" -f $tNetlogonShare, $tSysvolShare) -Color Gray

  $tcpStatus = @{}
  foreach ($k in $TcpPortsToCheck.Keys) {
    $tcpStatus[$k] = Test-TcpPort -ComputerName $target -Port $TcpPortsToCheck[$k] -TimeoutSeconds 3
  }

  $udpStatus = @{}
  foreach ($k in $UdpPortsToCheck.Keys) {
    if ($k -eq 'DNS_UDP') {
      $udpStatus[$k] = Test-DnsUdpFunctional -Name $target -Server $target
      continue
    }
    if (($k -eq 'KerberosUDP' -or $k -eq 'LDAPUDP') -and -not $IncludeUdpLegacy) {
      $udpStatus[$k] = 'NotTested'
      continue
    }
    $udpStatus[$k] = Test-UdpPort -ComputerName $target -Port $UdpPortsToCheck[$k] -TimeoutSeconds 3
  }

  # Etapa 4/5 - DNS funcional
  Update-ProgressSafe -Id 1 -ParentId 0 -Activity $dcFqdn -Status "Etapa 4/5: DNS funcional" -Percent 75
  Write-Stage -Dc $dcFqdn -Message "Etapa 4/5: DNS funcional (A/SRV/PTR)..." -Color Cyan

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

  Write-Stage -Dc $dcFqdn -Message ("DNS: A(Self)={0} | SRV(Forest)={1} | PTR(Self)={2}" -f $dnsA, $dnsSRV, $dnsPTR) -Color Gray

  # Etapa 5/5 - DCDIAG
  Update-ProgressSafe -Id 1 -ParentId 0 -Activity $dcFqdn -Status "Etapa 5/5: DCDIAG" -Percent 90
  Write-Stage -Dc $dcFqdn -Message "Etapa 5/5: Executando DCDIAG (1x)..." -Color Yellow

  $dcdiag = Invoke-DcDiagSummary -ComputerName $target -TimeoutSeconds $TimeoutSeconds
  Write-Stage -Dc $dcFqdn -Message ("DCDIAG: NetLogons={0} Replications={1} Services={2} Advertising={3} FSMO={4}" -f `
      $dcdiag.NetLogons,$dcdiag.Replications,$dcdiag.Services,$dcdiag.Advertising,$dcdiag.FSMOCheck) -Color Green

  $sw.Stop()

  # Montagem do resultado
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

  $row | Add-Member -NotePropertyName OverallStatus -NotePropertyValue (Get-OverallStatus -Row $row)

  Update-ProgressSafe -Id 1 -ParentId 0 -Activity $dcFqdn -Status "Concluído" -Percent 100
  Complete-ProgressSafe -Id 1 -Activity $dcFqdn

  Write-Stage -Dc $dcFqdn -Message ("Finalizado. Overall={0} | ElapsedMs={1}" -f $row.OverallStatus, $row.ElapsedMs) -Color Magenta

  $row
}

Complete-ProgressSafe -Id 0 -Activity "AD Health Check (PS 5.1)"

$ResultsArr = $ResultsArr | Sort-Object Identity

# ============================================================
# 9) Exportações
# ============================================================

if ($ExportCsv) {
  try {
    $ResultsArr | Export-Csv -NoTypeInformation -Path $ExportCsv -Encoding UTF8
    Write-Host "Export CSV: $((Resolve-Path -LiteralPath $ExportCsv).Path)" -ForegroundColor Green
  } catch { Write-Warning "CSV: $($_.Exception.Message)" }
}

if ($ExportJson) {
  try {
    $ResultsArr | ConvertTo-Json -Depth 6 | Out-File -FilePath $ExportJson -Encoding UTF8
    Write-Host "Export JSON: $((Resolve-Path -LiteralPath $ExportJson).Path)" -ForegroundColor Green
  } catch { Write-Warning "JSON: $($_.Exception.Message)" }
}

# ============================================================
# 10) HTML
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

$htmlHeader = @"
<html>
<head><meta charset="utf-8" /><title>Active Directory Health Check</title>
$css
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
  <b>Início:</b> $StartDate &nbsp; | &nbsp; <b>Fim:</b> $EndDate &nbsp; | &nbsp; <b>Timeout:</b> ${TimeoutSeconds}s
</div>

<div class='note'>
  <b>Nota sobre UDP:</b> Kerberos/LDAP via UDP pode não responder (silencioso), gerando <i>NoReply</i>.
  Por padrão, estes UDP legados ficam como <i>NotTested</i>. Para habilitar, use <b>-IncludeUdpLegacy</b>.
  O DNS UDP é validado com uma consulta funcional (nslookup).
</div>

<table>
  <tr>
    <th>Identity</th>
    <th>OverallStatus</th>
    <th>Ping</th>
    <th>Netlogon</th>
    <th>NTDS</th>
    <th>DNS Svc</th>
    <th>NetLogons Test</th>
    <th>Replications</th>
    <th>ReplErr</th>
    <th>Services Test</th>
    <th>Advertising</th>
    <th>FSMOCheck</th>
    <th>NETLOGON</th>
    <th>SYSVOL</th>
    <th>KRB TCP</th>
    <th>LDAP TCP</th>
    <th>LDAPS</th>
    <th>GC</th>
    <th>GC SSL</th>
    <th>DNS TCP</th>
    <th>DNS UDP</th>
    <th>DNS A</th>
    <th>DNS SRV</th>
    <th>DNS PTR</th>
    <th>RPC135</th>
    <th>139</th>
    <th>445</th>
    <th>KRB UDP</th>
    <th>LDAP UDP</th>
    <th>ElapsedMs</th>
  </tr>
"@

function Cell {
  param([string]$value)
  $cls = Get-StatusColor -Status $value
  return "<td class='$cls'><b>$value</b></td>"
}

$rows = foreach ($r in $ResultsArr) {
  $clsOverall = 'warn'
  if ($r.OverallStatus -eq 'OK') { $clsOverall = 'ok' }
  elseif ($r.OverallStatus -eq 'Failed') { $clsOverall = 'fail' }

  $replErr = $r.ReplicationErrorCode
  if ([string]::IsNullOrWhiteSpace($replErr)) { $replErr = '-' }

  "<tr>" +
    "<td class='idcell'>$($r.Identity)</td>" +
    "<td class='$clsOverall'><b>$($r.OverallStatus)</b></td>" +
    (Cell $r.PingStatus) +
    (Cell $r.NetlogonService) +
    (Cell $r.NTDSService) +
    (Cell $r.DNSServiceStatus) +
    (Cell $r.NetlogonsTest) +
    (Cell $r.ReplicationTest) +
    (Cell $replErr) +
    (Cell $r.ServicesTest) +
    (Cell $r.AdvertisingTest) +
    (Cell $r.FSMOCheckTest) +
    (Cell $r.NETLOGONTest) +
    (Cell $r.SYSVOLTest) +
    (Cell $r.KerberosTCP) +
    (Cell $r.LDAPTCP) +
    (Cell $r.LDAPS) +
    (Cell $r.GCLDAP) +
    (Cell $r.GCLDAPS) +
    (Cell $r.DNS_TCP) +
    (Cell $r.DNS_UDP) +
    (Cell $r.DNS_A_Self) +
    (Cell $r.DNS_SRV_Forest) +
    (Cell $r.DNS_PTR_Self) +
    (Cell $r.NTLM_RPC135) +
    (Cell $r.NTLM_139) +
    (Cell $r.NTLM_445) +
    (Cell $r.KerberosUDP) +
    (Cell $r.LDAPUDP) +
    "<td><b>$($r.ElapsedMs)</b></td>" +
  "</tr>"
}

$htmlFooter = @"
</table>
<br/>
<div class='meta'>
  Cliente: $ClientName &nbsp; | &nbsp; Analista: $AnalystName <br/>
  Start: $StartDate &nbsp; | &nbsp; End: $EndDate &nbsp; | &nbsp; Floresta: $ForestRoot
</div>
</body>
</html>
"@

try {
  $dir = Split-Path -Path $OutputPath -Parent
  if ($dir -and -not (Test-Path -LiteralPath $dir)) {
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
  }
  ($htmlHeader + ($rows -join "`n") + $htmlFooter) | Out-File -FilePath $OutputPath -Encoding UTF8 -Force
  $resolved = Resolve-Path -LiteralPath $OutputPath -ErrorAction Stop
  Write-Host ("Relatório HTML salvo em: {0}" -f $resolved.Path) -ForegroundColor Green
} catch {
  Write-Warning "Falha ao salvar HTML: $($_.Exception.Message)"
}

# ============================================================
# 11) E-mail opcional (PS 5.1)
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
  } catch {
    Write-Warning "Falha ao enviar e-mail: $($_.Exception.Message)"
  }
} else {
  Write-Host "Envio de e-mail não configurado (SmtpHost ou EmailTo ausentes)." -ForegroundColor Yellow
}

Write-Host "Concluído em $(Get-Date)." -ForegroundColor Cyan
