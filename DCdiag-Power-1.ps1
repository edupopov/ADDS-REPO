<# 
  Merge – AD Health Check + DCDiag (PS 5.1/7)
  Autor: Eduardo Popovici (base dos dois scripts) – Unificado e comentado
  Versão: Beta 1.0 - ainda em refinamento - Não esta pronto

  O que faz:
   - Executa DCDiag com /e /q /v /c /fix; grava TXT e consolida parsing EN/PT no HTML (mesmo formato do script 2).
   - Executa Health Check por DC (script 1): ping, serviços (Netlogon/NTDS/DNS), shares (NETLOGON/SYSVOL),
     portas TCP/UDP (Kerb/LDAP/LDAPS/GC/NTLM/DNS), DNS funcional (A, SRV floresta, PTR),
     e DCDiag por teste (Netlogons/Replications/Services/Advertising/FSMOCheck) com timeout real.
   - Gera um ÚNICO arquivo HTML com o layout do script 2 + seção "Matriz de Saúde do AD".

  Observações:
   - Compatível com Windows PowerShell 5.1 e PowerShell 7+ (sem -Encoding no Tee-Object).
   - Mantém a nota de /q (quiet) e a seção de “Falhas/Avisos detalhados” do DCDiag.
   - Explica "NoReply" para UDP (sem handshake).
#>

[CmdletBinding()]
param(
  [string]$Domain,                       # Se não informado, será detectado a partir da floresta (útil para quando não temos muitas informações)
  [Parameter(Mandatory=$true)][string]$AnalystName,
  [Parameter(Mandatory=$true)][string]$ClientName,
  [int]$TimeoutSeconds = 180,

  # Caminhos de saída
  [string]$OutputPath,                   # HTML consolidado. Se vazio, Desktop\AD-DCDiag_<dominio>_<timestamp>.html
  [string]$ExportCsv,                    # Export opcional da matriz de saúde
  [string]$ExportJson                    # Export opcional da matriz de saúde
)

$ErrorActionPreference = 'Stop'
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Unrestricted -Force

# ===== Utilidades comuns =====
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

# Mapeia status do Health Check (script 1) para classes visuais (pass/warn/fail)
function Get-CellClass {
  param([Parameter(Mandatory)][string]$Status)
  switch -Regex ($Status) {
    '^(Success|Running|Passed|Open)$' { 'cpass' }
    '^(Failed|Closed|PingFail)$'      { 'cfail' }
    default                           { 'cwarn' } # Unknown, Timeout, ConnError, NoReply, etc.
  }
}

# ===== Descoberta de DCs/Floresta =====
try {
  $forest = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
  $DCServers = $forest.Domains | ForEach-Object { $_.DomainControllers } | ForEach-Object { $_.Name } | Sort-Object -Unique
  if (-not $Domain -or [string]::IsNullOrWhiteSpace($Domain)) {
    $Domain = $forest.RootDomain.Name
  }
  if (-not $DCServers) { throw "Nenhum DC encontrado." }
} catch {
  throw "Falha ao enumerar DCs/Floresta: $($_.Exception.Message)"
}

# ===== Saídas =====
$timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$desktop   = Join-Path $env:USERPROFILE 'Desktop'
if (-not $OutputPath -or [string]::IsNullOrWhiteSpace($OutputPath)) {
  $OutputPath = Join-Path $desktop ("AD-DCDiag_{0}_{1}.html" -f $Domain,$timestamp)
}
$outTxt = Join-Path $desktop ("DCDiag_{0}_{1}.txt" -f $Domain,$timestamp)

# ===== DCDiag Completo =====
$dcdiagCmd = Get-Command dcdiag -ErrorAction SilentlyContinue
if (-not $dcdiagCmd) {
  throw "dcdiag não encontrado. Instale RSAT AD DS Tools ou execute em um DC."
}

Write-Host "Executando DCDIAG para o domínio $Domain ..."
$LASTEXITCODE = $null
$dcArgs = @('/e','/q','/v','/c','/fix',"/testdomain:$Domain")

# Captura a saída e salva TXT UTF-8
$null = & dcdiag @dcArgs 2>&1 | Tee-Object -Variable dcRaw
$dcOutput = $dcRaw
$dcOutput | Out-File -FilePath $outTxt -Encoding UTF8
$exitCode = $LASTEXITCODE
Write-Host "Saída TXT: $outTxt"
Write-Host "ExitCode do dcdiag: $exitCode"

# ===== Parser DCDiag (EN/PT) =====
$serverRegexEN = '^\s*Testing server:\s*(.+)$'
$serverRegexPT = '^\s*Testando servidor:\s*(.+)$'
$startRegexEN  = '^\s*Starting test:\s*(.+)$'
$startRegexPT  = '^\s*Iniciando teste:\s*(.+)$'

$rxFail = [regex]'(?i)\bfailed\b|\bfalhou\b|\bfatal\b|\berror(s)?\b|\berro\b|\bcritical\b|\bcr[ií]tico\b|n[ãa]o.*(responde|dispon[ií]vel)|cannot|could not|failed to'
$rxWarn = [regex]'(?i)\bwarn(ing)?\b|aviso(s)?'

$dcTests = New-Object System.Collections.Generic.List[object]
$currentServer = $null
$currentTest   = $null
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
    Server = 'N/D'; Test='Resumo';
    Status = if ($exitCode -eq 0) {'PASS'} else {'WARN'};
    Detail = "Saída minimizada por /q. Consulte o TXT: $outTxt"
  })
}

# ===== Health Check por DC (script 1) =====
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
    Start-Sleep -Milliseconds 300
    if ($udp.Available -gt 0) { 
      $null = $udp.Receive([ref]([System.Net.IPEndPoint]::new([System.Net.IPAddress]::Any,0)))
      $udp.Close()
      return 'Open'
    } else {
      $udp.Close()
      return 'NoReply'   # Porta pode estar aberta sem responder/filtrada
    }
  } catch {
    try { $udp.Close() } catch {}
    return 'NoReply'
  }
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

# Portas a verificar
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
  KerberosUDP = 88
  LDAPUDP     = 389
  DNS_UDP     = 53
}

# Coleta por DC
$StartDate = Get-Date
$Health = foreach ($dcFqdn in $DCServers) {
  $short = ($dcFqdn -split '\.')[0]

  # Ping
  $pingOkFqdn  = Test-PingHost -ComputerName $dcFqdn -TimeoutSeconds 3
  $pingOkShort = $false
  if (-not $pingOkFqdn) { $pingOkShort = Test-PingHost -ComputerName $short -TimeoutSeconds 3 }
  $pingOk = $pingOkFqdn -or $pingOkShort
  $pingStatus = if ($pingOk) { 'Success' } else { 'PingFail' }
  $target = if ($pingOkShort) { $short } else { $dcFqdn }

  # Serviços
  $netlogon = Get-ServiceStatusSafe -ComputerName $target -ServiceName 'Netlogon'
  $ntds     = Get-ServiceStatusSafe -ComputerName $target -ServiceName 'NTDS'
  $dnsSvc   = Get-ServiceStatusSafe -ComputerName $target -ServiceName 'DNS'

  # Testes DCDiag específicos
  $tNetlogons   = Invoke-DcDiagTest -ComputerName $target -TestName 'Netlogons'    -Timeout $TimeoutSeconds
  $tRepl        = Invoke-DcDiagTest -ComputerName $target -TestName 'Replications' -Timeout $TimeoutSeconds
  $tServices    = Invoke-DcDiagTest -ComputerName $target -TestName 'Services'     -Timeout $TimeoutSeconds
  $tAdvertising = Invoke-DcDiagTest -ComputerName $target -TestName 'Advertising'  -Timeout $TimeoutSeconds
  $tFSMO        = Invoke-DcDiagTest -ComputerName $target -TestName 'FSMOCheck'    -Timeout $TimeoutSeconds

  # Shares
  $tNetlogonShare = Test-UncShare -ComputerName $target -ShareName 'NETLOGON'
  $tSysvolShare   = Test-UncShare -ComputerName $target -ShareName 'SYSVOL'

  # Portas TCP
  $tcpStatus = @{}
  foreach ($k in $TcpPortsToCheck.Keys) {
    $tcpStatus[$k] = Test-TcpPort -ComputerName $target -Port $TcpPortsToCheck[$k] -TimeoutSeconds 3
  }

  # Portas UDP
  $udpStatus = @{}
  foreach ($k in $UdpPortsToCheck.Keys) {
    $udpStatus[$k] = Test-UdpPort -ComputerName $target -Port $UdpPortsToCheck[$k] -TimeoutSeconds 3
  }

  # DNS – funcionais usando o próprio DC como servidor
  $dnsA   = 'Unknown'
  $dnsSRV = 'Unknown'
  $dnsPTR = 'Unknown'
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
    } else {
      $dnsPTR = 'Unknown'
    }
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

    # Portas TCP
    KerberosTCP       = $tcpStatus.KerberosTCP
    LDAPTCP           = $tcpStatus.LDAPTCP
    LDAPS             = $tcpStatus.LDAPS
    GCLDAP            = $tcpStatus.GCLDAP
    GCLDAPS           = $tcpStatus.GCLDAPS
    NTLM_RPC135       = $tcpStatus.NTLM_RPC135
    NTLM_139          = $tcpStatus.NTLM_139
    NTLM_445          = $tcpStatus.NTLM_445
    DNS_TCP           = $tcpStatus.DNS_TCP

    # Portas UDP
    KerberosUDP       = $udpStatus.KerberosUDP
    LDAPUDP           = $udpStatus.LDAPUDP
    DNS_UDP           = $udpStatus.DNS_UDP

    # DNS funcional
    DNS_A_Self        = $dnsA
    DNS_SRV_Forest    = $dnsSRV
    DNS_PTR_Self      = $dnsPTR

    AnalystName       = $AnalystName
    ClientName        = $ClientName
  }
}

$Health = $Health | Sort-Object Identity

# Exportações opcionais
if ($ExportCsv) {
  try { $Health | Export-Csv -NoTypeInformation -Path $ExportCsv -Encoding UTF8 } catch { Write-Warning "CSV: $($_.Exception.Message)" }
}
if ($ExportJson) {
  try { $Health | ConvertTo-Json -Depth 4 | Out-File -FilePath $ExportJson -Encoding UTF8 } catch { Write-Warning "JSON: $($_.Exception.Message)" }
}

# ===== HTML (formato do script 2, com seção adicional de Matriz de Saúde) =====
$total = $dcTests.Count
$pass  = ($dcTests | Where-Object {$_.Status -eq 'PASS'}).Count
$warn  = ($dcTests | Where-Object {$_.Status -eq 'WARN'}).Count
$fail  = ($dcTests | Where-Object {$_.Status -eq 'FAIL'}).Count

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
} else {
  "<p>Sem falhas/avisos detectados com os parâmetros atuais (/q). Consulte o TXT para detalhes.</p>"
}

# ===== Seção: Matriz de Saúde do AD (conectividade/serviços/portas/DNS) =====
# Monta cabeçalho das colunas semelhantes ao script 1, mas usando classes do tema 2
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
      'PingStatus',
      'NetlogonService',
      'NTDSService',
      'DNSServiceStatus',
      'NETLOGONTest',
      'SYSVOLTest',
      'NetlogonsTest',
      'ReplicationTest',
      'ServicesTest',
      'AdvertisingTest',
      'FSMOCheckTest',
      'KerberosTCP',
      'KerberosUDP',
      'LDAPTCP',
      'LDAPUDP',
      'LDAPS',
      'GCLDAP',
      'GCLDAPS',
      'DNS_TCP',
      'DNS_UDP',
      'DNS_A_Self',
      'DNS_SRV_Forest',
      'DNS_PTR_Self'
    )) {
      $val = [string]$r.$p
      $cls = Get-CellClass -Status $val
      $cells.Add("<td class='$cls'><b>$(Escape-Html $val)</b></td>")
  }
  "<tr>$($cells -join '')</tr>"
}

$noteUdp = @"
<div class='note'>
  <b>Nota sobre UDP / NoReply:</b> Em UDP não existe handshake como no TCP. O teste envia um datagrama simples; 
  se o servidor não responde (comum para Kerberos/LDAP/DNS em UDP), marcamos <i>NoReply</i>. 
  Isso não significa necessariamente porta fechada — pode estar <i>aberta porém silenciosa</i> ou filtrada por firewall. 
  Quando há retorno de erro/ICMP é marcado como <i>Closed</i>. Para conectividade crítica do AD, priorize portas TCP.
</div>
"@

# ===== HTML Final =====
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
  /* Cores por célula para a Matriz de Saúde */
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
  }
"@

$noteQ = @"
<div class='note'>
  <b>Nota:</b> O parâmetro <code>/q</code> (quiet) reduz a verbosidade do DCDiag e pode ocultar testes aprovados.
  Use este HTML para focar em falhas/avisos e o TXT para análise completa.
  <div>Arquivo TXT: <code>$outTxt</code></div>
  <div>ExitCode DCDiag: <code>$exitCode</code></div>
</div>
"@

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

$html = @"
<!DOCTYPE html>
<html lang="pt-br">
<head>
<meta charset="utf-8"/>
<title>AD & DCDiag ($Domain) – $timestamp</title>
<style>
$css
</style>
</head>
<body>
  <h1>Diagnóstico AD – Domínio $(Escape-Html $Domain)</h1>
  <div class="sub">Geração: $timestamp — DCDiag (itens mapeados): $total (PASS: $pass, WARN: $warn, FAIL: $fail)</div>

  <div class="summary">
    <div class="card all">Itens DCDiag: <b>$total</b></div>
    <div class="card ok">Pass: <b>$pass</b></div>
    <div class="card wrn">Warn: <b>$warn</b></div>
    <div class="card bad">Fail: <b>$fail</b></div>
  </div>

  $noteQ

  $($serverTables -join "`n")

  <div class="section">
    <h2>Falhas/Avisos detalhados (DCDiag)</h2>
    $($issueBlocks -join "`n")
  </div>

  $healthTable

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
