<#
  Script: Validação AD – RPC/DCOM + Logs Remotos + DCDIAG + WMI/CIM + (opcional) PortQry
  Autor:  Criado por Eduardo Popovici
  Nota:   Para que TODOS os testes funcionem (especialmente o mapeamento de endpoints RPC no EPM/135),
          instale o PortQry e deixe acessível (ex.: C:\PortQryV2\portqry.exe).
#>

$ErrorActionPreference = 'Stop'
$TargetServer = 'SRV-AD-02'

$timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$desktop   = Join-Path $env:USERPROFILE 'Desktop'
$outCsv    = Join-Path $desktop ("Validacao_RPC_Logs_{0}_{1}.csv"  -f $TargetServer,$timestamp)
$outHtml   = Join-Path $desktop ("Validacao_RPC_Logs_{0}_{1}.html" -f $TargetServer,$timestamp)

function New-Result {
    param(
      [string]$Category,
      [string]$TestName,
      [string]$Target,
      [bool]  $Passed,
      [string]$Detail = ''
    )
    [pscustomobject]@{
        Timestamp = (Get-Date).ToString('s')
        Category  = $Category
        Test      = $TestName
        Target    = $Target
        Passed    = $Passed
        Detail    = $Detail
    }
}

# Escape simples para HTML
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

$results = [System.Collections.Generic.List[object]]::new()

# ============= 1) Conectividade RPC =============
try {
    $t135 = Test-NetConnection -ComputerName $TargetServer -Port 135 -WarningAction SilentlyContinue
    $lat  = if ($t135.PingSucceeded) { $t135.PingReplyDetails.RoundtripTime } else { $null }
    $results.Add( (New-Result 'Conectividade' 'TCP Port' "$($TargetServer):135" $t135.TcpTestSucceeded ("Latency(ms)={0}" -f $lat)) )
} catch { $results.Add( (New-Result 'Conectividade' 'TCP Port' "$($TargetServer):135" $false $_.Exception.Message) ) }

# Porta dinâmica (amostra – pode falhar sem indicar problema real)
$highPort = 49152
try {
    $thigh = Test-NetConnection -ComputerName $TargetServer -Port $highPort -WarningAction SilentlyContinue
    $lat2  = if ($thigh.PingSucceeded) { $thigh.PingReplyDetails.RoundtripTime } else { $null }
    $results.Add( (New-Result 'Conectividade' 'TCP Port (dynamic sample)' "$($TargetServer):$highPort" $thigh.TcpTestSucceeded ("Latency(ms)={0}" -f $lat2)) )
} catch { $results.Add( (New-Result 'Conectividade' 'TCP Port (dynamic sample)' "$($TargetServer):$highPort" $false $_.Exception.Message) ) }

# ============= 2) Firewall – regras relevantes =============
try {
    $fwRules = Get-NetFirewallRule |
      Where-Object {
        $_.Enabled -eq 'True' -and (
          $_.DisplayName -match 'Evento|Event|Registro' -or
          $_.DisplayGroup -match 'Evento|Event|Registro' -or
          $_.DisplayGroup -match 'Remote Service Management|Gerenciamento.*Servi'
        )
      }
    $results.Add( (New-Result 'Firewall' 'Firewall Rules Summary' $env:COMPUTERNAME ($fwRules.Count -gt 0) ("EnabledRules={0}" -f $fwRules.Count)) )
    foreach ($r in $fwRules) {
        $results.Add( (New-Result 'Firewall' 'Firewall Rule' $r.DisplayName $true ("Group={0}; Direction={1}; Action={2}" -f $r.DisplayGroup,$r.Direction,$r.Action)) )
    }
} catch {
    $results.Add( (New-Result 'Firewall' 'Firewall Rules Summary' $env:COMPUTERNAME $false $_.Exception.Message) )
}

# ============= 3) Serviços essenciais =============
try {
    Get-Service RpcSs,EventLog | ForEach-Object {
        $results.Add( (New-Result 'Serviços' 'Service' $_.Name ($_.Status -eq 'Running') ("Status={0}; StartType={1}" -f $_.Status,$_.StartType)) )
    }
} catch {
    $results.Add( (New-Result 'Serviços' 'Service' 'RpcSs/EventLog' $false $_.Exception.Message) )
}

# ============= 4) Leitura remota de eventos =============
function Test-RemoteLog {
    param([string]$Computer,[string]$LogName,[int]$Max=3)
    try {
        $null = Get-WinEvent -ComputerName $Computer -ListLog $LogName -ErrorAction Stop
        $ev = Get-WinEvent -ComputerName $Computer -LogName $LogName -MaxEvents $Max -ErrorAction Stop
        $results.Add( (New-Result 'Logs Remotos' ("Remote Event Read ($LogName)") $Computer $true ("Count={0}" -f ($ev | Measure-Object).Count)) )
    }
    catch {
        $results.Add( (New-Result 'Logs Remotos' ("Remote Event Read ($LogName)") $Computer $false $_.Exception.Message) )
    }
}
Test-RemoteLog -Computer $TargetServer -LogName 'System'
Test-RemoteLog -Computer $TargetServer -LogName 'Application'
Test-RemoteLog -Computer $TargetServer -LogName 'DFS Replication'   # pode não existir em todos

# ============= 5) WMI/CIM remoto (prova de RPC/DCOM) =============
try {
    $os = Get-CimInstance -ClassName Win32_OperatingSystem -ComputerName $TargetServer -ErrorAction Stop
    $results.Add( (New-Result 'WMI/CIM' 'CIM Win32_OperatingSystem' $TargetServer $true ("Caption={0}; Version={1}" -f $os.Caption,$os.Version)) )
} catch {
    $results.Add( (New-Result 'WMI/CIM' 'CIM Win32_OperatingSystem' $TargetServer $false $_.Exception.Message) )
}

# ============= 6) WinRM/Invoke-Command + wevtutil (fallback automático) =============
try {
    # Mais universal
    $ic = Invoke-Command -ComputerName $TargetServer -ScriptBlock { wevtutil qe System /c:3 /f:text } -ErrorAction Stop
    $ok = ($ic -is [array]) -or ($ic -is [string]) -and ($ic.Length -gt 0)
    $snippet = ($ic | Select-Object -First 1)
    $results.Add( (New-Result 'WinRM/Invoke-Command' 'Invoke-Command wevtutil' $TargetServer $ok ("FirstLine={0}" -f $snippet)) )
}
catch {
    # Fallback para XML
    try {
        $ic2 = Invoke-Command -ComputerName $TargetServer -ScriptBlock { wevtutil qe System /c:3 /f:xml } -ErrorAction Stop
        $ok2 = ($ic2 -is [array]) -or ($ic2 -is [string]) -and ($ic2.Length -gt 0)
        $snippet2 = ($ic2 | Select-Object -First 1)
        $results.Add( (New-Result 'WinRM/Invoke-Command' 'Invoke-Command wevtutil (xml)' $TargetServer $ok2 ("FirstLine={0}" -f $snippet2)) )
    }
    catch {
        $results.Add( (New-Result 'WinRM/Invoke-Command' 'Invoke-Command wevtutil' $TargetServer $false $_.Exception.Message) )
    }
}

# ============= 7) PortQry (opcional) – mapeia EPM 135 =============
# (1) opcional: adicionar C:\PortQryV2 ao PATH apenas nesta sessão
if (Test-Path 'C:\PortQryV2') {
    $env:Path = 'C:\PortQryV2;' + $env:Path
}

# (2) detectar portqry em PATH, System32 e C:\PortQryV2
$portqry = $null
try {
    $cmd = Get-Command portqry.exe -ErrorAction SilentlyContinue
    if     ($cmd) { $portqry = $cmd.Source }
    elseif (Test-Path 'C:\Windows\System32\portqry.exe') { $portqry = 'C:\Windows\System32\portqry.exe' }
    elseif (Test-Path 'C:\PortQryV2\portqry.exe')        { $portqry = 'C:\PortQryV2\portqry.exe' }
}
catch {}

if ($portqry) {
    try {
        $LASTEXITCODE = $null
        $pqout = & $portqry -n $TargetServer -e 135 -p tcp 2>&1 | Out-String
        # RC: 0=LISTENING, 1=NOT LISTENING, 2=FILTERED
        $pass = ($LASTEXITCODE -eq 0)
        $snippet = ($pqout -split "`r?`n" | Select-Object -First 3) -join ' | '
        $results.Add( (New-Result 'PortQry' 'PortQry EPM 135' $TargetServer $pass ("RC=$LASTEXITCODE; $snippet")) )
    }
    catch {
        $results.Add( (New-Result 'PortQry' 'PortQry EPM 135' $TargetServer $false $_.Exception.Message) )
    }
}
else {
    $results.Add( (New-Result 'PortQry' 'PortQry EPM 135' $TargetServer $false 'portqry.exe não encontrado – teste ignorado. Instale/aponte o PortQry (ex.: C:\PortQryV2\portqry.exe) e reexecute para mapear endpoints RPC do EPM 135.') )
}

# ============= 8) DCDIAG (SystemLog/DFSREvent/KccEvent) =============
$dcdiagTests = @('systemlog','dfsrevent','kccevent')
foreach ($t in $dcdiagTests) {
    try {
        $LASTEXITCODE = $null
        $out = & dcdiag /test:$t /s:$TargetServer 2>&1 | Out-String
        $pass = ($LASTEXITCODE -eq 0) -and ($out -notmatch '0x6ba') -and ($out -notmatch 'RPC (?:server|servidor) (?:is )?unavailable|RPC.*indispon[ií]vel')
        $snippet = ($out -split "`r?`n" | Select-Object -First 3) -join ' | '
        $results.Add( (New-Result 'DCDIAG' ("dcdiag:{0}" -f $t) $TargetServer $pass $snippet) )
    }
    catch {
        $results.Add( (New-Result 'DCDIAG' ("dcdiag:{0}" -f $t) $TargetServer $false $_.Exception.Message) )
    }
}

# ============= Exportar CSV =============
$results | Export-Csv -Path $outCsv -NoTypeInformation -Encoding UTF8

# ============= Geração do HTML (cards + âncoras + tabelas por categoria + falhas detalhadas) =============
$passCount = ($results | Where-Object {$_.Passed}).Count
$failItems =  $results | Where-Object {$_.Passed -eq $false}
$failCount = $failItems.Count
$total     = $results.Count

# Lista de categorias na ordem desejada
$categories = @('Conectividade','Firewall','Serviços','Logs Remotos','WMI/CIM','WinRM/Invoke-Command','PortQry','DCDIAG')

function Get-Advice {
    param([string]$Category,[string]$Test,[string]$Target,[string]$Detail)
    $c = $Category.ToLower()
    $t = $Test.ToLower()
    $d = ($Detail | Out-String).ToLower()

    if ($c -eq 'conectividade' -and $t -like 'tcp port (dynamic sample)*') {
        return 'Teste amostral de porta dinâmica RPC. Falha aqui não indica problema real; valide a funcionalidade (Get-WinEvent remoto, CIM/WMI, dcdiag).'
    }
    if ($c -eq 'winrm/invoke-command' -and $t -like 'invoke-command wevtutil*' -and ($d -match 'valor inv[aá]lido|invalid value')) {
        return 'Use o formato /f:text (mais universal). O script já faz fallback para /f:xml quando necessário.'
    }
    if ($c -eq 'portqry' -and ($d -match 'n[oã]o encontrado|not found|teste ignorado')) {
        return 'Instale/aponte o PortQry (ex.: C:\PortQryV2\portqry.exe) para mapear endpoints RPC publicados no EPM (porta 135). É opcional, mas muito útil para troubleshooting de RPC.'
    }
    if ($c -eq 'logs remotos' -and $t -like 'remote event read*') {
        return 'Se falhar: verifique Firewall (grupos “Gerenciamento remoto de log de eventos”/Remote Event Log Management), RPC 135 e portas dinâmicas, além de DNS/ACLs e permissões.'
    }
    if ($c -eq 'dcdiag' -and ($d -match '0x6ba|rpc.*indispon')) {
        return 'Falha típica de consulta remota: libere RPC 135 + portas dinâmicas no Firewall e confirme resolução DNS/ACLs.'
    }
    return 'Verifique Firewall (RPC 135 e portas dinâmicas), DNS e permissões/WinRM conforme o tipo do teste.'
}

# Monta cards de categoria com contadores
$catCards = foreach ($cat in $categories) {
    $subset = $results | Where-Object { $_.Category -eq $cat }
    if (-not $subset) { continue }
    $ok = ($subset | Where-Object {$_.Passed}).Count
    $ko = ($subset | Where-Object {$_.Passed -eq $false}).Count
    "<a class='catcard' href='#cat_{0}'><div class='catname'>{0}</div><div class='catnums'><span class='oknum'>{1}</span>/<span class='totalnum'>{2}</span></div></a>" -f (Escape-Html $cat), $ok, ($subset.Count)
}

# Monta tabelas por categoria
$catTables = foreach ($cat in $categories) {
    $subset = $results | Where-Object { $_.Category -eq $cat }
    if (-not $subset) { continue }
    $rows = foreach ($r in $subset) {
        $cls = if ($r.Passed) { 'pass' } else { 'fail' }
        "<tr class='$cls'><td>{0}</td><td>{1}</td><td>{2}</td><td><pre>{3}</pre></td></tr>" -f (Escape-Html $r.Test),(Escape-Html $r.Target),($r.Passed),(Escape-Html $r.Detail)
    }
@"
  <div class='section' id='cat_$(Escape-Html $cat)'>
    <h2>$cat</h2>
    <table>
      <thead><tr><th>Teste</th><th>Alvo</th><th>Passou</th><th>Detalhe</th></tr></thead>
      <tbody>
        $($rows -join "`n")
      </tbody>
    </table>
  </div>
"@
}

# Seção de falhas detalhadas
$failBlocks = if ($failCount -gt 0) {
    foreach ($f in $failItems) {
        $advice = Get-Advice -Category $f.Category -Test $f.Test -Target $f.Target -Detail $f.Detail
        @"
<div class='failcard'>
  <div class='ftitle'>$(Escape-Html $f.Category) — $(Escape-Html $f.Test)</div>
  <div class='fmeta'><b>Alvo:</b> $(Escape-Html $f.Target)</div>
  <div class='fdetail'><b>Detalhe:</b> <pre>$(Escape-Html $f.Detail)</pre></div>
  <div class='fadvice'><b>Dica:</b> $(Escape-Html $advice)</div>
</div>
"@
    }
} else {
    "<p>Tudo certo — nenhuma falha registrada.</p>"
}

# Nota PortQry (se não instalado)
$portqryNote = if ($results | Where-Object { $_.Category -eq 'PortQry' -and $_.Detail -match 'n[oã]o encontrado|not found|teste ignorado' }) {
@"
<div class='note'>
  <b>Nota:</b> O teste PortQry foi ignorado porque o <code>portqry.exe</code> não foi encontrado. 
  Instale/aponte o PortQry (ex.: <code>C:\PortQryV2\portqry.exe</code>) e reexecute para mapear endpoints RPC publicados no EPM (porta 135).
</div>
"@
} else { '' }

# HTML final (com suporte a dark mode via prefers-color-scheme)
$html = @"
<!DOCTYPE html>
<html lang="pt-br">
<head>
<meta charset="utf-8"/>
<title>Validação RPC/Logs – $TargetServer ($timestamp)</title>
<style>
  :root { color-scheme: light dark; }
  body { font-family: Segoe UI, Roboto, Arial, sans-serif; margin: 24px; }
  h1 { margin: 0 0 4px 0; font-size: 22px; }
  .sub { color:#555; margin: 0 0 16px 0; }
  .summary { display:flex; gap:16px; margin: 16px 0 12px 0; flex-wrap: wrap; }
  .card { padding:12px 16px; border-radius:10px; box-shadow:0 1px 3px rgba(0,0,0,.08); }
  .ok    { background:#e8fff0; border:1px solid #b6f0c9; }
  .bad   { background:#ffecec; border:1px solid #ffb3b3; }
  .all   { background:#eef4ff; border:1px solid #c9d8ff; }

  .catgrid { display:flex; gap:10px; flex-wrap: wrap; margin:10px 0 20px 0; }
  .catcard { text-decoration:none; color:inherit; background:#fafafa; border:1px solid #e7e7e7; border-radius:10px; padding:10px 12px; display:flex; gap:12px; align-items:center; }
  .catcard:hover { box-shadow:0 1px 6px rgba(0,0,0,.12); }
  .catname { font-weight:600; }
  .catnums .oknum { color:#0a7a2d; font-weight:700; }
  .catnums .totalnum { color:#666; }

  table { width:100%; border-collapse: collapse; }
  th, td { border-bottom:1px solid #eee; padding:8px 10px; vertical-align: top; }
  th { text-align:left; background:#fafafa; }
  tr.pass td { background:#f7fff9; }
  tr.fail td { background:#fff7f7; }
  pre { margin:0; white-space: pre-wrap; word-wrap: break-word; }
  .section { margin-top:28px; }
  .failcard { border:1px solid #ffd2d2; background:#fff5f5; padding:12px; border-radius:10px; margin-bottom:12px; }
  .ftitle { font-weight:600; margin-bottom:4px; }
  .fmeta { color:#333; margin-bottom:6px; }
  .fdetail { margin-bottom:6px; }
  .fadvice { color:#0f5132; background:#d1e7dd; border:1px solid #badbcc; padding:8px; border-radius:8px; }
  .note { margin:14px 0; padding:10px; border-radius:8px; background:#fff9e6; border:1px solid #ffe08a; }
  .footer { color:#777; font-size:12px; margin-top:24px; }

  @media (prefers-color-scheme: dark) {
    body { color:#eee; background:#121212; }
    .sub { color:#bbb; }
    .card { box-shadow:none; }
    .all { background:#1b2744; border-color:#30487c; }
    .ok  { background:#14301d; border-color:#1f7a46; }
    .bad { background:#3a1b1b; border-color:#7a2e2e; }
    th { background:#1b1b1b; }
    th, td { border-bottom:1px solid #2a2a2a; }
    tr.pass td { background:#0e2216; }
    tr.fail td { background:#2a1515; }
    .catcard { background:#1b1b1b; border-color:#2a2a2a; }
    .fmeta { color:#ddd; }
    .note { background:#2f2a18; border-color:#7a6d2e; }
    .fadvice { color:#d1f2e1; background:#123b2a; border-color:#1f6d4e; }
  }
</style>
</head>
<body>
  <h1>Validação RPC/Logs – $TargetServer</h1>
  <div class="sub">Geração: $timestamp — Total: $total, PASS: $passCount, FAIL: $failCount</div>

  <div class="summary">
    <div class="card all">Total: <b>$total</b></div>
    <div class="card ok">Pass: <b>$passCount</b></div>
    <div class="card bad">Fail: <b>$failCount</b></div>
  </div>

  <div class="catgrid">
    $($catCards -join "`n")
  </div>

  $portqryNote

  $($catTables -join "`n")

  <div class="section">
    <h2>Falhas detalhadas</h2>
    $($failBlocks -join "`n")
  </div>

  <div class="footer">
    * Observação: Testes de porta dinâmica (ex.: 49152) são amostrais; falha neles não indica problema quando as validações funcionais (Get-WinEvent remoto, CIM/WMI e dcdiag) passam.
  </div>
</body>
</html>
"@

# Salvar HTML em UTF-8
$html | Out-File -FilePath $outHtml -Encoding utf8

Write-Host "Relatórios salvos:"
Write-Host " - CSV : $outCsv"
Write-Host " - HTML: $outHtml"
