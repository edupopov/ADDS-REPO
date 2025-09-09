<# 
  Validação AD – RPC/DCOM + Leitura Remota de Logs + DCDIAG + WMI/CIM + (opcional) PortQry
  Saídas: CSV e HTML na Área de Trabalho do usuário atual
  Criado por Eduardo Popovici
#>

$ErrorActionPreference = 'Stop'
$TargetServer = 'SRV-AD-02'

$timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$desktop   = Join-Path $env:USERPROFILE 'Desktop'
$outCsv    = Join-Path $desktop ("Validacao_RPC_Logs_{0}_{1}.csv"  -f $TargetServer,$timestamp)
$outHtml   = Join-Path $desktop ("Validacao_RPC_Logs_{0}_{1}.html" -f $TargetServer,$timestamp)

function New-Result {
    param([string]$TestName,[string]$Target,[bool]$Passed,[string]$Detail='')
    [pscustomobject]@{
        Timestamp = (Get-Date).ToString('s')
        Test      = $TestName
        Target    = $Target
        Passed    = $Passed
        Detail    = $Detail
    }
}

# Escape simples para HTML (evita quebrar a página com caracteres especiais)
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
    $results.Add( (New-Result 'TCP Port' "$($TargetServer):135" $t135.TcpTestSucceeded ("Latency(ms)={0}" -f $lat)) )
} catch { $results.Add( (New-Result 'TCP Port' "$($TargetServer):135" $false $_.Exception.Message) ) }

# Porta dinâmica (amostra – pode falhar sem indicar problema real)
$highPort = 49152
try {
    $thigh = Test-NetConnection -ComputerName $TargetServer -Port $highPort -WarningAction SilentlyContinue
    $lat2  = if ($thigh.PingSucceeded) { $thigh.PingReplyDetails.RoundtripTime } else { $null }
    $results.Add( (New-Result 'TCP Port (dynamic sample)' "$($TargetServer):$highPort" $thigh.TcpTestSucceeded ("Latency(ms)={0}" -f $lat2)) )
} catch { $results.Add( (New-Result 'TCP Port (dynamic sample)' "$($TargetServer):$highPort" $false $_.Exception.Message) ) }

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
    $results.Add( (New-Result 'Firewall Rules Summary' $env:COMPUTERNAME ($fwRules.Count -gt 0) ("EnabledRules={0}" -f $fwRules.Count)) )
    foreach ($r in $fwRules) {
        $results.Add( (New-Result 'Firewall Rule' $r.DisplayName $true ("Group={0}; Direction={1}; Action={2}" -f $r.DisplayGroup,$r.Direction,$r.Action)) )
    }
} catch {
    $results.Add( (New-Result 'Firewall Rules Summary' $env:COMPUTERNAME $false $_.Exception.Message) )
}

# ============= 3) Serviços essenciais =============
try {
    Get-Service RpcSs,EventLog | ForEach-Object {
        $results.Add( (New-Result 'Service' $_.Name ($_.Status -eq 'Running') ("Status={0}; StartType={1}" -f $_.Status,$_.StartType)) )
    }
} catch {
    $results.Add( (New-Result 'Service' 'RpcSs/EventLog' $false $_.Exception.Message) )
}

# ============= 4) Leitura remota de eventos =============
function Test-RemoteLog {
    param([string]$Computer,[string]$LogName,[int]$Max=3)
    try {
        $null = Get-WinEvent -ComputerName $Computer -ListLog $LogName -ErrorAction Stop
        $ev = Get-WinEvent -ComputerName $Computer -LogName $LogName -MaxEvents $Max -ErrorAction Stop
        $results.Add( (New-Result "Remote Event Read ($LogName)" $Computer $true ("Count={0}" -f ($ev | Measure-Object).Count)) )
    }
    catch {
        $results.Add( (New-Result "Remote Event Read ($LogName)" $Computer $false $_.Exception.Message) )
    }
}
Test-RemoteLog -Computer $TargetServer -LogName 'System'
Test-RemoteLog -Computer $TargetServer -LogName 'Application'
Test-RemoteLog -Computer $TargetServer -LogName 'DFS Replication'   # pode não existir em todos

# ============= 5) WMI/CIM remoto (prova de RPC/DCOM) =============
try {
    $os = Get-CimInstance -ClassName Win32_OperatingSystem -ComputerName $TargetServer -ErrorAction Stop
    $results.Add( (New-Result 'CIM Win32_OperatingSystem' $TargetServer $true ("Caption={0}; Version={1}" -f $os.Caption,$os.Version)) )
} catch {
    $results.Add( (New-Result 'CIM Win32_OperatingSystem' $TargetServer $false $_.Exception.Message) )
}

# ============= 6) Invoke-Command + wevtutil (fallback automático) =============
try {
    # Mais universal
    $ic = Invoke-Command -ComputerName $TargetServer -ScriptBlock { wevtutil qe System /c:3 /f:text } -ErrorAction Stop
    $ok = ($ic -is [array]) -or ($ic -is [string]) -and ($ic.Length -gt 0)
    $snippet = ($ic | Select-Object -First 1)
    $results.Add( (New-Result 'Invoke-Command wevtutil' $TargetServer $ok ("FirstLine={0}" -f $snippet)) )
}
catch {
    # Fallback para XML
    try {
        $ic2 = Invoke-Command -ComputerName $TargetServer -ScriptBlock { wevtutil qe System /c:3 /f:xml } -ErrorAction Stop
        $ok2 = ($ic2 -is [array]) -or ($ic2 -is [string]) -and ($ic2.Length -gt 0)
        $snippet2 = ($ic2 | Select-Object -First 1)
        $results.Add( (New-Result 'Invoke-Command wevtutil (xml)' $TargetServer $ok2 ("FirstLine={0}" -f $snippet2)) )
    }
    catch {
        $results.Add( (New-Result 'Invoke-Command wevtutil' $TargetServer $false $_.Exception.Message) )
    }
}

# ============= 7) PortQry (opcional) – mapeia EPM 135 =============
# Procura portqry no PATH ou em locais comuns
$portqry = $null
try {
    $cmd = Get-Command portqry.exe -ErrorAction SilentlyContinue
    if ($cmd) { $portqry = $cmd.Source }
    elseif (Test-Path 'C:\Windows\System32\portqry.exe') { $portqry = 'C:\Windows\System32\portqry.exe' }
}
catch {}

if ($portqry) {
    try {
        $LASTEXITCODE = $null
        $pqout = & $portqry -n $TargetServer -e 135 -p tcp 2>&1 | Out-String
        # RC: 0=LISTENING, 1=NOT LISTENING, 2=FILTERED
        $pass = ($LASTEXITCODE -eq 0)
        $snippet = ($pqout -split "`r?`n" | Select-Object -First 3) -join ' | '
        $results.Add( (New-Result 'PortQry EPM 135' $TargetServer $pass ("RC=$LASTEXITCODE; $snippet")) )
    }
    catch {
        $results.Add( (New-Result 'PortQry EPM 135' $TargetServer $false $_.Exception.Message) )
    }
}
else {
    $results.Add( (New-Result 'PortQry EPM 135' $TargetServer $false 'portqry.exe não encontrado – teste ignorado. Instale o PortQry (opcional) e reexecute para mapear endpoints RPC do EPM 135.') )
}

# ============= 8) dcdiag (SystemLog/DFSREvent/KccEvent) =============
$dcdiagTests = @('systemlog','dfsrevent','kccevent')
foreach ($t in $dcdiagTests) {
    try {
        $LASTEXITCODE = $null
        $out = & dcdiag /test:$t /s:$TargetServer 2>&1 | Out-String
        $pass = ($LASTEXITCODE -eq 0) -and ($out -notmatch '0x6ba') -and ($out -notmatch 'RPC (?:server|servidor) (?:is )?unavailable|RPC.*indispon[ií]vel')
        $snippet = ($out -split "`r?`n" | Select-Object -First 3) -join ' | '
        $results.Add( (New-Result ("dcdiag:{0}" -f $t) $TargetServer $pass $snippet) )
    }
    catch {
        $results.Add( (New-Result ("dcdiag:{0}" -f $t) $TargetServer $false $_.Exception.Message) )
    }
}

# ============= Exportar CSV =============
$results | Export-Csv -Path $outCsv -NoTypeInformation -Encoding UTF8

# ============= Gerar HTML (resumo + tabela + falhas detalhadas) =============
$passCount = ($results | Where-Object {$_.Passed}).Count
$failItems =  $results | Where-Object {$_.Passed -eq $false}
$failCount = $failItems.Count
$total     = $results.Count

# Heurísticas de dica para falhas comuns
function Get-Advice {
    param([string]$Test,[string]$Target,[string]$Detail)

    $t = $Test.ToLower()
    $d = ($Detail | Out-String).ToLower()

    if ($t -like 'tcp port*' -and $Target -match ':\d+$' -and $Target -match ':4915\d|:49\d{3,}') {
        return 'Teste de porta dinâmica por amostragem. Falha aqui não indica problema real: portas RPC são alocadas sob demanda. Valide a funcionalidade (Get-WinEvent remoto, dcdiag), que já está coberta.'
    }
    if ($t -like 'invoke-command wevtutil*' -and ($d -match 'valor inv[aá]lido|invalid value')) {
        return 'Use o formato /f:text (mais universal). O script já faz fallback para /f:xml quando necessário.'
    }
    if ($t -eq 'portqry epm 135' -and ($d -match 'n[oã]o encontrado|not found|teste ignorado')) {
        return 'Instale o PortQry (portqry.exe) para mapear os endpoints registrados no EPM (porta 135). É opcional, mas útil para troubleshooting de RPC.'
    }
    if ($t -like 'remote event read*') {
        return 'Se falhar, verifique Firewall (grupos “Gerenciamento remoto de log de eventos”/Remote Event Log Management), RPC 135 e portas dinâmicas, além de DNS/ACLs.'
    }
    if ($t -like 'dcdiag:*' -and ($d -match '0x6ba|rpc.*indispon')) {
        return 'Falha típica de consulta remota: libere RPC 135 + portas dinâmicas no Firewall e confirme resolução DNS/ACLs.'
    }
    return 'Verifique Firewall (RPC 135 e portas dinâmicas), DNS e permissões/WinRM conforme o tipo do teste.'
}

# Monta linhas HTML
$rows = foreach ($r in $results) {
    $cls = if ($r.Passed) { 'pass' } else { 'fail' }
    "<tr class='$cls'><td>{0}</td><td>{1}</td><td>{2}</td><td><pre>{3}</pre></td></tr>" -f (Escape-Html $r.Test),(Escape-Html $r.Target),($r.Passed), (Escape-Html $r.Detail)
}

# Seção de falhas detalhadas
$failBlocks = if ($failCount -gt 0) {
    foreach ($f in $failItems) {
        $advice = Get-Advice -Test $f.Test -Target $f.Target -Detail $f.Detail
        @"
<div class='failcard'>
  <div class='ftitle'>$(Escape-Html $f.Test)</div>
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
$portqryNote = if ($results | Where-Object { $_.Test -eq 'PortQry EPM 135' -and $_.Detail -match 'n[oã]o encontrado|not found|teste ignorado' }) {
@"
<div class='note'>
  <b>Nota:</b> O teste PortQry foi ignorado porque o <code>portqry.exe</code> não foi encontrado. 
  Instale o PortQry (opcional) e reexecute para mapear endpoints RPC publicados no EPM (porta 135).
</div>
"@
} else { '' }

# HTML final
$html = @"
<!DOCTYPE html>
<html lang="pt-br">
<head>
<meta charset="utf-8"/>
<title>Validação RPC/Logs – $TargetServer ($timestamp)</title>
<style>
  body { font-family: Segoe UI, Roboto, Arial, sans-serif; margin: 24px; }
  h1 { margin: 0 0 4px 0; font-size: 22px; }
  .sub { color:#555; margin: 0 0 16px 0; }
  .summary { display:flex; gap:16px; margin: 16px 0 20px 0; }
  .card { padding:12px 16px; border-radius:10px; box-shadow:0 1px 3px rgba(0,0,0,.1); }
  .ok    { background:#e8fff0; border:1px solid #b6f0c9; }
  .bad   { background:#ffecec; border:1px solid #ffb3b3; }
  .all   { background:#eef4ff; border:1px solid #c9d8ff; }
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
  .note { margin-top:12px; padding:10px; border-radius:8px; background:#fff9e6; border:1px solid #ffe08a; }
  .footer { color:#777; font-size:12px; margin-top:24px; }
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

  $portqryNote

  <div class="section">
    <h2>Tabela de Resultados</h2>
    <table>
      <thead><tr><th>Teste</th><th>Alvo</th><th>Passou</th><th>Detalhe</th></tr></thead>
      <tbody>
        $($rows -join "`n")
      </tbody>
    </table>
  </div>

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
