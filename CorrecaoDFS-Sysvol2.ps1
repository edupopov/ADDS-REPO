<#
  Fix SYSVOL (DFSR) – Item A – Fechar sincronização inicial
  Criado por Eduardo Popovici

  Como usar:
    - Execute em um host com RSAT (PowerShell elevado, conta com permissão de Admin do Domínio).
    - O script atua remotamente em cada DC listado em $Targets (não precisa rodar em cada servidor).
#>

$ErrorActionPreference = 'Stop'

# ===== Parâmetros do ambiente =====
$SourceDC        = 'SRV-AD-02'                      # DC saudável (fonte/hub)
$Targets         = @('SRV-AD-01','FIX-DC00')        # DCs que precisam concluir a sync
$RGName          = 'Domain System Volume'
$RFFolder        = 'SYSVOL Share'
$TimeoutMinutes  = 20                                # tempo máximo para aguardar backlog chegar a 0

# ===== Saídas =====
$ts       = Get-Date -Format 'yyyyMMdd-HHmmss'
$desktop  = Join-Path $env:USERPROFILE 'Desktop'
$outCsv   = Join-Path $desktop ("Fix_SYSVOL_ItemA_{0}_via_{1}.csv"  -f ($Targets -join '+'),$SourceDC)
$outHtml  = Join-Path $desktop ("Fix_SYSVOL_ItemA_{0}_via_{1}_{2}.html" -f ($Targets -join '+'),$SourceDC,$ts)

# ===== Helpers =====
function New-Row {
  param([string]$Target,[string]$Step,[string]$Action,[bool]$Passed,[string]$Detail='')
  [pscustomobject]@{
    Timestamp = (Get-Date).ToString('s')
    Target    = $Target
    Step      = $Step
    Action    = $Action
    Passed    = $Passed
    Detail    = $Detail
  }
}
$log = [System.Collections.Generic.List[object]]::new()

function Add-Ok { param($T,$S,$A,$D='') $log.Add( (New-Row $T,$S,$A,$true,$D) ) }
function Add-Ko { param($T,$S,$A,$D='') $log.Add( (New-Row $T,$S,$A,$false,$D) ) }

function Escape-Html {
  param([string]$Text)
  if ($null -eq $Text) { return '' }
  $t = $Text -replace '&','&amp;' -replace '<','&lt;' -replace '>','&gt;' -replace '"','&quot;' -replace "'",'&#39;'
  return $t
}

# ===== Funções remotas (rodam dentro de cada Target) =====
$remoteScript = {
  param($RGName,$RFFolder)

  $ErrorActionPreference = 'Stop'
  $ns = 'root\microsoftdfs'
  $out = New-Object System.Collections.Generic.List[string]

  # 0) Serviços e eventos recentes 9061
  $svc = Get-Service DFSR -ErrorAction Stop
  $out.Add(("DFSR Service: {0} (StartType={1})" -f $svc.Status,$svc.StartType))

  $ev9061 = @()
  try {
    $ev9061 = Get-WinEvent -FilterHashtable @{LogName='DFS Replication'; Id=9061; StartTime=(Get-Date).AddDays(-2)} -ErrorAction SilentlyContinue | Select-Object -First 3
    $out.Add(("Eventos 9061 (ultimas 48h): {0}" -f ($ev9061 | Measure-Object).Count))
  } catch { $out.Add("Eventos 9061: erro ao consultar: $_") }

  # 1) ResumeReplication em ReplicatedFolderConfig (SYSVOL Share)
  try {
    $rf = Get-WmiObject -Namespace $ns -Class DfsrReplicatedFolderConfig -Filter ("ReplicatedFolderName='{0}'" -f $RFFolder) -ErrorAction Stop
    foreach ($r in $rf) { Invoke-WmiMethod -InputObject $r -Name ResumeReplication | Out-Null }
    $out.Add("ResumeReplication (DfsrReplicatedFolderConfig) aplicado.")
  } catch { $out.Add("ResumeReplication (ReplicatedFolderConfig) falhou: $($_.Exception.Message)") }

  # 2) ResumeReplication em VolumeConfig (cobre evento 2213/MaxOfflineTime)
  try {
    $vols = Get-WmiObject -Namespace $ns -Class DfsrVolumeConfig -ErrorAction Stop
    foreach ($v in $vols) { Invoke-WmiMethod -InputObject $v -Name ResumeReplication | Out-Null }
    $out.Add("ResumeReplication (DfsrVolumeConfig) aplicado.")
  } catch { $out.Add("ResumeReplication (VolumeConfig) falhou: $($_.Exception.Message)") }

  # 3) PollAD + restart serviço
  try { dfsrdiag PollAD | Out-Null; $out.Add("dfsrdiag PollAD OK.") } catch { $out.Add("dfsrdiag PollAD falhou: $($_.Exception.Message)") }
  try { Restart-Service DFSR -Force -ErrorAction Stop; Start-Sleep -Seconds 5; $out.Add("Restart DFSR OK.") } catch { $out.Add("Restart DFSR falhou: $($_.Exception.Message)") }

  # 4) Retorna texto
  return ($out -join "`n")
}

# ===== Execução por Target =====
foreach ($t in $Targets) {
  # Pré-cheque: WinRM
  try { Test-WsMan -ComputerName $t -ErrorAction Stop | Out-Null; Add-Ok $t '0' 'WinRM reachability' 'OK' }
  catch { Add-Ko $t '0' 'WinRM reachability' $_.Exception.Message; continue }

  # 1) Operações remotas: ResumeReplication + PollAD + Restart
  try {
    $txt = Invoke-Command -ComputerName $t -ScriptBlock $remoteScript -ArgumentList $RGName,$RFFolder
    Add-Ok $t '1' 'ResumeReplication + PollAD + Restart DFSR (remoto)' $txt
  } catch {
    Add-Ko $t '1' 'ResumeReplication + PollAD + Restart DFSR (remoto)' $_.Exception.Message
    continue
  }

  # 2) Disparar SyncNow (feito a partir do SourceDC)
  try {
    $o = Invoke-Command -ComputerName $SourceDC -ScriptBlock {
      dfsrdiag SyncNow /RGName:"Domain System Volume" /Time:2 /Verbose
    } | Out-String
    Add-Ok $t '2' 'dfsrdiag SyncNow (a partir do SourceDC)' $o
  } catch {
    Add-Ko $t '2' 'dfsrdiag SyncNow (a partir do SourceDC)' $_.Exception.Message
  }

  # 3) Acompanhar backlog até 0 (ou timeout)
  $deadline = (Get-Date).AddMinutes($TimeoutMinutes)
  $lastOut  = ''
  $ok = $false
  while ((Get-Date) -lt $deadline) {
    try {
      $s = Invoke-Command -ComputerName $SourceDC -ScriptBlock {
        param($RGName,$RFFolder,$Src,$Dst)
        dfsrdiag backlog /rgname:$RGName /rfname:$RFFolder /sendingmember:$Src /receivingmember:$Dst
      } -ArgumentList $RGName,$RFFolder,$SourceDC,$t | Out-String
      $lastOut = $s
      # Heurística: procura "No backlog" ou "Backlog File Count: 0"
      if ($s -match '(?i)no backlog|file count\s*:\s*0|backlog.*:\s*0') { $ok = $true; break }
    } catch { $lastOut = $_.Exception.Message }
    Start-Sleep -Seconds 10
  }
  if ($ok) { Add-Ok $t '3' 'Aguardar backlog=0' ($lastOut -split "`r?`n" | Select-Object -First 6 | Out-String) }
  else     { Add-Ko $t '3' ('Aguardar backlog=0 (timeout {0} min)' -f $TimeoutMinutes) ($lastOut -split "`r?`n" | Select-Object -First 8 | Out-String) }

  # 4) Valida SYSVOL/NETLOGON
  try {
    $shares = Invoke-Command -ComputerName $t -ScriptBlock { net share | findstr /I "SYSVOL NETLOGON" } | Out-String
    $pass = ($shares -match 'SYSVOL') -and ($shares -match 'NETLOGON')
    if ($pass) { Add-Ok $t '4' 'Shares SYSVOL/NETLOGON' $shares } else { Add-Ko $t '4' 'Shares SYSVOL/NETLOGON' $shares }
  } catch { Add-Ko $t '4' 'Shares SYSVOL/NETLOGON' $_.Exception.Message }

  # 5) Advertising (rápido)
  try {
    $LASTEXITCODE = $null
    $o = & dcdiag /test:advertising /s:$t 2>&1 | Out-String
    if ($LASTEXITCODE -eq 0) { Add-Ok $t '5' 'dcdiag /test:advertising' $o } else { Add-Ko $t '5' 'dcdiag /test:advertising' ("exitcode=$LASTEXITCODE`n$o") }
  } catch { Add-Ko $t '5' 'dcdiag /test:advertising' $_.Exception.Message }
}

# ===== Exportar CSV =====
$log | Export-Csv -Path $outCsv -NoTypeInformation -Encoding UTF8

# ===== HTML =====
$total = $log.Count
$pass  = ($log | ? Passed).Count
$fail  = ($log | ? { -not $_.Passed }).Count

# tabelas por Target
$targetsHtml = foreach ($t in $Targets) {
  $sub = $log | Where-Object { $_.Target -eq $t }
  if (-not $sub) { continue }
  $rows = foreach ($r in $sub) {
    $cls = if ($r.Passed) {'pass'} else {'fail'}
    "<tr class='$cls'><td>{0}</td><td>{1}</td><td><pre>{2}</pre></td></tr>" -f (Escape-Html $r.Step),(Escape-Html $r.Action),(Escape-Html $r.Detail)
  }
@"
  <div class='section' id='t_$(Escape-Html $t)'>
    <h2>Destino: $(Escape-Html $t)</h2>
    <table>
      <thead><tr><th>Etapa</th><th>Ação</th><th>Detalhe</th></tr></thead>
      <tbody>
        $($rows -join "`n")
      </tbody>
    </table>
  </div>
"@
}

$html = @"
<!DOCTYPE html>
<html lang='pt-br'>
<head>
<meta charset='utf-8'/>
<title>Fix SYSVOL – Item A (via $SourceDC) – $ts</title>
<style>
  :root { color-scheme: light dark; }
  body { font-family: Segoe UI, Roboto, Arial, sans-serif; margin: 24px; }
  h1 { margin: 0 0 4px 0; font-size: 22px; }
  .sub { color:#555; margin: 0 0 16px 0; }
  .summary { display:flex; gap:16px; margin: 16px 0 12px 0; flex-wrap: wrap; }
  .card { padding:12px 16px; border-radius:10px; box-shadow:0 1px 3px rgba(0,0,0,.08); }
  .all { background:#eef4ff; border:1px solid #c9d8ff; }
  .ok  { background:#e8fff0; border:1px solid #b6f0c9; }
  .bad { background:#ffecec; border:1px solid #ffb3b3; }
  table { width:100%; border-collapse: collapse; }
  th, td { border-bottom:1px solid #eee; padding:8px 10px; vertical-align: top; }
  th { text-align:left; background:#fafafa; }
  tr.pass td { background:#f7fff9; }
  tr.fail td { background:#fff7f7; }
  pre { margin:0; white-space: pre-wrap; word-wrap: break-word; }
  .section { margin-top:28px; }
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
  }
</style>
</head>
<body>
  <h1>Fix SYSVOL – Item A (DFSR) – via $(Escape-Html $SourceDC)</h1>
  <div class='sub'>Geração: $ts — Alvos: $(Escape-Html ($Targets -join ', ')) — Total: $total (PASS: $pass, FAIL: $fail)</div>

  <div class='summary'>
    <div class='card all'>Total: <b>$total</b></div>
    <div class='card ok'>Pass: <b>$pass</b></div>
    <div class='card bad'>Fail: <b>$fail</b></div>
  </div>

  $($targetsHtml -join "`n")

  <div class='section'>
    <h2>Observações</h2>
    <ul>
      <li><b>ResumeReplication</b> (WMI) cobre cenários de <i>MaxOfflineTimeInDays</i> (evento 9061) e 2213.</li>
      <li>O backlog é medido do <b>$SourceDC</b> → Destino; quando chegar a <b>0</b>, os shares <code>SYSVOL</code>/<code>NETLOGON</code> tendem a reaparecer.</li>
      <li>Se o backlog não cair até o <i>timeout</i>, verifique o log “DFS Replication” e a conectividade (RPC, DFSR, DNS).</li>
    </ul>
  </div>
</body>
</html>
"@

$html | Out-File -FilePath $outHtml -Encoding UTF8
$log  | Export-Csv -Path $outCsv -NoTypeInformation -Encoding UTF8

Write-Host "Relatórios salvos:"
Write-Host " - CSV : $outCsv"
Write-Host " - HTML: $outHtml"
