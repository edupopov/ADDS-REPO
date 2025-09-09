<#
  Fix SYSVOL (DFSR) – Item A – Fechar sincronização (v3)
  Criado por Eduardo Popovici

  Melhorias:
   - Parsing do backlog PT/EN (Backlog File Count | Contagem ... arquivos).
   - Progresso a cada 10s com contagem regressiva.
   - Execução local quando o alvo = máquina atual (sem remoting).
#>

$ErrorActionPreference = 'Stop'

# ===== Parâmetros =====
$SourceDC        = 'SRV-AD-02'                      # DC saudável (fonte)
$Targets         = @('SRV-AD-01','FIX-DC00')        # DC(s) a corrigir
$RGName          = 'Domain System Volume'
$RFFolder        = 'SYSVOL Share'
$TimeoutMinutes  = 20

# ===== Saídas =====
$ts      = Get-Date -Format 'yyyyMMdd-HHmmss'
$desktop = Join-Path $env:USERPROFILE 'Desktop'
$outCsv  = Join-Path $desktop ("Fix_SYSVOL_ItemA_{0}_via_{1}.csv"  -f ($Targets -join '+'),$SourceDC)
$outHtml = Join-Path $desktop ("Fix_SYSVOL_ItemA_{0}_via_{1}_{2}.html" -f ($Targets -join '+'),$SourceDC,$ts)

# ===== Helpers =====
function New-Row { param([string]$Target,[string]$Step,[string]$Action,[bool]$Passed,[string]$Detail='')
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
function Add-Ok { param($T,$S,$A,$D='') $log.Add( (New-Row $T,$S,$A,$true ,$D) ) }
function Add-Ko { param($T,$S,$A,$D='') $log.Add( (New-Row $T,$S,$A,$false,$D) ) }

function Escape-Html([string]$t){
  if ($null -eq $t) { return '' }
  $t = $t -replace '&','&amp;' -replace '<','&lt;' -replace '>','&gt;' -replace '"','&quot;' -replace "'",'&#39;'
  return $t
}

# Execução local dos passos do alvo
$targetScript = {
  param($RGName,$RFFolder)
  $ErrorActionPreference = 'Stop'
  $ns = 'root\microsoftdfs'
  $out = New-Object System.Collections.Generic.List[string]

  $svc = Get-Service DFSR -ErrorAction Stop
  $out.Add(("DFSR Service: {0} (StartType={1})" -f $svc.Status,$svc.StartType))

  try {
    $ev9061 = Get-WinEvent -FilterHashtable @{LogName='DFS Replication'; Id=9061; StartTime=(Get-Date).AddDays(-2)} -ErrorAction SilentlyContinue
    $out.Add(("Eventos 9061 (48h): {0}" -f (($ev9061 | Measure-Object).Count)))
  } catch { $out.Add("Eventos 9061: erro ao consultar: $($_.Exception.Message)") }

  try {
    $rf = Get-WmiObject -Namespace $ns -Class DfsrReplicatedFolderConfig -Filter ("ReplicatedFolderName='{0}'" -f $RFFolder)
    foreach ($r in $rf) { Invoke-WmiMethod -InputObject $r -Name ResumeReplication | Out-Null }
    $out.Add("ResumeReplication (ReplicatedFolderConfig) OK.")
  } catch { $out.Add("ResumeReplication (ReplicatedFolderConfig) falhou: $($_.Exception.Message)") }

  try {
    $vols = Get-WmiObject -Namespace $ns -Class DfsrVolumeConfig
    foreach ($v in $vols) { Invoke-WmiMethod -InputObject $v -Name ResumeReplication | Out-Null }
    $out.Add("ResumeReplication (VolumeConfig) OK.")
  } catch { $out.Add("ResumeReplication (VolumeConfig) falhou: $($_.Exception.Message)") }

  try { dfsrdiag PollAD | Out-Null; $out.Add("dfsrdiag PollAD OK.") } catch { $out.Add("dfsrdiag PollAD falhou: $($_.Exception.Message)") }
  try { Restart-Service DFSR -Force; Start-Sleep -Seconds 5; $out.Add("Restart DFSR OK.") } catch { $out.Add("Restart DFSR falhou: $($_.Exception.Message)") }

  return ($out -join "`n")
}

# Função: obtém texto do backlog (executado a partir do SourceDC)
function Get-BacklogText {
  param([string]$Dst)
  Invoke-Command -ComputerName $SourceDC -ScriptBlock {
    param($RGName,$RFFolder,$Src,$Dst)
    dfsrdiag backlog /rgname:$RGName /rfname:$RFFolder /sendingmember:$Src /receivingmember:$Dst
  } -ArgumentList $RGName,$RFFolder,$SourceDC,$Dst | Out-String
}

# Função: extrai contagem do backlog (PT/EN) – retorna [int] ou $null
function Parse-BacklogCount {
  param([string]$Text)
  if ([string]::IsNullOrWhiteSpace($Text)) { return $null }
  $rx = [regex]'(?im)(Backlog\s*(File\s*)?Count|Contagem.*?arquivos).*?:\s*(\d+)'
  $m = $rx.Match($Text)
  if ($m.Success) { return [int]$m.Groups[3].Value }
  if ($Text -match '(?i)\bno backlog\b|\bsem backlog\b|\bnenhum(a)? pend') { return 0 }
  return $null
}

foreach ($t in $Targets) {

  # 0) Pré-cheque WinRM para chamadas ao SourceDC (backlog/SyncNow)
  try { Test-WsMan -ComputerName $SourceDC -ErrorAction Stop | Out-Null; Add-Ok $t '0' ("WinRM no Source {0}" -f $SourceDC) 'OK' }
  catch { Add-Ko $t '0' ("WinRM no Source {0}" -f $SourceDC) $_.Exception.Message; continue }

  # 1) ResumeReplication + PollAD + Restart no alvo (local ou remoto)
  try {
    if ($t -ieq $env:COMPUTERNAME) {
      $txt = & $targetScript.Invoke($RGName,$RFFolder)
    } else {
      Test-WsMan -ComputerName $t -ErrorAction Stop | Out-Null
      $txt = Invoke-Command -ComputerName $t -ScriptBlock $targetScript -ArgumentList $RGName,$RFFolder
    }
    Add-Ok $t '1' 'ResumeReplication + PollAD + Restart DFSR' $txt
  } catch {
    Add-Ko $t '1' 'ResumeReplication + PollAD + Restart DFSR' $_.Exception.Message
    continue
  }

  # 2) SyncNow (feito do SourceDC)
  try {
    $o = Invoke-Command -ComputerName $SourceDC -ScriptBlock { dfsrdiag SyncNow /RGName:"Domain System Volume" /Time:2 /Verbose } | Out-String
    Add-Ok $t '2' 'dfsrdiag SyncNow (a partir do SourceDC)' $o
  } catch {
    Add-Ko $t '2' 'dfsrdiag SyncNow (a partir do SourceDC)' $_.Exception.Message
  }

  # 3) Acompanhar backlog até 0 (ou timeout) – com progresso
  $deadline = (Get-Date).AddMinutes($TimeoutMinutes)
  $lastTxt  = ''
  $ok = $false
  while ((Get-Date) -lt $deadline) {
    try {
      $txt = Get-BacklogText -Dst $t
      $lastTxt = $txt
      $cnt = Parse-BacklogCount -Text $txt
      $minsLeft = [int]([Math]::Ceiling(($deadline - (Get-Date)).TotalMinutes))
      if ($null -ne $cnt) {
        Write-Host ("[{0} → {1}] Backlog={2} (restam ~{3} min)" -f $SourceDC,$t,$cnt,$minsLeft)
        if ($cnt -le 0) { $ok = $true; break }
      } else {
        Write-Host ("[{0} → {1}] Backlog=indeterminado (restam ~{2} min)" -f $SourceDC,$t,$minsLeft)
      }
    } catch {
      $lastTxt = $_.Exception.Message
      Write-Host ("[{0} → {1}] Erro ao consultar backlog: {2}" -f $SourceDC,$t,$_.Exception.Message)
    }
    Start-Sleep -Seconds 10
  }

  if ($ok) { Add-Ok $t '3' 'Aguardar backlog=0' ($lastTxt -split "`r?`n" | Select-Object -First 8 | Out-String) }
  else     { Add-Ko $t '3' ('Aguardar backlog=0 (timeout {0} min)' -f $TimeoutMinutes) ($lastTxt -split "`r?`n" | Select-Object -First 12 | Out-String) }

  # 4) Validação SYSVOL/NETLOGON
  try {
    if ($t -ieq $env:COMPUTERNAME) {
      $shares = net share | findstr /I "SYSVOL NETLOGON" | Out-String
    } else {
      $shares = Invoke-Command -ComputerName $t -ScriptBlock { net share | findstr /I "SYSVOL NETLOGON" } | Out-String
    }
    $pass = ($shares -match 'SYSVOL') -and ($shares -match 'NETLOGON')
    if ($pass) { Add-Ok $t '4' 'Shares SYSVOL/NETLOGON' $shares } else { Add-Ko $t '4' 'Shares SYSVOL/NETLOGON' $shares }
  } catch { Add-Ko $t '4' 'Shares SYSVOL/NETLOGON' $_.Exception.Message }

  # 5) Advertising
  try {
    $LASTEXITCODE = $null
    $o = & dcdiag /test:advertising /s:$t 2>&1 | Out-String
    if ($LASTEXITCODE -eq 0) { Add-Ok $t '5' 'dcdiag /test:advertising' $o } else { Add-Ko $t '5' 'dcdiag /test:advertising' ("exitcode=$LASTEXITCODE`n$o") }
  } catch { Add-Ko $t '5' 'dcdiag /test:advertising' $_.Exception.Message }
}

# ===== Exportar =====
$log | Export-Csv -Path $outCsv -NoTypeInformation -Encoding UTF8

# ===== HTML =====
$total = $log.Count
$pass  = ($log | ? Passed).Count
$fail  = $total - $pass

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
<title>Fix SYSVOL – Item A v3 (via $SourceDC) – $ts</title>
<style>
  :root { color-scheme: light dark; }
  body { font-family: Segoe UI, Roboto, Arial, sans-serif; margin:24px; }
  h1 { margin:0 0 4px 0; font-size:22px; }
  .sub { color:#555; margin:0 0 16px 0; }
  .summary { display:flex; gap:16px; margin: 16px 0 12px 0; flex-wrap: wrap; }
  .card { padding:12px 16px; border-radius:10px; box-shadow:0 1px 3px rgba(0,0,0,.08); }
  .all { background:#eef4ff; border:1px solid #c9d8ff; }
  .ok  { background:#e8fff0; border:1px solid #b6f0c9; }
  .bad { background:#ffecec; border:1px solid #ffb3b3; }
  table { width:100%; border-collapse:collapse; }
  th,td { border-bottom:1px solid #eee; padding:8px 10px; vertical-align:top; }
  th { text-align:left; background:#fafafa; }
  tr.pass td { background:#f7fff9; }
  tr.fail td { background:#fff7f7; }
  pre { margin:0; white-space:pre-wrap; word-wrap:break-word; }
  .section { margin-top:28px; }
  @media (prefers-color-scheme: dark) {
    body { color:#eee; background:#121212; }
    .sub { color:#bbb; }
    .card { box-shadow:none; }
    .all { background:#1b2744; border-color:#30487c; }
    .ok  { background:#14301d; border-color:#1f7a46; }
    .bad { background:#3a1b1b; border-color:#7a2e2e; }
    th { background:#1b1b1b; }
    th,td { border-bottom:1px solid #2a2a2a; }
    tr.pass td { background:#0e2216; }
    tr.fail td { background:#2a1515; }
  }
</style>
</head>
<body>
  <h1>Fix SYSVOL (DFSR) – Item A v3 – via $(Escape-Html $SourceDC)</h1>
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
      <li>Se persistirem eventos <b>4012/9061</b> e o backlog não iniciar, remova e recrie o <i>membership</i> do alvo no RG "<code>$RGName</code>" para forçar uma nova sincronização inicial.</li>
      <li>Após backlog = 0, verifique os compartilhamentos <code>SYSVOL</code>/<code>NETLOGON</code> e o teste <code>dcdiag /test:advertising</code>.</li>
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
