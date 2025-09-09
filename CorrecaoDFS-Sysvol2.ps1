<#
  Fix SYSVOL (DFSR) – Item A v3.1
  - Pré-reparo da 5722 (firewall/serviço) Source/Targets
  - Recria membership/conexão do Target se a 5722 seguir fechada
  - Só então entra no loop do backlog (PT/EN) com progresso
  - Gera CSV + HTML na Desktop
  Criado por Eduardo Popovici
#>

$ErrorActionPreference = 'Stop'

# ===== Parâmetros =====
$SourceDC        = 'SRV-AD-02'
$Targets         = @('SRV-AD-01')          # adicione 'FIX-DC00' se desejar
$RGName          = 'Domain System Volume'
$RFFolder        = 'SYSVOL Share'
$TimeoutMinutes  = 25

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

# ===== Funções infra =====
function Enable-DFSR-Port {
  param([string]$ComputerName)
  Invoke-Command -ComputerName $ComputerName -ScriptBlock {
    $ErrorActionPreference = 'Stop'
    # PT/EN
    $grp = Get-NetFirewallRule -DisplayGroup 'DFS Replication','Replicação do DFS' -ErrorAction SilentlyContinue
    if ($grp) { $grp | Enable-NetFirewallRule | Out-Null }
    # Regra explícita
    if (-not (Get-NetFirewallRule -DisplayName 'EDU-DFSR-5722-In' -ErrorAction SilentlyContinue)) {
      New-NetFirewallRule -DisplayName 'EDU-DFSR-5722-In' -Direction Inbound -Action Allow -Protocol TCP -LocalPort 5722 -Profile Any | Out-Null
    } else {
      Set-NetFirewallRule -DisplayName 'EDU-DFSR-5722-In' -Enabled True -Action Allow -Profile Any | Out-Null
    }
    # Serviço
    Set-Service DFSR -StartupType Automatic
    if ((Get-Service DFSR).Status -ne 'Running') { Start-Service DFSR }
  }
}

function Is-Listening5722 {
  param([string]$ComputerName)
  $listening = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
    $ErrorActionPreference = 'SilentlyContinue'
    $c = Get-NetTCPConnection -State Listen -LocalPort 5722
    if (-not $c) {
      $n = (netstat -ano | Select-String -Pattern ':\s*5722\s+LISTENING')
      if ($n) { 'NETSTAT' } else { $null }
    } else { 'CIM' }
  }
  return [bool]$listening
}

function Test-5722 {
  param([string]$From,[string]$To)
  Invoke-Command -ComputerName $From -ScriptBlock {
    param($To)
    $t = Test-NetConnection -ComputerName $To -Port 5722 -WarningAction SilentlyContinue
    [pscustomobject]@{ From=$env:COMPUTERNAME; To=$To; Tcp=$t.TcpTestSucceeded; Ping=$t.PingSucceeded }
  } -ArgumentList $To
}

function Invoke-Native {
  param([string]$File, [string]$Args)
  $psi = New-Object System.Diagnostics.ProcessStartInfo
  $psi.FileName = $File; $psi.Arguments = $Args
  $psi.RedirectStandardOutput = $true; $psi.RedirectStandardError  = $true
  $psi.UseShellExecute = $false; $psi.CreateNoWindow = $true
  $p = [System.Diagnostics.Process]::Start($psi)
  $out = $p.StandardOutput.ReadToEnd(); $err = $p.StandardError.ReadToEnd()
  $p.WaitForExit()
  [pscustomobject]@{ ExitCode=$p.ExitCode; StdOut=$out; StdErr=$err; Command="$File $Args" }
}

function Recreate-Membership {
  param([string]$Source,[string]$Target,[string]$RGName,[string]$RFFolder)
  if (-not (Get-Command dfsradmin -ErrorAction SilentlyContinue)) {
    throw "dfsradmin não encontrado. Instale as DFS Management Tools (RSAT)."
  }
  $ns = 'root\microsoftdfs'
  $memFilter  = "ReplicationGroupName='$RGName' AND ReplicatedFolderName='$RFFolder' AND MemberName='$Target'"
  $connFilter = "ReplicationGroupName='$RGName' AND SendingMemberName='$Source' AND ReceivingMemberName='$Target'"
  $mem = Get-WmiObject -Namespace $ns -Class DfsrReplicatedFolderInfo -Filter $memFilter -ErrorAction SilentlyContinue
  $con = Get-WmiObject -Namespace $ns -Class DfsrConnectionInfo        -Filter $connFilter -ErrorAction SilentlyContinue

  if ($mem) {
    Invoke-Native dfsradmin ("membership delete /rgname:`"$RGName`" /rfname:`"$RFFolder`" /memname:`"$Target`" /force") | Out-Null
  }
  if ($con) {
    Invoke-Native dfsradmin ("conn delete /rgname:`"$RGName`" /sourcecomputer:`"$Source`" /destinationcomputer:`"$Target`" /force") | Out-Null
  }
  Invoke-Native dfsradmin ("membership new /rgname:`"$RGName`" /rfname:`"$RFFolder`" /memname:`"$Target`" /localpath:`"C:\Windows\SYSVOL\domain`" /enabled:true /primary:false") | Out-Null
  Invoke-Native dfsradmin ("conn new /rgname:`"$RGName`" /sourcecomputer:`"$Source`" /destinationcomputer:`"$Target`" /enabled:true") | Out-Null
  Invoke-Command -ComputerName $Target -ScriptBlock { dfsrdiag PollAD; Restart-Service DFSR -Force }
}

function Get-BacklogText {
  param([string]$Source,[string]$Dst,[string]$RGName,[string]$RFFolder)
  Invoke-Command -ComputerName $Source -ScriptBlock {
    param($RGName,$RFFolder,$Src,$Dst)
    dfsrdiag backlog /rgname:$RGName /rfname:$RFFolder /sendingmember:$Src /receivingmember:$Dst
  } -ArgumentList $RGName,$RFFolder,$Source,$Dst | Out-String
}

function Parse-BacklogCount {
  param([string]$Text)
  if ([string]::IsNullOrWhiteSpace($Text)) { return $null }
  $rx = [regex]'(?im)(Backlog\s*(File\s*)?Count|Contagem.*?arquivos).*?:\s*(\d+)'
  $m = $rx.Match($Text)
  if ($m.Success) { return [int]$m.Groups[3].Value }
  if ($Text -match '(?i)\bno backlog\b|\bsem backlog\b|\bnenhum(a)? pend') { return 0 }
  return $null
}

# ===== Pré: 5722/serviço no Source =====
try { Test-WsMan -ComputerName $SourceDC -ErrorAction Stop | Out-Null } catch { throw ("WinRM indisponível em {0}: {1}" -f $SourceDC, $_.Exception.Message) }
Enable-DFSR-Port -ComputerName $SourceDC

foreach ($t in $Targets) {

  # 0) Pré no Target
  try { Test-WsMan -ComputerName $t -ErrorAction Stop | Out-Null; Add-Ok $t '0' 'WinRM no Target' 'OK' }
  catch { Add-Ko $t '0' 'WinRM no Target' $_.Exception.Message; continue }

  Enable-DFSR-Port -ComputerName $t
  Invoke-Command -ComputerName $t { dfsrdiag PollAD; Restart-Service DFSR -Force }

  # 0.1) Verificações 5722 + testes cruzados
  $srcListen = Is-Listening5722 -ComputerName $SourceDC
  $dstListen = Is-Listening5722 -ComputerName $t
  Add-Ok $t '0.1' 'LISTEN Source/Target' ("{0}:{1} | {2}:{3}" -f $SourceDC,$srcListen,$t,$dstListen)

  $r1 = Test-5722 -From $SourceDC -To $t
  $r2 = Test-5722 -From $t        -To $SourceDC
  Add-Ok $t '0.2' 'Test-NetConnection 5722' (($r1,$r2 | Format-Table -AutoSize | Out-String))

  # 0.2) Se o Target ainda não escuta, recriar membership/conexão e revalidar
  if (-not $dstListen) {
    Add-Ko $t '0.3' 'Target não escuta 5722 — recriando membership/conexão' ''
    Recreate-Membership -Source $SourceDC -Target $t -RGName $RGName -RFFolder $RFFolder
    Start-Sleep 5
    $dstListen = Is-Listening5722 -ComputerName $t
    if ($dstListen) { Add-Ok $t '0.4' '5722 LISTENING após recriar' 'OK' } else { Add-Ko $t '0.4' '5722 ainda não LISTENING após recriar' 'Verifique eventos 4012/9061/2213 no destino' }
  }

  # 1) ResumeReplication + PollAD + Restart (garantia extra)
  try {
    Invoke-Command -ComputerName $t -ScriptBlock {
      $ns='root\microsoftdfs'
      $rf=Get-WmiObject -Namespace $ns -Class DfsrReplicatedFolderConfig -Filter ("ReplicatedFolderName='SYSVOL Share'")
      foreach ($r in $rf){ Invoke-WmiMethod -InputObject $r -Name ResumeReplication | Out-Null }
      $vol=Get-WmiObject -Namespace $ns -Class DfsrVolumeConfig
      foreach ($v in $vol){ Invoke-WmiMethod -InputObject $v -Name ResumeReplication | Out-Null }
      dfsrdiag PollAD | Out-Null
      Restart-Service DFSR -Force
    }
    Add-Ok $t '1' 'ResumeReplication + Restart DFSR' 'OK'
  } catch {
    Add-Ko $t '1' 'ResumeReplication + Restart DFSR' $_.Exception.Message
  }

  # 2) SyncNow (do Source)
  try {
    Invoke-Command -ComputerName $SourceDC { dfsrdiag SyncNow /RGName:"Domain System Volume" /Time:2 /Verbose | Out-Null }
    Add-Ok $t '2' 'dfsrdiag SyncNow' 'OK'
  } catch {
    Add-Ko $t '2' 'dfsrdiag SyncNow' $_.Exception.Message
  }

  # 3) Aguardar backlog = 0
  $deadline = (Get-Date).AddMinutes($TimeoutMinutes)
  $lastTxt = ''; $ok=$false
  while ((Get-Date) -lt $deadline) {
    try {
      $txt = Get-BacklogText -Source $SourceDC -Dst $t -RGName $RGName -RFFolder $RFFolder
      $lastTxt = $txt
      $cnt = Parse-BacklogCount -Text $txt
      $minsLeft = [int]([Math]::Ceiling(($deadline - (Get-Date)).TotalMinutes))
      if ($null -ne $cnt) {
        Write-Host ("[{0} → {1}] Backlog={2} (restam ~{3} min)" -f $SourceDC,$t,$cnt,$minsLeft)
        if ($cnt -le 0) { $ok=$true; break }
      } else {
        Write-Host ("[{0} → {1}] Backlog=indeterminado (restam ~{2} min)" -f $SourceDC,$t,$minsLeft)
      }
    } catch { $lastTxt = $_.Exception.Message }
    Start-Sleep -Seconds 10
  }
  if ($ok) { Add-Ok $t '3' 'Aguardar backlog=0' ($lastTxt -split "`r?`n" | Select-Object -First 8 | Out-String) }
  else     { Add-Ko $t '3' ('Aguardar backlog=0 (timeout {0} min)' -f $TimeoutMinutes) ($lastTxt -split "`r?`n" | Select-Object -First 12 | Out-String) }

  # 4) SYSVOL/NETLOGON e Advertising
  try {
    $shares = Invoke-Command -ComputerName $t -ScriptBlock { net share | findstr /I "SYSVOL NETLOGON" } | Out-String
    $pass = ($shares -match 'SYSVOL') -and ($shares -match 'NETLOGON')
    if ($pass) { Add-Ok $t '4' 'Shares SYSVOL/NETLOGON' $shares } else { Add-Ko $t '4' 'Shares SYSVOL/NETLOGON' $shares }
  } catch { Add-Ko $t '4' 'Shares SYSVOL/NETLOGON' $_.Exception.Message }

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
<title>Fix SYSVOL – Item A v3.1 (via $SourceDC) – $ts</title>
<style>
  :root { color-scheme: light dark; }
  body { font-family: Segoe UI, Roboto, Arial, sans-serif; margin:24px; }
  h1 { margin:0 0 4px 0; font-size:22px; }
  .sub { color:#555; margin:0 0 16px 0; }
  table { width:100%; border-collapse:collapse; }
  th,td { border-bottom:1px solid #eee; padding:8px 10px; vertical-align:top; }
  th { text-align:left; background:#fafafa; }
  tr.pass td { background:#f7fff9; }
  tr.fail td { background:#fff7f7; }
  pre { margin:0; white-space:pre-wrap; word-wrap:break-word; }
  @media (prefers-color-scheme: dark) {
    body { color:#eee; background:#121212; }
    th { background:#1b1b1b; }
    th,td { border-bottom:1px solid #2a2a2a; }
    tr.pass td { background:#0e2216; }
    tr.fail td { background:#2a1515; }
  }
</style>
</head>
<body>
  <h1>Fix SYSVOL (DFSR) – via $(Escape-Html $SourceDC)</h1>
  <div class='sub'>Geração: $ts — Alvos: $(Escape-Html ($Targets -join ', ')) — Total: $total (PASS: $pass, FAIL: $fail)</div>
  $($targetsHtml -join "`n")
</body>
</html>
"@
$html | Out-File -FilePath $outHtml -Encoding UTF8
$log  | Export-Csv -Path $outCsv -NoTypeInformation -Encoding UTF8

Write-Host "Relatórios salvos:"
Write-Host " - CSV : $outCsv"
Write-Host " - HTML: $outHtml"
