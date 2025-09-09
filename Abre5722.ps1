<#
  Fix DFSR 5722 + Sync SYSVOL (end-to-end) — v2
  Criado por Eduardo Popovici

  O que faz:
   1) Abre 5722/TCP nos dois DCs + garante DFSR iniciado
   2) Verifica LISTENING local (Get-NetTCPConnection | netstat)
   3) Testa conectividade 5722 em ambos os sentidos
   4) Se necessário, RECRIA membership/conexão do SYSVOL no destino (idempotente, sem falhar se já não existir)
   5) dfsrdiag SyncNow no Source e espera backlog chegar a 0 (PT/EN)

  Uso:
    .\Fix-DFSR-5722-and-Sync_v2.ps1 -SourceDC 'SRV-AD-02' -TargetDC 'SRV-AD-01' -TimeoutMinutes 25
#>

param(
  [string]$SourceDC  = 'SRV-AD-02',
  [string]$TargetDC  = 'SRV-AD-01',
  [int]   $TimeoutMinutes = 25
)

$ErrorActionPreference = 'Stop'
$rg = 'Domain System Volume'
$rf = 'SYSVOL Share'

# ---- helpers ----
function Invoke-Native {
  param([string]$File, [string]$Args)
  $psi = New-Object System.Diagnostics.ProcessStartInfo
  $psi.FileName = $File
  $psi.Arguments = $Args
  $psi.RedirectStandardOutput = $true
  $psi.RedirectStandardError  = $true
  $psi.UseShellExecute        = $false
  $psi.CreateNoWindow         = $true
  $p = [System.Diagnostics.Process]::Start($psi)
  $out = $p.StandardOutput.ReadToEnd()
  $err = $p.StandardError.ReadToEnd()
  $p.WaitForExit()
  [pscustomobject]@{ ExitCode=$p.ExitCode; StdOut=$out; StdErr=$err; Command="$File $Args" }
}

function Enable-DFSR-Port {
  param([string]$ComputerName)
  Invoke-Command -ComputerName $ComputerName -ScriptBlock {
    $ErrorActionPreference = 'Stop'
    $grp = Get-NetFirewallRule -DisplayGroup 'DFS Replication' -ErrorAction SilentlyContinue
    if ($grp) { $grp | Enable-NetFirewallRule | Out-Null }
    if (-not (Get-NetFirewallRule -DisplayName 'EDU-DFSR-5722-In' -ErrorAction SilentlyContinue)) {
      New-NetFirewallRule -DisplayName 'EDU-DFSR-5722-In' -Direction Inbound -Action Allow -Protocol TCP -LocalPort 5722 -Profile Any | Out-Null
    } else {
      Set-NetFirewallRule -DisplayName 'EDU-DFSR-5722-In' -Enabled True -Action Allow -Profile Any | Out-Null
    }
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

function Recreate-Membership {
  param([string]$Source,[string]$Target)

  # 0) pré-cheques
  if (-not (Get-Command dfsradmin -ErrorAction SilentlyContinue)) {
    throw "dfsradmin não encontrado. Instale as DFS Management Tools (RSAT)."
  }

  # 1) verificar existência via WMI (evita erro ao deletar algo que não existe)
  $ns = 'root\microsoftdfs'
  $memFilter  = "ReplicationGroupName='$rg' AND ReplicatedFolderName='$rf' AND MemberName='$Target'"
  $connFilter = "ReplicationGroupName='$rg' AND SendingMemberName='$Source' AND ReceivingMemberName='$Target'"

  $mem = Get-WmiObject -Namespace $ns -Class DfsrReplicatedFolderInfo -Filter $memFilter -ErrorAction SilentlyContinue
  $con = Get-WmiObject -Namespace $ns -Class DfsrConnectionInfo        -Filter $connFilter -ErrorAction SilentlyContinue

  # 2) deletar se existirem (capturando ExitCode)
  if ($mem) {
    Write-Host ("Removendo membership do {0}..." -f $Target) -ForegroundColor Yellow
    $r = Invoke-Native dfsradmin ("membership delete /rgname:`"$rg`" /rfname:`"$rf`" /memname:`"$Target`" /force")
    if ($r.ExitCode -ne 0) { Write-Warning ("membership delete retornou {0}: {1}" -f $r.ExitCode, ($r.StdErr.Trim() -replace '\s+',' ')) }
  } else {
    Write-Host ("Membership de {0} não existe — ok" -f $Target)
  }

  if ($con) {
    Write-Host ("Removendo conexão {0} -> {1}..." -f $Source,$Target) -ForegroundColor Yellow
    $r = Invoke-Native dfsradmin ("conn delete /rgname:`"$rg`" /sourcecomputer:`"$Source`" /destinationcomputer:`"$Target`" /force")
    if ($r.ExitCode -ne 0) { Write-Warning ("conn delete retornou {0}: {1}" -f $r.ExitCode, ($r.StdErr.Trim() -replace '\s+',' ')) }
  } else {
    Write-Host ("Conexão {0} -> {1} não existe — ok" -f $Source,$Target)
  }

  # 3) recriar (sempre)
  Write-Host ("Criando membership de {0}..." -f $Target) -ForegroundColor Green
  $r = Invoke-Native dfsradmin ("membership new /rgname:`"$rg`" /rfname:`"$rf`" /memname:`"$Target`" /localpath:`"C:\Windows\SYSVOL\domain`" /enabled:true /primary:false")
  if ($r.ExitCode -ne 0) { Write-Warning ("membership new retornou {0}: {1}" -f $r.ExitCode, ($r.StdErr.Trim() -replace '\s+',' ')) }

  Write-Host ("Criando conexão {0} -> {1}..." -f $Source,$Target) -ForegroundColor Green
  $r = Invoke-Native dfsradmin ("conn new /rgname:`"$rg`" /sourcecomputer:`"$Source`" /destinationcomputer:`"$Target`" /enabled:true")
  if ($r.ExitCode -ne 0) { Write-Warning ("conn new retornou {0}: {1}" -f $r.ExitCode, ($r.StdErr.Trim() -replace '\s+',' ')) }

  # 4) forçar leitura do AD e reiniciar DFSR no destino
  Invoke-Command -ComputerName $Target -ScriptBlock { dfsrdiag PollAD; Restart-Service DFSR -Force }
}

function Get-BacklogText {
  param([string]$Source,[string]$Dst)
  Invoke-Command -ComputerName $Source -ScriptBlock {
    param($RGName,$RFFolder,$Src,$Dst)
    dfsrdiag backlog /rgname:$RGName /rfname:$RFFolder /sendingmember:$Src /receivingmember:$Dst
  } -ArgumentList $rg,$rf,$Source,$Dst | Out-String
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

# ==== 1) Abrir porta e iniciar DFSR nos dois ====
Enable-DFSR-Port -ComputerName $SourceDC
Enable-DFSR-Port -ComputerName $TargetDC

# ==== 2) Verificar LISTENING em ambos ====
$srcListen = Is-Listening5722 -ComputerName $SourceDC
$dstListen = Is-Listening5722 -ComputerName $TargetDC
Write-Host ("[{0}] 5722 LISTENING = {1}" -f $SourceDC,$srcListen)
Write-Host ("[{0}] 5722 LISTENING = {1}" -f $TargetDC,$dstListen)

# ==== 3) Testes cruzados ====
$r1 = Test-5722 -From $SourceDC -To $TargetDC
$r2 = Test-5722 -From $TargetDC -To $SourceDC
$r1, $r2 | Format-Table -AutoSize

# ==== 4) Se destino ainda não escuta, recriar membership/conexão ====
if (-not $dstListen) {
  Recreate-Membership -Source $SourceDC -Target $TargetDC
  Start-Sleep 5
  $dstListen = Is-Listening5722 -ComputerName $TargetDC
  Write-Host ("[{0}] 5722 LISTENING (após recriar) = {1}" -f $TargetDC,$dstListen)
}

# ==== 5) Disparar SyncNow e aguardar backlog ====
Invoke-Command -ComputerName $SourceDC { dfsrdiag SyncNow /RGName:"Domain System Volume" /Time:2 /Verbose | Out-Null }

$deadline = (Get-Date).AddMinutes($TimeoutMinutes)
while ((Get-Date) -lt $deadline) {
  $txt = Get-BacklogText -Source $SourceDC -Dst $TargetDC
  $cnt = Parse-BacklogCount -Text $txt
  $minsLeft = [int]([Math]::Ceiling(($deadline - (Get-Date)).TotalMinutes))
  if ($null -ne $cnt) {
    Write-Host ("[{0} → {1}] Backlog={2} (restam ~{3} min)" -f $SourceDC,$TargetDC,$cnt,$minsLeft)
    if ($cnt -le 0) { break }
  } else {
    Write-Host ("[{0} → {1}] Backlog=indeterminado (restam ~{2} min)" -f $SourceDC,$TargetDC,$minsLeft)
  }
  Start-Sleep -Seconds 10
}

Write-Host "Fim. Se o backlog não caiu, confira eventos 4012/9061 e a agenda/enable da conexão DFSR $SourceDC -> $TargetDC."
