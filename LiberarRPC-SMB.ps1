<#
  Item B – Liberar RPC/SMB para o DCDiag ler logs remotos
  Criado por Eduardo Popovici

  O que este script faz:
   - Cria/ativa regras de firewall no ALVO (TCP 135, 139, 445 e 49152–65535).
   - Tenta habilitar o grupo nativo "Remote Event Log Management" (nomes PT/EN).
   - Garante os serviços RpcSs, EventLog e RemoteRegistry (Automático + Iniciado).
   - Habilita WinRM/PSRemoting (útil para os demais scripts remotos).
   - Valida, a partir de $TestFrom, portas 135/445 e um Get-WinEvent remoto.
   - Gera CSV + HTML na Área de Trabalho do usuário atual.

  Uso:
    .\Enable-RPC-SMB.ps1 -Target 'SRV-AD-01' -TestFrom 'SRV-AD-02'
#>

param(
  [string]$Target   = 'SRV-AD-01',
  [string]$TestFrom = 'SRV-AD-02'
)

$ErrorActionPreference = 'Stop'

# ===== Saídas =====
$ts      = Get-Date -Format 'yyyyMMdd-HHmmss'
$desktop = Join-Path $env:USERPROFILE 'Desktop'
$outCsv  = Join-Path $desktop ("Enable_RPC_SMB_{0}_{1}.csv"  -f $Target,$ts)
$outHtml = Join-Path $desktop ("Enable_RPC_SMB_{0}_{1}.html" -f $Target,$ts)

# ===== Helpers =====
function New-Row { param([string]$Step,[string]$Action,[bool]$Passed,[string]$Detail='')
  [pscustomobject]@{
    Timestamp = (Get-Date).ToString('s')
    Step      = $Step
    Action    = $Action
    Passed    = $Passed
    Detail    = $Detail
  }
}
$log = [System.Collections.Generic.List[object]]::new()
function OK { param($s,$a,$d='') $log.Add( (New-Row $s,$a,$true ,$d) ) }
function KO { param($s,$a,$d='') $log.Add( (New-Row $s,$a,$false,$d) ) }

function Escape-Html([string]$t){
  if ($null -eq $t) { return '' }
  $t = $t -replace '&','&amp;' -replace '<','&lt;' -replace '>','&gt;' -replace '"','&quot;' -replace "'",'&#39;'
  return $t
}

# ===== 0) Pré-cheques =====
try { Test-WsMan -ComputerName $Target -ErrorAction Stop | Out-Null; OK '0' ("WinRM alcançável em {0}" -f $Target) 'OK' }
catch { KO '0' ("WinRM alcançável em {0}" -f $Target) $_.Exception.Message }

# ===== 1) Configuração no TARGET =====
$remoteConfig = {
  param()
  $ErrorActionPreference = 'Stop'

  # 1.1 – Regras custom (independentes de idioma)
  $rules = @(
    @{ Name='EDU-RPC-135-In';     Port=135;            Desc='RPC Endpoint Mapper' },
    @{ Name='EDU-NETBIOS-139-In'; Port=139;            Desc='NetBIOS Session' },
    @{ Name='EDU-SMB-445-In';     Port=445;            Desc='SMB' },
    @{ Name='EDU-RPC-Dyn-In';     Port='49152-65535';  Desc='RPC Dynamic Range' }
  )
  foreach ($r in $rules) {
    if (-not (Get-NetFirewallRule -DisplayName $r.Name -ErrorAction SilentlyContinue)) {
      New-NetFirewallRule -DisplayName $r.Name -Direction Inbound -Action Allow -Protocol TCP -LocalPort $r.Port -Profile Any | Out-Null
    } else {
      Set-NetFirewallRule -DisplayName $r.Name -Enabled True -Profile Any -Action Allow | Out-Null
    }
  }

  # 1.2 – Habilitar grupo nativo de Event Log remoto (quando presente)
  try {
    $evtRules = Get-NetFirewallRule | Where-Object {
      $_.DisplayGroup -match 'Event Log|Evento|Registro' -or $_.DisplayName -match 'Event Log|Evento|Registro'
    }
    if ($evtRules) { $evtRules | Enable-NetFirewallRule | Out-Null }
  } catch {}

  # 1.3 – Serviços essenciais
  foreach ($svc in 'RpcSs','EventLog','RemoteRegistry') {
    try { Set-Service $svc -StartupType Automatic } catch {}
    try { Start-Service $svc } catch {}
  }

  # 1.4 – PSRemoting (útil para automação)
  try { Enable-PSRemoting -Force -SkipNetworkProfileCheck | Out-Null } catch {}

  # 1.5 – Resumo de portas em escuta
  $listening = Get-NetTCPConnection -State Listen |
               Where-Object { $_.LocalPort -in 135,139,445 } |
               Select-Object LocalAddress,LocalPort,OwningProcess
  return ($listening | Format-Table -AutoSize | Out-String)
}

try {
  $summary = Invoke-Command -ComputerName $Target -ScriptBlock $remoteConfig
  OK '1' ("Configuração aplicada em {0}" -f $Target) $summary
} catch {
  KO '1' ("Configuração aplicada em {0}" -f $Target) $_.Exception.Message
}

# ===== 2) Validações a partir de $TestFrom =====
$remoteTests = {
  param($Target)
  $ErrorActionPreference = 'Stop'
  $o = New-Object System.Collections.Generic.List[string]

  foreach ($p in 135,445) {
    try {
      $t = Test-NetConnection -ComputerName $Target -Port $p -WarningAction SilentlyContinue
      $o.Add( ("TNC {0}:{1} => TCP={2} Ping={3}" -f $Target, $p, $t.TcpTestSucceeded, $t.PingSucceeded) )
    } catch {
      $o.Add( ("TNC {0}:{1} => erro: {2}" -f $Target, $p, $_.Exception.Message) )
    }
  }

  try {
    $ev = Get-WinEvent -ComputerName $Target -LogName System -MaxEvents 1 -ErrorAction Stop
    $o.Add("Get-WinEvent remoto OK: 1 evento lido.")
  } catch {
    $o.Add( ("Get-WinEvent remoto FALHOU: {0}" -f $_.Exception.Message) )
  }

  return ($o -join "`n")
}

try {
  if ($TestFrom -ieq $env:COMPUTERNAME) {
    $val = & $remoteTests.Invoke($Target)
  } else {
    try { Test-WsMan -ComputerName $TestFrom -ErrorAction Stop | Out-Null }
    catch { throw ("WinRM indisponível em {0}: {1}" -f $TestFrom, $_.Exception.Message) }

    $val = Invoke-Command -ComputerName $TestFrom -ScriptBlock $remoteTests -ArgumentList $Target
  }
  OK '2' ("Validação a partir de {0}" -f $TestFrom) $val
} catch {
  KO '2' ("Validação a partir de {0}" -f $TestFrom) $_.Exception.Message
}

# ===== 3) Dica para DCDiag =====
OK '3' 'Dica' ("Execute: dcdiag /test:netlogons /test:sysvolcheck /test:advertising /s:{0}" -f $Target)

# ===== Exportar CSV =====
$log | Export-Csv -Path $outCsv -NoTypeInformation -Encoding UTF8

# ===== HTML =====
$total = $log.Count
$pass  = ($log | Where-Object Passed).Count
$fail  = $total - $pass

$rows = foreach ($r in $log) {
  $cls = if ($r.Passed) {'pass'} else {'fail'}
  "<tr class='$cls'><td>{0}</td><td>{1}</td><td><pre>{2}</pre></td></tr>" -f (Escape-Html $r.Step),(Escape-Html $r.Action),(Escape-Html $r.Detail)
}

$html = @"
<!DOCTYPE html>
<html lang='pt-br'>
<head>
<meta charset='utf-8'/>
<title>Enable RPC/SMB – $Target ($ts)</title>
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
  <h1>Enable RPC/SMB – $(Escape-Html $Target)</h1>
  <div class='sub'>Geração: $ts — Testado a partir de: $(Escape-Html $TestFrom) — Total: $total (PASS: $pass, FAIL: $fail)</div>

  <table>
    <thead><tr><th>Etapa</th><th>Ação</th><th>Detalhe</th></tr></thead>
    <tbody>
      $($rows -join "`n")
    </tbody>
  </table>
</body>
</html>
"@

$html | Out-File -FilePath $outHtml -Encoding UTF8

Write-Host "Relatórios salvos:"
Write-Host " - CSV : $outCsv"
Write-Host " - HTML: $outHtml"
