<#
  Fix SYSVOL (DFSR) – Itens 0 a 5 (v2)
  Autor:  Criado por Eduardo Popovici
  Notas:
    - dfsradmin.exe é usado COM ASPAS nos nomes com espaço.
    - dfsrdiag é executado REMOTAMENTE no $SourceDC (altere para $TargetDC se preferir).
    - CSV + HTML gerados na Área de Trabalho do usuário atual.
#>

$ErrorActionPreference = 'Stop'

# ======== Parâmetros ========
$SourceDC        = 'SRV-AD-02'                    # DC saudável (fonte/hub)
$TargetDC        = 'SRV-AD-01'                    # DC a corrigir (destino)
$RGName          = 'Domain System Volume'
$RFFolder        = 'SYSVOL Share'
$LocalSysvolPath = 'C:\Windows\SYSVOL\domain'

# ======== Saídas ========
$ts       = Get-Date -Format 'yyyyMMdd-HHmmss'
$desktop  = Join-Path $env:USERPROFILE 'Desktop'
$outCsv   = Join-Path $desktop ("Fix_SYSVOL_{0}_via_{1}_{2}.csv"  -f $TargetDC,$SourceDC,$ts)
$outHtml  = Join-Path $desktop ("Fix_SYSVOL_{0}_via_{1}_{2}.html" -f $TargetDC,$SourceDC,$ts)

# ======== Helpers ========
function Get-Category {
  param([string]$Step)
  switch ($Step) {
    '0'      { 'Pré-cheques' }
    '1'      { 'Remoção antiga' }
    '2'      { 'Recriação' }
    '3'      { 'PollAD/Serviço DFSR' }
    '4'      { 'Sincronização' }
    '5'      { 'Validações finais' }
    'CHECK'  { 'Checks' }
    default  { 'Outros' }
  }
}
function New-Row {
  param([string]$Step,[string]$Action,[string]$Target,[bool]$Passed,[string]$Detail='')
  [pscustomobject]@{
    Timestamp = (Get-Date).ToString('s')
    Step      = $Step
    Category  = Get-Category $Step
    Action    = $Action
    Target    = $Target
    Passed    = $Passed
    Detail    = $Detail
  }
}
$log = [System.Collections.Generic.List[object]]::new()

function Add-Ok { param($S,$A,$T,$D='') $log.Add( (New-Row $S $A $T $true  $D) ) }
function Add-Ko { param($S,$A,$T,$D='') $log.Add( (New-Row $S $A $T $false $D) ) }

# Executa comando externo e valida exitcode
function Run-External {
  param([string]$Step,[string]$Action,[string]$Exe,[string[]]$Args,[string]$Target='')
  $psi = New-Object System.Diagnostics.ProcessStartInfo
  $psi.FileName = $Exe
  $psi.Arguments = ($Args -join ' ')
  $psi.RedirectStandardOutput = $true
  $psi.RedirectStandardError  = $true
  $psi.UseShellExecute = $false
  $p = [System.Diagnostics.Process]::Start($psi)
  $stdout = $p.StandardOutput.ReadToEnd()
  $stderr = $p.StandardError.ReadToEnd()
  $p.WaitForExit()
  $rc = $p.ExitCode
  $detail = ("RC={0}`n{1}`n{2}" -f $rc,$stdout,$stderr)
  if ($rc -eq 0) { Add-Ok $Step $Action $Target $detail } else { Add-Ko $Step $Action $Target $detail }
}

function Command-Exists { param([string]$Name) try { [bool](Get-Command $Name -ErrorAction Stop) } catch { $false } }

# Escapar HTML simples
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

# ======== 0) PRÉ-CHEQUES ========
try {
  $dns = Invoke-Command -ComputerName $TargetDC -ScriptBlock {
    Get-DnsClientServerAddress -AddressFamily IPv4 |
      Where-Object { $_.InterfaceAlias -notmatch 'Loopback|isatap|Teredo' } |
      Select-Object InterfaceAlias,ServerAddresses
  } | Out-String
  Add-Ok '0' 'Listar DNS configurado (IPv4) no Target' $TargetDC $dns
} catch { Add-Ko '0' 'Listar DNS configurado (IPv4) no Target' $TargetDC $_.Exception.Message }

try {
  $LASTEXITCODE = $null
  $o = & dcdiag /test:connectivity /s:$TargetDC 2>&1 | Out-String
  if ($LASTEXITCODE -ne 0) { Add-Ko '0' 'dcdiag /test:connectivity (Target)' $TargetDC ("exitcode=$LASTEXITCODE`n$o") }
  else { Add-Ok '0' 'dcdiag /test:connectivity (Target)' $TargetDC $o }
} catch { Add-Ko '0' 'dcdiag /test:connectivity (Target)' $TargetDC $_.Exception.Message }

# Domínio do Target
$DomainFqdn = $null
try {
  $d = Invoke-Command -ComputerName $TargetDC -ScriptBlock { (Get-WmiObject Win32_ComputerSystem).Domain }
  if ($d) { $DomainFqdn = "$d"; Add-Ok '0' 'Descobrir domínio do Target' $TargetDC ("DomainFQDN=$d") }
  else    { Add-Ko '0' 'Descobrir domínio do Target' $TargetDC 'Indefinido' }
} catch { Add-Ko '0' 'Descobrir domínio do Target' $TargetDC $_.Exception.Message }

# Ferramentas locais
if (Command-Exists 'dfsradmin.exe') { Add-Ok 'CHECK' 'dfsradmin.exe' $env:COMPUTERNAME 'OK' }
else { Add-Ko 'CHECK' 'dfsradmin.exe' $env:COMPUTERNAME 'Não encontrado – instale RSAT DFS Management Tools' }

# ======== 1) REMOVER membership/conexões antigas ========
# membership delete (com aspas)
Run-External -Step '1' -Action 'Remover membership do Target no RG' -Target $TargetDC `
  -Exe 'dfsradmin.exe' -Args @('membership','delete',("/rgname:`"$RGName`""),("/rfname:`"$RFFolder`""),("/memname:`"$TargetDC`""),'/force')

# lista conexões
Run-External -Step '1' -Action 'Listar conexões existentes no RG' -Target $RGName `
  -Exe 'dfsradmin.exe' -Args @('conn','list',("/rgname:`"$RGName`""),('/attr:sourcecomputer,destinationcomputer,enabled'))

# tenta remover conexões $SourceDC->$TargetDC e $TargetDC->$TargetDC (se existirem)
foreach ($src in @($SourceDC,$TargetDC)) {
  Run-External -Step '1' -Action "Remover conexão $src -> $TargetDC (se existir)" -Target "$src->$TargetDC" `
    -Exe 'dfsradmin.exe' -Args @('conn','delete',("/rgname:`"$RGName`""),("/sourcecomputer:`"$src`""),("/destinationcomputer:`"$TargetDC`""),'/force')
}

# ======== 2) RECRIAR membership + conexão ========
Run-External -Step '2' -Action 'Criar membership do Target (SYSVOL Share)' -Target $TargetDC `
  -Exe 'dfsradmin.exe' -Args @('membership','new',("/rgname:`"$RGName`""),("/rfname:`"$RFFolder`""),("/memname:`"$TargetDC`""),("/localpath:`"$LocalSysvolPath`""),'/enabled:true','/primary:false')

Run-External -Step '2' -Action 'Criar conexão Source -> Target' -Target "$SourceDC->$TargetDC" `
  -Exe 'dfsradmin.exe' -Args @('conn','new',("/rgname:`"$RGName`""),("/sourcecomputer:`"$SourceDC`""),("/destinationcomputer:`"$TargetDC`""),'/enabled:true')

# ======== 3) PollAD + serviço DFSR (no Target) ========
try {
  $out = Invoke-Command -ComputerName $TargetDC -ScriptBlock { dfsrdiag PollAD } | Out-String
  Add-Ok '3' 'dfsrdiag PollAD (Target)' $TargetDC $out
} catch { Add-Ko '3' 'dfsrdiag PollAD (Target)' $TargetDC $_.Exception.Message }

try {
  $out = Invoke-Command -ComputerName $TargetDC -ScriptBlock { Restart-Service DFSR -Force } | Out-String
  Add-Ok '3' 'Restart-Service DFSR (Target)' $TargetDC $out
} catch { Add-Ko '3' 'Restart-Service DFSR (Target)' $TargetDC $_.Exception.Message }

# ======== 4) Sync + estado/backlog (RODA dfsrdiag REMOTO no SourceDC) ========
try {
  $o = Invoke-Command -ComputerName $SourceDC -ScriptBlock { dfsrdiag SyncNow /RGName:"Domain System Volume" /Time:1 /Verbose } | Out-String
  Add-Ok '4' 'dfsrdiag SyncNow (RG) [remoto no Source]' $RGName $o
} catch { Add-Ko '4' 'dfsrdiag SyncNow (RG) [remoto no Source]' $RGName $_.Exception.Message }

try {
  $o = Invoke-Command -ComputerName $SourceDC -ScriptBlock { dfsrdiag ReplicationState } | Out-String
  Add-Ok '4' 'dfsrdiag ReplicationState [remoto no Source]' $SourceDC $o
} catch { Add-Ko '4' 'dfsrdiag ReplicationState [remoto no Source]' $SourceDC $_.Exception.Message }

try {
  $o = Invoke-Command -ComputerName $SourceDC -ScriptBlock { dfsrdiag backlog /rgname:"Domain System Volume" /rfname:"SYSVOL Share" /sendingmember:$using:SourceDC /receivingmember:$using:TargetDC /full } | Out-String
  Add-Ok '4' 'dfsrdiag Backlog Source->Target [remoto no Source]' "$SourceDC->$TargetDC" $o
} catch { Add-Ko '4' 'dfsrdiag Backlog Source->Target [remoto no Source]' "$SourceDC->$TargetDC" $_.Exception.Message }

# ======== 5) Validações finais ========
try {
  $o = Invoke-Command -ComputerName $TargetDC -ScriptBlock { net share | findstr /I "SYSVOL NETLOGON" } | Out-String
  Add-Ok '5' 'Verificar shares SYSVOL/NETLOGON (Target)' $TargetDC $o
} catch { Add-Ko '5' 'Verificar shares SYSVOL/NETLOGON (Target)' $TargetDC $_.Exception.Message }

if ($DomainFqdn) {
  try {
    $unc = "\\{0}\SYSVOL" -f $DomainFqdn
    $o = dir $unc 2>&1 | Out-String
    Add-Ok '5' 'Listar \\dominio\SYSVOL' $unc $o
  } catch { Add-Ko '5' 'Listar \\dominio\SYSVOL' $DomainFqdn $_.Exception.Message }
} else {
  Add-Ko '5' 'Listar \\dominio\SYSVOL' 'N/A' 'DomainFQDN não resolvido no passo 0'
}

try {
  $LASTEXITCODE = $null
  $o = & dcdiag /test:advertising /s:$TargetDC 2>&1 | Out-String
  if ($LASTEXITCODE -ne 0) { Add-Ko '5' 'dcdiag /test:advertising (Target)' $TargetDC ("exitcode=$LASTEXITCODE`n$o") }
  else { Add-Ok '5' 'dcdiag /test:advertising (Target)' $TargetDC $o }
} catch { Add-Ko '5' 'dcdiag /test:advertising (Target)' $TargetDC $_.Exception.Message }

# ======== Exportar CSV ========
$log | Export-Csv -Path $outCsv -NoTypeInformation -Encoding UTF8

# ======== HTML ========
$pass = ($log | ? Passed).Count
$fail = ($log | ? { -not $_.Passed }).Count
$total = $log.Count
$cats = @('Checks','Pré-cheques','Remoção antiga','Recriação','PollAD/Serviço DFSR','Sincronização','Validações finais')

function Get-Advice {
  param([string]$Step,[string]$Action,[string]$Detail)
  $a = $Action.ToLower(); $d = ($Detail|Out-String).ToLower()
  if ($a -like 'remover membership*' -or $a -like 'criar membership*') { return 'Confira permissões (Admin do Domínio) e replicação do AD. Use nomes RG/RF entre aspas. Verifique eventos DFSR/Directory Service.' }
  if ($a -like 'criar conexão*') { return 'Se falhar, revise DNS/resolução entre Source e Target e integridade dos objetos DFSR no AD.' }
  if ($a -like 'dfsrdiag syncnow*' -or $a -like 'replicationstate*' -or $a -like 'backlog*') { return 'dfsrdiag executa remoto no SourceDC; se falhar, verifique WinRM, firewall e presença do dfsrdiag no DC.' }
  if ($a -like 'dcdiag /test:advertising*') { return 'Só passa quando SYSVOL/NETLOGON estão corretos no Target. Revalide após a convergência.' }
  if ($a -like 'listar \\dominio\\sysvol*') { return 'Se falhar, confirme que o SYSVOL foi compartilhado novamente e que o namespace \\domínio\SYSVOL resolve.' }
  return 'Verifique DNS, permissões, serviços e eventos DFSR conforme o passo.'
}

# linhas tabela + falhas
$rows = foreach ($r in $log) {
  $cls = if ($r.Passed) {'pass'} else {'fail'}
  "<tr class='$cls'><td>{0}</td><td>{1}</td><td>{2}</td><td><pre>{3}</pre></td></tr>" -f (Escape-Html $r.Action),(Escape-Html $r.Target),$r.Passed,(Escape-Html $r.Detail)
}
$fails = $log | ? { -not $_.Passed } | % {
  $adv = Get-Advice $_.Step $_.Action $_.Detail
  @"
<div class='failcard'>
  <div class='ftitle'>$(Escape-Html $_.Category) — $(Escape-Html $_.Action)</div>
  <div class='fmeta'><b>Alvo:</b> $(Escape-Html $_.Target)</div>
  <div class='fdetail'><b>Detalhe:</b> <pre>$(Escape-Html $_.Detail)</pre></div>
  <div class='fadvice'><b>Dica:</b> $(Escape-Html $adv)</div>
</div>
"@
}

# HTML básico (dark-mode friendly)
$html = @"
<!DOCTYPE html>
<html lang='pt-br'>
<head>
<meta charset='utf-8'/>
<title>Fix SYSVOL – $TargetDC via $SourceDC ($ts)</title>
<style>
  :root { color-scheme: light dark; }
  body { font-family: Segoe UI, Roboto, Arial, sans-serif; margin: 24px; }
  h1 { margin: 0 0 4px 0; font-size: 22px; }
  .sub { color:#555; margin: 0 0 16px 0; }
  .summary { display:flex; gap:16px; margin: 16px 0 12px 0; flex-wrap: wrap; }
  .card { padding:12px 16px; border-radius:10px; box-shadow:0 1px 3px rgba(0,0,0,.08); }
  .ok  { background:#e8fff0; border:1px solid #b6f0c9; }
  .bad { background:#ffecec; border:1px solid #ffb3b3; }
  .all { background:#eef4ff; border:1px solid #c9d8ff; }
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
  .fadvice { color:#0f5132; background:#d1e7dd; border:1px solid #badbcc; padding:8px; border-radius:8px; }
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
    .fmeta { color:#ddd; }
    .fadvice { color:#d1f2e1; background:#123b2a; border-color:#1f6d4e; }
  }
</style>
</head>
<body>
  <h1>Fix SYSVOL (DFSR) – $TargetDC via $SourceDC</h1>
  <div class='sub'>Geração: $ts — Total: $total; PASS: $pass; FAIL: $fail</div>

  <div class='summary'>
    <div class='card all'>Total: <b>$total</b></div>
    <div class='card ok'>Pass: <b>$pass</b></div>
    <div class='card bad'>Fail: <b>$fail</b></div>
  </div>

  <div class='section'>
    <h2>Resultados</h2>
    <table>
      <thead><tr><th>Ação</th><th>Alvo</th><th>Passou</th><th>Detalhe</th></tr></thead>
      <tbody>
        $($rows -join "`n")
      </tbody>
    </table>
  </div>

  <div class='section'>
    <h2>Falhas detalhadas</h2>
    $($fails -join "`n")
  </div>
</body>
</html>
"@

$html | Out-File -FilePath $outHtml -Encoding utf8

Write-Host "Relatórios salvos:"
Write-Host " - CSV : $outCsv"
Write-Host " - HTML: $outHtml"
