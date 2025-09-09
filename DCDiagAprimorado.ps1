<#
  Executa DCDiag completo e gera TXT + HTML na Área de Trabalho
  Criado por Eduardo Popovici

  Observações:
   - Usa /e /q /v /c /fix, como solicitado.
   - /q (quiet) reduz a verbosidade (foco em falhas/avisos).
   - Compatível com Windows PowerShell 5.1 e PowerShell 7+ (sem -Encoding no Tee-Object).
   - Adicione o domínio na linha 13 - substitua o dominio.local pelo seu domínio
#>

param(
  [string]$Domain = 'dominio.local'
)

$ErrorActionPreference = 'Stop'

# ===== Saídas =====
$timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$desktop   = Join-Path $env:USERPROFILE 'Desktop'
$outTxt    = Join-Path $desktop ("DCDiag_{0}_{1}.txt"  -f $Domain,$timestamp)
$outHtml   = Join-Path $desktop ("DCDiag_{0}_{1}.html" -f $Domain,$timestamp)

# ===== Pré-cheque =====
$dcdiagCmd = Get-Command dcdiag -ErrorAction SilentlyContinue
if (-not $dcdiagCmd) {
  Write-Error "dcdiag não encontrado. Instale RSAT AD DS Tools ou execute em um DC."
  exit 1
}

Write-Host "Executando DCDIAG para o domínio $Domain ..."
$LASTEXITCODE = $null
$dcArgs = @('/e','/q','/v','/c','/fix',"/testdomain:$Domain")

# ===== Execução: captura a saída em variável e grava como UTF-8 =====
# (Tee-Object não aceita -Encoding, então usamos -Variable e depois Out-File)
$null = & dcdiag @dcArgs 2>&1 | Tee-Object -Variable dcRaw
$dcOutput = $dcRaw
$dcOutput | Out-File -FilePath $outTxt -Encoding UTF8

$exitCode = $LASTEXITCODE
Write-Host "Saída TXT: $outTxt"
Write-Host "ExitCode do dcdiag: $exitCode"

# ===== Parser heurístico EN/PT =====
$serverRegexEN = '^\s*Testing server:\s*(.+)$'
$serverRegexPT = '^\s*Testando servidor:\s*(.+)$'
$startRegexEN  = '^\s*Starting test:\s*(.+)$'
$startRegexPT  = '^\s*Iniciando teste:\s*(.+)$'

$rxFail = [regex]'(?i)\bfailed\b|\bfalhou\b|\bfatal\b|\berror(s)?\b|\berro\b|\bcritical\b|\bcr[ií]tico\b|n[ãa]o.*(responde|dispon[ií]vel)|cannot|could not|failed to'
$rxWarn = [regex]'(?i)\bwarn(ing)?\b|aviso(s)?'

$tests = New-Object System.Collections.Generic.List[object]
$currentServer = $null
$currentTest   = $null
$currentLines  = New-Object System.Collections.Generic.List[string]

function Flush-Test {
  param([string]$Server,[string]$Test,[System.Collections.Generic.List[string]]$Lines)
  if ([string]::IsNullOrWhiteSpace($Test)) { return }
  $joined = ($Lines -join "`n")
  $isFail = $rxFail.IsMatch($joined)
  $isWarn = (-not $isFail) -and $rxWarn.IsMatch($joined)
  $status = if ($isFail) {'FAIL'} elseif ($isWarn) {'WARN'} else {'PASS'}
  $firstHit = ($Lines | Where-Object { $_ -match $rxFail.ToString() -or $_ -match $rxWarn.ToString() } | Select-Object -First 4) -join ' | '
  $tests.Add([pscustomobject]@{ Server=$Server; Test=$Test; Status=$status; Detail=$firstHit })
  $Lines.Clear()
}

foreach ($line in $dcOutput) {
  if ($line -match $serverRegexEN -or $line -match $serverRegexPT) {
    Flush-Test -Server $currentServer -Test $currentTest -Lines $currentLines
    $currentServer = $Matches[1].Trim(); $currentTest = $null; continue
  }
  if ($line -match $startRegexEN -or $line -match $startRegexPT) {
    Flush-Test -Server $currentServer -Test $currentTest -Lines $currentLines
    $currentTest = $Matches[1].Trim(); continue
  }
  if ($currentTest) { $currentLines.Add([string]$line) }
}
Flush-Test -Server $currentServer -Test $currentTest -Lines $currentLines

if ($tests.Count -eq 0) {
  $tests.Add([pscustomobject]@{
    Server = 'N/D'; Test='Resumo';
    Status = if ($exitCode -eq 0) {'PASS'} else {'WARN'};
    Detail = "Saída minimizada por /q. Consulte o TXT: $outTxt"
  })
}

# ===== Relatório HTML =====
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

$total = $tests.Count
$pass  = ($tests | Where-Object {$_.Status -eq 'PASS'}).Count
$warn  = ($tests | Where-Object {$_.Status -eq 'WARN'}).Count
$fail  = ($tests | Where-Object {$_.Status -eq 'FAIL'}).Count

$servers = ($tests | Select-Object -ExpandProperty Server | Sort-Object -Unique)
$serverTables = foreach ($sv in $servers) {
  $rows = foreach ($t in ($tests | Where-Object {$_.Server -eq $sv})) {
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

$issues = $tests | Where-Object {$_.Status -ne 'PASS'}
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

$noteQ = @"
<div class='note'>
  <b>Nota:</b> O parâmetro <code>/q</code> (quiet) reduz a verbosidade do DCDiag e pode ocultar testes aprovados.
  Use este HTML para focar em falhas/avisos e o TXT para análise completa.
  <div>Arquivo TXT: <code>$outTxt</code></div>
  <div>ExitCode DCDiag: <code>$exitCode</code></div>
</div>
"@

$html = @"
<!DOCTYPE html>
<html lang="pt-br">
<head>
<meta charset="utf-8"/>
<title>DCDiag ($Domain) – $timestamp</title>
<style>
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
  th, td { border-bottom:1px solid #eee; padding:8px 10px; vertical-align: top; }
  th { text-align:left; background:#fafafa; }
  tr.pass td { background:#f7fff9; }
  tr.warn td { background:#fff9ec; }
  tr.fail td { background:#fff7f7; }
  pre { margin:0; white-space: pre-wrap; word-wrap: break-word; }
  .section { margin-top:28px; }
  .failcard { border:1px solid #ffd2d2; background:#fff5f5; padding:12px; border-radius:10px; margin-bottom:12px; }
  .ftitle { font-weight:600; margin-bottom:4px; }
  .fmeta { color:#333; margin-bottom:6px; }
  .note { margin:14px 0; padding:10px; border-radius:8px; background:#fff9e6; border:1px solid #ffe08a; }
  @media (prefers-color-scheme: dark) {
    body { color:#eee; background:#121212; }
    .sub { color:#bbb; }
    .card { box-shadow:none; }
    .all { background:#1b2744; border-color:#30487c; }
    .ok  { background:#14301d; border-color:#1f7a46; }
    .wrn { background:#3a2f18; border-color:#7a6d2e; }
    .bad { background:#3a1b1b; border-color:#7a2e2e; }
    th { background:#1b1b1b; }
    th, td { border-bottom:1px solid #2a2a2a; }
    tr.pass td { background:#0e2216; }
    tr.warn td { background:#2f2a18; }
    tr.fail td { background:#2a1515; }
    .fmeta { color:#ddd; }
  }
</style>
</head>
<body>
  <h1>DCDiag – Domínio $(Escape-Html $Domain)</h1>
  <div class="sub">Geração: $timestamp — Mapeados: $total (PASS: $pass, WARN: $warn, FAIL: $fail)</div>

  <div class="summary">
    <div class="card all">Mapeados: <b>$total</b></div>
    <div class="card ok">Pass: <b>$pass</b></div>
    <div class="card wrn">Warn: <b>$warn</b></div>
    <div class="card bad">Fail: <b>$fail</b></div>
  </div>

  $noteQ

  $($serverTables -join "`n")

  <div class="section">
    <h2>Falhas/Avisos detalhados</h2>
    $($issueBlocks -join "`n")
  </div>
</body>
</html>
"@

$html | Out-File -FilePath $outHtml -Encoding UTF8
Write-Host "Relatório HTML: $outHtml"
