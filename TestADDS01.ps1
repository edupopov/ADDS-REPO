<# 
  Validação AD – Acesso remoto a logs (RPC/DCOM) + checks funcionais
  Saída: CSV na Área de Trabalho do usuário atual
  Desenvolvedor: Eduardo Popovici
#>

$ErrorActionPreference = 'Stop'
# Defina aqui o servidor que será direcionado o teste
$TargetServer = 'SRV-AD-02'

$timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$outFile   = Join-Path $env:USERPROFILE ("Desktop\Validacao_RPC_Logs_{0}_{1}.csv" -f $TargetServer,$timestamp)

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

$results = [System.Collections.Generic.List[object]]::new()

# ============= 1) Conectividade RPC =============
try {
    $t135 = Test-NetConnection -ComputerName $TargetServer -Port 135 -WarningAction SilentlyContinue
    $lat  = if ($t135.PingSucceeded) { $t135.PingReplyDetails.RoundtripTime } else { $null }
    $results.Add( (New-Result 'TCP Port' "$($TargetServer):135" $t135.TcpTestSucceeded ("Latency(ms)={0}" -f $lat)) )
} catch { $results.Add( (New-Result 'TCP Port' "$($TargetServer):135" $false $_.Exception.Message) ) }

# Porta dinâmica (amostra – pode falhar sem indicar problema)
$highPort = 49152
try {
    $thigh = Test-NetConnection -ComputerName $TargetServer -Port $highPort -WarningAction SilentlyContinue
    $lat2  = if ($thigh.PingSucceeded) { $thigh.PingReplyDetails.RoundtripTime } else { $null }
    $results.Add( (New-Result 'TCP Port' "$($TargetServer):$highPort" $thigh.TcpTestSucceeded ("Latency(ms)={0}" -f $lat2)) )
} catch { $results.Add( (New-Result 'TCP Port' "$($TargetServer):$highPort" $false $_.Exception.Message) ) }

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

# ============= 4) Leitura remota de eventos (System/Application/DFS Replication) =============
# Helper para checar log remotamente com try/catch
function Test-RemoteLog {
    param([string]$Computer,[string]$LogName,[int]$Max=3)
    try {
        # Verifica se o log existe (evita erro em servidores que não têm o canal)
        $exists = Get-WinEvent -ComputerName $Computer -ListLog $LogName -ErrorAction Stop
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

# ============= 6) Invoke-Command + wevtutil (requer WinRM) =============
try {
    $ic = Invoke-Command -ComputerName $TargetServer -ScriptBlock { wevtutil qe System /c:3 /f:RenderedText } -ErrorAction Stop
    $ok = ($ic -is [array]) -or ($ic -is [string]) -and ($ic.Length -gt 0)
    $snippet = ($ic | Select-Object -First 1)
    $results.Add( (New-Result 'Invoke-Command wevtutil' $TargetServer $ok ("FirstLine={0}" -f $snippet)) )
} catch {
    $results.Add( (New-Result 'Invoke-Command wevtutil' $TargetServer $false $_.Exception.Message) )
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
    $results.Add( (New-Result 'PortQry EPM 135' $TargetServer $false 'portqry.exe não encontrado – teste ignorado') )
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
$results | Export-Csv -Path $outFile -NoTypeInformation -Encoding UTF8
Write-Host "Relatório salvo em: $outFile"
