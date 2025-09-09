<# Corrige NS/delegação de _msdcs para dominio.local
   - Remove NS antigo (ex.: fixen-dc01.fixen.local)
   - Garante NS para SRV-AD-01 e SRV-AD-02
   - Se _msdcs.FIXEN.local existir, corrige a zona; senão, corrige o nó delegado no pai
#>

$DnsServer   = 'SRV-AD-02'
$ParentZone  = 'dominio.local'
$ChildName   = '_msdcs'
$ChildZone   = "$ChildName.$ParentZone"

# NS válidos e respectivos IPs (glue) — ajuste se necessário
$GoodNS      = @('SRV-AD-01.dominio.local','SRV-AD-02.dominio.local')
$GoodIPs     = @('192.168.50.41','192.168.50.42')

Write-Host "Servidor DNS alvo: $DnsServer"
Write-Host "Zona pai: $ParentZone | Zona/child: $ChildZone"

function Ensure-GlueA {
  param(
    [string]$HostFqdn,
    [string]$IPv4,
    [string]$ParentZone,
    [string]$DnsServer
  )
  # extrai apenas o rótulo na zona pai (ex.: 'SRV-AD-01')
  $name = $HostFqdn.TrimEnd('.')
  if ($name.ToLower().EndsWith(("." + $ParentZone).ToLower())) {
    $name = $name.Substring(0, $name.Length - 1 - $ParentZone.Length)
  }
  $a = Get-DnsServerResourceRecord -ComputerName $DnsServer -ZoneName $ParentZone -RRType A -Name $name -ErrorAction SilentlyContinue
  if (-not $a) {
    Write-Host "  + Criando glue A para $HostFqdn -> $IPv4"
    Add-DnsServerResourceRecordA -ComputerName $DnsServer -ZoneName $ParentZone -Name $name -IPv4Address $IPv4 | Out-Null
  }
}

# 1) Existe a zona separada _msdcs.FIXEN.local?
$childZoneObj = Get-DnsServerZone -ComputerName $DnsServer -Name $ChildZone -ErrorAction SilentlyContinue

if ($childZoneObj) {
  Write-Host "Detectado: zona ${ChildZone} existe (AD-integrada). Corrigindo NS dentro da zona..."

  # NS atuais na zona _msdcs
  $nsInChild = Get-DnsServerResourceRecord -ComputerName $DnsServer -ZoneName $ChildZone -RRType NS -ErrorAction SilentlyContinue

  # Remover NS que não estão na lista GoodNS
  foreach ($r in $nsInChild) {
    $nsName = $r.RecordData.NameServer.TrimEnd('.')
    if ($GoodNS -notcontains $nsName) {
      Write-Host "  - Removendo NS obsoleto da zona ${ChildZone}: $nsName"
      $r | Remove-DnsServerResourceRecord -ZoneName $ChildZone -ComputerName $DnsServer -Force
    }
  }

  # Adicionar NS que faltam
  foreach ($ns in $GoodNS) {
    $exists = $nsInChild | Where-Object { $_.RecordData.NameServer.TrimEnd('.') -ieq $ns }
    if (-not $exists) {
      Write-Host "  + Adicionando NS na zona ${ChildZone}: $ns"
      Add-DnsServerResourceRecord -ComputerName $DnsServer -ZoneName $ChildZone -NS -Name '.' -NameServer $ns | Out-Null
    }
  }

  # (Opcional) Higienizar NS do nó _msdcs no pai
  Write-Host "Higienizando NS do nó ${ChildName} no pai ${ParentZone} (opcional)..."
  $nsInParent = Get-DnsServerResourceRecord -ComputerName $DnsServer -ZoneName $ParentZone -Name $ChildName -RRType NS -ErrorAction SilentlyContinue
  foreach ($r in $nsInParent) {
    $nsName = $r.RecordData.NameServer.TrimEnd('.')
    if ($GoodNS -notcontains $nsName) {
      Write-Host "  - Removendo NS antigo do nó ${ChildName} no pai: $nsName"
      $r | Remove-DnsServerResourceRecord -ZoneName $ParentZone -ComputerName $DnsServer -Force
    }
  }
  foreach ($ns in $GoodNS) {
    $exists = $nsInParent | Where-Object { $_.RecordData.NameServer.TrimEnd('.') -ieq $ns }
    if (-not $exists) {
      Write-Host "  + Adicionando NS atual no nó ${ChildName} do pai: $ns"
      Add-DnsServerResourceRecord -ComputerName $DnsServer -ZoneName $ParentZone -NS -Name $ChildName -NameServer $ns | Out-Null
    }
  }

} else {
  Write-Host "Não existe zona ${ChildZone}. Corrigindo a DELEGAÇÃO no pai ${ParentZone}..."

  # Remover NS antigos do nó _msdcs no pai
  $nsInParent = Get-DnsServerResourceRecord -ComputerName $DnsServer -ZoneName $ParentZone -Name $ChildName -RRType NS -ErrorAction SilentlyContinue
  foreach ($r in $nsInParent) {
    $nsName = $r.RecordData.NameServer.TrimEnd('.')
    if ($GoodNS -notcontains $nsName) {
      Write-Host "  - Removendo NS obsoleto do nó ${ChildName}: $nsName"
      $r | Remove-DnsServerResourceRecord -ZoneName $ParentZone -ComputerName $DnsServer -Force
    }
  }

  # Garantir glue A para os NS válidos
  for ($i=0; $i -lt $GoodNS.Count; $i++) {
    Ensure-GlueA -HostFqdn $GoodNS[$i] -IPv4 $GoodIPs[$i] -ParentZone $ParentZone -DnsServer $DnsServer
  }

  # Adicionar NS que faltam na delegação
  foreach ($ns in $GoodNS) {
    $exists = $nsInParent | Where-Object { $_.RecordData.NameServer.TrimEnd('.') -ieq $ns }
    if (-not $exists) {
      Write-Host "  + Adicionando NS do nó ${ChildName}: $ns"
      Add-DnsServerResourceRecord -ComputerName $DnsServer -ZoneName $ParentZone -NS -Name $ChildName -NameServer $ns | Out-Null
    }
  }
}

Write-Host "`nVerificando..."
Resolve-DnsName -Server $DnsServer -Type NS $ChildZone | Format-Table -AutoSize
