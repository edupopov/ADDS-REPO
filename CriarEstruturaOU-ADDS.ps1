<#
Cria estrutura-padrão de OUs e grupos em qualquer domínio.
- Detecta o domínio via Get-ADDomain
- Idempotente (não recria se existir)
- Protege OUs via New-ADOrganizationalUnit -ProtectedFromAccidentalDeletion
- Protege grupos via Set-ADObject -ProtectedFromAccidentalDeletion
- Criado por Eduardo Popovici
#>

[CmdletBinding()]
param(
  [string]$RootCompanyOU = "01-EMPRESA",
  [string]$BranchesOU    = "02-FILIAIS",
  [string]$SubsidiariesOU= "03-SUCURSAIS",
  [string]$EntraIDSyncOU = "04-EntraIDSync",
  [bool]$EnableProtection = $true,
  [string]$Server,
  [PSCredential]$Credential
)

function Test-ADModule {
  if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    throw "Módulo ActiveDirectory não encontrado. Instale o RSAT AD PowerShell."
  }
}

function Get-ADRootDN {
  if ($Server -and $Credential) { return (Get-ADDomain -Server $Server -Credential $Credential).DistinguishedName }
  if ($Server)                  { return (Get-ADDomain -Server $Server).DistinguishedName }
  if ($Credential)              { return (Get-ADDomain -Credential $Credential).DistinguishedName }
  return (Get-ADDomain).DistinguishedName
}

function Ensure-OU {
  param(
    [string]$Name,[string]$Path,[string]$Description="",
    [bool]$Protect=$true
  )
  $ouDn = "OU=$Name,$Path"

  $lookupParams = @{ LDAPFilter="(ou=$Name)"; SearchBase=$Path; ErrorAction="SilentlyContinue" }
  if ($Server)     { $lookupParams.Server=$Server }
  if ($Credential) { $lookupParams.Credential=$Credential }

  $exists = [bool](Get-ADOrganizationalUnit @lookupParams)

  if (-not $exists) {
    Write-Verbose "Criando OU: $ouDn"
    $newParams = @{
      Name = $Name; Path = $Path; Description = $Description;
      ProtectedFromAccidentalDeletion = $Protect
    }
    if ($Server)     { $newParams.Server=$Server }
    if ($Credential) { $newParams.Credential=$Credential }
    New-ADOrganizationalUnit @newParams | Out-Null
  } else {
    Write-Verbose "OU já existe: $ouDn"
    # Garante proteção conforme parâmetro (opcional)
    $setParams = @{ Identity=$ouDn; ProtectedFromAccidentalDeletion=$Protect }
    if ($Server)     { $setParams.Server=$Server }
    if ($Credential) { $setParams.Credential=$Credential }
    try { Set-ADOrganizationalUnit @setParams } catch {}
  }
  return $ouDn
}

function Ensure-Group {
  param(
    [string]$Name,[string]$Path,[string]$Description="",
    [string]$GroupScope="Global",[string]$GroupCategory="Security",
    [bool]$Protect=$true
  )
  $groupDn = "CN=$Name,$Path"

  $lookupParams = @{ LDAPFilter="(cn=$Name)"; SearchBase=$Path; ErrorAction="SilentlyContinue" }
  if ($Server)     { $lookupParams.Server=$Server }
  if ($Credential) { $lookupParams.Credential=$Credential }

  $exists = [bool](Get-ADGroup @lookupParams)

  if (-not $exists) {
    Write-Verbose "Criando Grupo: $groupDn"
    $newParams = @{
      Name=$Name; Path=$Path; GroupScope=$GroupScope; GroupCategory=$GroupCategory; Description=$Description
    }
    if ($Server)     { $newParams.Server=$Server }
    if ($Credential) { $newParams.Credential=$Credential }
    New-ADGroup @newParams | Out-Null
  } else {
    Write-Verbose "Grupo já existe: $groupDn"
  }

  # Aplica/garante proteção (New-ADGroup não tem o parâmetro)
  if ($Protect) {
    $protParams = @{ Identity=$groupDn; ProtectedFromAccidentalDeletion=$true }
    if ($Server)     { $protParams.Server=$Server }
    if ($Credential) { $protParams.Credential=$Credential }
    try { Set-ADObject @protParams } catch {}
  }

  return $groupDn
}

# -------------------- MAIN --------------------
try {
  Test-ADModule
  $rootDN = Get-ADRootDN
  Write-Verbose "Domínio detectado: $rootDN"

  # Raiz
  $domainPath = $rootDN

  # OUs de primeiro nível
  $ouEmpresaDN    = Ensure-OU -Name $RootCompanyOU   -Path $domainPath -Description "Unidade Organizacional para a Empresa"     -Protect:$EnableProtection
  $ouFiliaisDN    = Ensure-OU -Name $BranchesOU      -Path $domainPath -Description "Unidade Organizacional para Filiais"       -Protect:$EnableProtection
  $ouSucursaisDN  = Ensure-OU -Name $SubsidiariesOU  -Path $domainPath -Description "Unidade Organizacional para Sucursais"     -Protect:$EnableProtection
  $ouEntraSyncDN  = Ensure-OU -Name $EntraIDSyncOU   -Path $domainPath -Description "Unidade Organizacional para EntraIDSync"   -Protect:$EnableProtection

  # Internas de 01-EMPRESA
  $ouDepartamentosDN = Ensure-OU -Name "Departamentos" -Path $ouEmpresaDN -Description "Unidade Organizacional para Departamentos" -Protect:$EnableProtection
  $ouServidoresDN    = Ensure-OU -Name "Servidores"    -Path $ouEmpresaDN -Description "Unidade Organizacional para Servidores"   -Protect:$EnableProtection
  $ouTerceirosDN     = Ensure-OU -Name "Terceiros"     -Path $ouEmpresaDN -Description "Unidade Organizacional para Terceiros"    -Protect:$EnableProtection
  $ouAplicacoesDN    = Ensure-OU -Name "Aplicacoes"    -Path $ouEmpresaDN -Description "Unidade Organizacional para Aplicações"   -Protect:$EnableProtection

  # Dentro de Servidores
  Ensure-OU -Name "Servidor de Arquivos"          -Path $ouServidoresDN -Description "Unidade Organizacional para Servidores de Arquivos"         -Protect:$EnableProtection | Out-Null
  Ensure-OU -Name "Servidores de Aplicacao"       -Path $ouServidoresDN -Description "Unidade Organizacional para Servidores de Aplicação"        -Protect:$EnableProtection | Out-Null
  Ensure-OU -Name "Servidores de Bancos de Dados" -Path $ouServidoresDN -Description "Unidade Organizacional para Servidores de Bancos de Dados"  -Protect:$EnableProtection | Out-Null

  # Departamentos
  $ouTI_DN          = Ensure-OU -Name "TI"          -Path $ouDepartamentosDN -Description "Unidade Organizacional de TI"           -Protect:$EnableProtection
  $ouRH_DN          = Ensure-OU -Name "RH"          -Path $ouDepartamentosDN -Description "Unidade Organizacional de RH"           -Protect:$EnableProtection
  $ouCOMPRAS_DN     = Ensure-OU -Name "COMPRAS"     -Path $ouDepartamentosDN -Description "Unidade Organizacional de Compras"      -Protect:$EnableProtection
  $ouCOMERCIAL_DN   = Ensure-OU -Name "COMERCIAL"   -Path $ouDepartamentosDN -Description "Unidade Organizacional Comercial"        -Protect:$EnableProtection
  $ouENGENHARIA_DN  = Ensure-OU -Name "ENGENHARIA"  -Path $ouDepartamentosDN -Description "Unidade Organizacional de Engenharia"    -Protect:$EnableProtection
  $ouJURIDICO_DN    = Ensure-OU -Name "JURIDICO"    -Path $ouDepartamentosDN -Description "Unidade Organizacional Jurídico"         -Protect:$EnableProtection

  # TI
  Ensure-OU -Name "N1"              -Path $ouTI_DN -Description "Unidade Organizacional N1"                        -Protect:$EnableProtection | Out-Null
  Ensure-OU -Name "N2"              -Path $ouTI_DN -Description "Unidade Organizacional N2"                        -Protect:$EnableProtection | Out-Null
  Ensure-OU -Name "Administradores" -Path $ouTI_DN -Description "Unidade Organizacional de Administradores"        -Protect:$EnableProtection | Out-Null
  Ensure-OU -Name "Computadores"    -Path $ouTI_DN -Description "Unidade Organizacional de Computadores"           -Protect:$EnableProtection | Out-Null
  Ensure-OU -Name "Impressoras"     -Path $ouTI_DN -Description "Unidade Organizacional de Impressoras"            -Protect:$EnableProtection | Out-Null

  # RH, COMPRAS, COMERCIAL, ENGENHARIA, JURIDICO
  foreach ($base in @($ouRH_DN,$ouCOMPRAS_DN,$ouCOMERCIAL_DN,$ouENGENHARIA_DN,$ouJURIDICO_DN)) {
    Ensure-OU -Name "Computadores" -Path $base -Description "Unidade Organizacional de Computadores" -Protect:$EnableProtection | Out-Null
    Ensure-OU -Name "Funcionários" -Path $base -Description "Unidade Organizacional de Funcionários" -Protect:$EnableProtection | Out-Null
    Ensure-OU -Name "Impressoras"  -Path $base -Description "Unidade Organizacional de Impressoras"  -Protect:$EnableProtection | Out-Null
    Ensure-OU -Name "Inativos"     -Path $base -Description "Unidade Organizacional de Inativos"     -Protect:$EnableProtection | Out-Null
  }

  # Regras
  $ouRegrasVPN_DN        = Ensure-OU -Name "Regras de VPN"         -Path $ouEmpresaDN -Description "Unidade Organizacional para Regras de VPN"         -Protect:$EnableProtection
  $ouRegrasFileServer_DN = Ensure-OU -Name "Regras do File Server" -Path $ouEmpresaDN -Description "Unidade Organizacional para Regras do File Server"  -Protect:$EnableProtection

  # Grupos - File Server
  foreach ($g in @(
    "LEITURA-COMERCIAL","LEITURA-COMPRAS","LEITURA-ENGENHARIA","LEITURA-JURIDICO","LEITURA-RH","LEITURA-TI",
    "ESCRITA-COMPRAS","ESCRITA-ENGENHARIA","ESCRITA-JURIDICO","ESCRITA-RH","ESCRITA-TI"
  )) {
    Ensure-Group -Name $g -Path $ouRegrasFileServer_DN -Description "Grupo de $g" -GroupScope "Global" -GroupCategory "Security" -Protect:$EnableProtection | Out-Null
  }

  # Grupos - VPN
  foreach ($g in @("VPN-01","VPN-02","VPN-03")) {
    Ensure-Group -Name $g -Path $ouRegrasVPN_DN -Description "Grupo de $g" -GroupScope "Global" -GroupCategory "Security" -Protect:$EnableProtection | Out-Null
  }

  # Terceiros
  Ensure-OU -Name "Ativos"   -Path $ouTerceirosDN -Description "Unidade Organizacional de Terceiros Ativos"   -Protect:$EnableProtection | Out-Null
  Ensure-OU -Name "Inativos" -Path $ouTerceirosDN -Description "Unidade Organizacional de Terceiros Inativos" -Protect:$EnableProtection | Out-Null

  Write-Host "✅ Estrutura criada/validada com sucesso no domínio: $rootDN"
}
catch {
  Write-Error "Falha ao criar estrutura: $($_.Exception.Message)"
}
