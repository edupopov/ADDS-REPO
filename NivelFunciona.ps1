<#
Importante - Não execute este script em lote. Aqui tem diversos passos
Analise o script e veja qual passo faz sentido dentro de seu ambiente
Este script sobre o nível funcional para Windows Server 2016 e pode ser adequado para novas versões como o 2025 por exemplo
Criado por Eduardo Popovici
#>

# Passo 1
# Domínio raiz e FSMOs relevantes
$forest = Get-ADForest
$root   = $forest.RootDomain
$dnm    = $forest.DomainNamingMaster   # DC que detém Domain Naming Master
$schema = $forest.SchemaMaster         # só para conferência

# Veja o modo atual
$forest.ForestMode
Get-ADForest | Select ForestMode, Domains
Get-ADDomain -Server $root | Select DomainMode

# Todos os DCs devem ser WS2016+ e todos os domínios em Windows2016Domain
Get-ADDomainController -Filter * | Select Name,Site,IPv4Address,OperatingSystem

# Passo 2
# Execute com conta de Enterprise Admin
Set-ADForestMode -Identity $root -ForestMode Windows2016Forest -Server $dnm -Confirm:$false

# Passo 3
# Para cada domínio listado em $forest.Domains, defina para 2016
Set-ADDomainMode -Identity "<dominio.raiz.ou.filho>" -DomainMode Windows2016Domain -Server "<DC_daquele_domínio>" -Confirm:$false

# Passo 4
# Valide o nível funcional da floresta e do domínio
(Get-ADForest -Server $dnm).ForestMode
Get-ADDomain -Server $root | Select DomainMode
