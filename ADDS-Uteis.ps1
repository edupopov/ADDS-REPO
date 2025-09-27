# Promoção de controladores de domínio 
Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools
Install-ADDSDomainController -CreateDnsDelegation:$false -InstallDns:$true -DomainName "popovici.lab" -SiteName "Default-First-Site-Name" -ReplicationSourceDC "SRV-AD-01.popovici.lab" -DatabasePath "C:\Windows\NTDS" -LogPath "C:\Windows\NTDS" -SysvolPath "C:\Windows\SYSVOL" -Force:$true

# Transferir FSMO
Get-ADDomain | Select-Object InfrastructureMaster, RIDMaster, PDCEmulator
Get-ADForest | Select-Object DomainNamingMaster, SchemaMaster

# Mover FSMO
Move-ADDirectoryServerOperationMasterRole -Identity TargetDC -OperationMasterRole SchemaMaster, DomainNamingMaster, PDCEmulator, RIDMaster, InfrastructureMaster

# Rebaixar controlador de domínio
Uninstall-ADDSDomainController -DemoteOperationMasterRole -RemoveApplicationPartition

# Atualizar nívem funcional 
Set-ADDomainMode -identity tailwindtraders.com -DomainMode Windows2025Domain
Set-ADForestMode -Identity tailwindtraders.com -ForestMode Windows2025Forest

