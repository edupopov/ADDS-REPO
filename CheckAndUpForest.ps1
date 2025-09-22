<#
Permissões: use uma conta do grupo Enterprise Admins (e conecte-se ao domínio raiz).
Replicação: aguarde a convergência (ou force) antes de validar em outros DCs.
Irreversível: elevar FFL/DFL não tem rollback.
GUI x PowerShell: confie no PowerShell; a GUI às vezes “arredonda” como “2016 ou superior”.
Criado por Eduardo Popovici
#>

# Requisitos: módulo ActiveDirectory, conta Enterprise Admin
$forest = Get-ADForest
$root   = $forest.RootDomain
$dnm    = $forest.DomainNamingMaster

# 1) Checar DCs
"--- DCs ---"
Get-ADDomainController -Filter * | Select Name,OperatingSystem | Format-Table -Auto

# 2) Elevar todos os domínios para 2016, se necessário
foreach($d in $forest.Domains){
    $dm = (Get-ADDomain -Server $d).DomainMode
    if($dm -ne 'Windows2016Domain'){
        Write-Host "Elevando DFL de $d (atual: $dm) -> Windows2016Domain"
        Set-ADDomainMode -Identity $d -DomainMode Windows2016Domain -Server $d -Confirm:$false
    } else {
        Write-Host "DFL de $d já é Windows2016Domain"
    }
}

# 3) Elevar floresta para 2016 (apontando ao Domain Naming Master)
if( (Get-ADForest -Server $dnm).ForestMode -ne 'Windows2016Forest'){
    Write-Host "Elevando FFL da floresta $root -> Windows2016Forest via $dnm"
    Set-ADForestMode -Identity $root -ForestMode Windows2016Forest -Server $dnm -Confirm:$false
} else {
    Write-Host "FFL já é Windows2016Forest"
}

# 4) Validar
"--- Validação ---"
(Get-ADForest -Server $dnm).ForestMode
foreach($d in $forest.Domains){ (Get-ADDomain -Server $d).DomainMode }
