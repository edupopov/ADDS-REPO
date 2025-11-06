# Este pequeno Script recupera a chave de ativação do Windows Instalado
$(Get-WmiObject SoftwareLicensingService).OA3xOriginalProductKey | foreach{ 
 if ( $null -ne $_ ) { 
 Write-Host "Installing"$_
 changepk.exe /Productkey $_ 
 } else { 
 Write-Host "No key present" 
 } 
}
