<#
  Define o servidor como um servidor de horário
  Criado por Eduardo Popovici
#>

w32tm /config /manualpeerlist:"pool.ntp.org" /syncfromflags:manual /reliable:yes /update
net stop w32time
net start w32time
