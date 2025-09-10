<#
  Define o servidor como um servidor de horário
  Criado por Eduardo Popovici
#>

# Configurar o servidor de horário e forçar a replicação
w32tm /config /manualpeerlist:"pool.ntp.org" /syncfromflags:manual /reliable:yes /update
net stop w32time
net start w32time
w32tm /resync /rediscover

# Validar Funcionamento 
w32tm /query /status
w32tm /query /configuration
w32tm /query /peers
