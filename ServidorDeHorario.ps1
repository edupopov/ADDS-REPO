<#
  Define o servidor como um servidor de horário (Time Server) no domínio.
  Criado por Eduardo Popovici
#>

# --- Configuração do servidor de horário ---
# Este comando define que o SRV-AD-01 será um servidor confiável de horário.
# /config                → inicia configuração do serviço W32Time
# /manualpeerlist        → lista de servidores NTP externos que o DC vai usar como fonte de tempo
#                          (aqui configurado para "pool.ntp.org", mas pode ser substituído por outro NTP confiável, ex: a.st1.ntp.br)
# /syncfromflags:manual  → força a sincronização somente com os servidores definidos em manualpeerlist
# /reliable:yes          → anuncia este servidor como fonte de tempo confiável para o domínio
# /update                → aplica imediatamente as mudanças
w32tm /config /manualpeerlist:"pool.ntp.org" /syncfromflags:manual /reliable:yes /update

# Para definir o fuso horário de São Paulo (Brasília, UTC-03:00) no Windows Server:
tzutil /s "E. South America Standard Time"
tzutil /g

# --- Reinício do serviço de tempo ---
# Interrompe o serviço de tempo do Windows para aplicar as novas configurações
net stop w32time
# Reinicia o serviço de tempo com as novas configurações já aplicadas
net start w32time

# --- Forçar sincronização ---
# Resync → força uma sincronização imediata do horário
# /rediscover → faz o serviço W32Time redescobrir de onde deve sincronizar
w32tm /resync /rediscover

# --- Validação do funcionamento ---
# Mostra o status atual do serviço de tempo (última sincronização, origem, etc.)
w32tm /query /status
# Exibe as configurações atuais do serviço (se está manual, NT5DS, peers, etc.)
w32tm /query /configuration
# Lista os peers configurados (servidores de horário externos ou internos que estão sendo usados)
w32tm /query /peers
