<#
Corrige cadeia SYSVOL (<domain>\scripts) e os compartilhamentos SYSVOL/NETLOGON
com boas práticas de share e NTFS. Compatível com diferentes versões do SMB.
Criador por Eduardo Popovici
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param()

# --- Utilidades ---
function Resolve-SidName {
    param([Parameter(Mandatory)][string]$SidValue)
    try {
        $sid = New-Object System.Security.Principal.SecurityIdentifier($SidValue)
        return ($sid.Translate([System.Security.Principal.NTAccount])).Value
    } catch {
        throw "Falha ao traduzir SID $SidValue - $($_.Exception.Message)"
    }
}

function Get-SysvolPath {
    $regPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'
    try {
        $prop = Get-ItemProperty -Path $regPath -Name 'SysVol' -ErrorAction Stop
        if ($prop.SysVol) { return $prop.SysVol }
    } catch { }
    return (Join-Path $env:SystemRoot 'SYSVOL\sysvol')
}

function Ensure-Folder {
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }
}

# Aplica ACL NTFS canônica
function Ensure-NTFS {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][hashtable]$DesiredAcl
    )

    $acl = Get-Acl -LiteralPath $Path
    $entries = $acl.Access

    foreach ($sid in $DesiredAcl.Keys) {
        $ruleSpec = $DesiredAcl[$sid]
        $account  = Resolve-SidName $sid

        # Remove regras existentes do mesmo principal para regravar de forma limpa
        $toRemove = @($entries | Where-Object { $_.IdentityReference -eq $account })
        foreach ($r in $toRemove) { [void]$acl.RemoveAccessRule($r) }

        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            $account,
            $ruleSpec.Rights,
            $ruleSpec.Inheritance,
            $ruleSpec.Propagation,
            $ruleSpec.ControlType
        )
        [void]$acl.AddAccessRule($rule)
    }

    if ($PSCmdlet.ShouldProcess($Path, "Aplicar ACL NTFS padrão para SYSVOL/NETLOGON")) {
        Set-Acl -LiteralPath $Path -AclObject $acl
    }
}

# Cria/ajusta Share com parâmetros opcionais somente se suportados
function NewOrFix-SmbShare {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Path
    )

    $share = Get-SmbShare -Name $Name -ErrorAction SilentlyContinue
    $newShareParams = @{
        Name = $Name
        Path = $Path
    }

    # CachingMode=None é amplamente suportado, mas validamos
    $newCmd = Get-Command New-SmbShare -ErrorAction Stop
    if ($newCmd.Parameters.ContainsKey('CachingMode')) { $newShareParams['CachingMode'] = 'None' }

    if (-not $share) {
        if ($PSCmdlet.ShouldProcess("$Name -> $Path", "Criar SMB Share")) {
            New-SmbShare @newShareParams | Out-Null
        }
        $share = Get-SmbShare -Name $Name
    } else {
        # Ajusta caminho se diferente
        if ($share.Path -ne $Path) {
            if ($PSCmdlet.ShouldProcess("$Name -> $Path", "Ajustar caminho do share")) {
                Remove-SmbShare -Name $Name -Force
                New-SmbShare @newShareParams | Out-Null
                $share = Get-SmbShare -Name $Name
            }
        }
        # Ajusta caching se suportado
        $setCmd = Get-Command Set-SmbShare -ErrorAction Stop
        if ($setCmd.Parameters.ContainsKey('CachingMode') -and $share.CachingMode -ne 'None') {
            if ($PSCmdlet.ShouldProcess($Name, "Definir CachingMode=None")) {
                Set-SmbShare -Name $Name -CachingMode None
            }
        }
    }

    return $share
}

# Aplica permissões do compartilhamento (SMB)
function Ensure-SmbShareAccess {
    param(
        [Parameter(Mandatory)][string]$Name,
        [string[]]$FullSidList,
        [string[]]$ReadSidList
    )

    $existing = Get-SmbShareAccess -Name $Name
    $targetAccounts = @()
    foreach ($sid in @($FullSidList + $ReadSidList)) { $targetAccounts += (Resolve-SidName $sid) }

    # Revoga acessos inesperados
    foreach ($acc in $existing.AccountName) {
        if ($acc -notin $targetAccounts) {
            if ($PSCmdlet.ShouldProcess("$Name - $acc", "Revogar acesso SMB")) {
                Revoke-SmbShareAccess -Name $Name -AccountName $acc -Force
            }
        }
    }

    # Garante Full
    foreach ($sid in $FullSidList) {
        $acc = Resolve-SidName $sid
        $current = $existing | Where-Object { $_.AccountName -eq $acc -and $_.AccessRight -eq 'Full' }
        if (-not $current) {
            if ($PSCmdlet.ShouldProcess("$Name - $acc", "Conceder SMB Full")) {
                Grant-SmbShareAccess -Name $Name -AccountName $acc -AccessRight Full -Force | Out-Null
            }
        }
    }

    # Garante Read
    foreach ($sid in $ReadSidList) {
        $acc = Resolve-SidName $sid
        $current = $existing | Where-Object { $_.AccountName -eq $acc -and $_.AccessRight -eq 'Read' }
        if (-not $current) {
            if ($PSCmdlet.ShouldProcess("$Name - $acc", "Conceder SMB Read")) {
                Grant-SmbShareAccess -Name $Name -AccountName $acc -AccessRight Read -Force | Out-Null
            }
        }
    }
}

# ===================== Execução =====================
try {
    Write-Host "==> Detectando domínio e caminhos..." -ForegroundColor Cyan
    $domainName = ([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()).Name
    $sysvolPath = Get-SysvolPath
    $domainRoot  = Join-Path $sysvolPath $domainName
    $scriptsPath = Join-Path $domainRoot 'scripts'

    Write-Host "Domínio            : $domainName"
    Write-Host "SYSVOL (base)      : $sysvolPath"
    Write-Host "Pasta do domínio   : $domainRoot"
    Write-Host "Pasta NETLOGON     : $scriptsPath"
    Write-Host ""

    # Cadeia de pastas
    Ensure-Folder -Path $sysvolPath
    Ensure-Folder -Path $domainRoot
    Ensure-Folder -Path $scriptsPath

    # SIDs conhecidos
    $SID_Administrators = 'S-1-5-32-544' # BUILTIN\Administrators
    $SID_SYSTEM         = 'S-1-5-18'     # NT AUTHORITY\SYSTEM
    $SID_AuthUsers      = 'S-1-5-11'     # Authenticated Users
    $SID_CreatorOwner   = 'S-1-3-0'      # CREATOR OWNER

    # ACL NTFS desejada
    $desiredAcl = @{
        $SID_Administrators = @{
            Rights      = [System.Security.AccessControl.FileSystemRights]::FullControl
            Inheritance = [System.Security.AccessControl.InheritanceFlags] "ContainerInherit, ObjectInherit"
            Propagation = [System.Security.AccessControl.PropagationFlags]::None
            ControlType = [System.Security.AccessControl.AccessControlType]::Allow
        }
        $SID_SYSTEM = @{
            Rights      = [System.Security.AccessControl.FileSystemRights]::FullControl
            Inheritance = [System.Security.AccessControl.InheritanceFlags] "ContainerInherit, ObjectInherit"
            Propagation = [System.Security.AccessControl.PropagationFlags]::None
            ControlType = [System.Security.AccessControl.AccessControlType]::Allow
        }
        $SID_CreatorOwner = @{
            Rights      = [System.Security.AccessControl.FileSystemRights]::FullControl
            Inheritance = [System.Security.AccessControl.InheritanceFlags] "ContainerInherit, ObjectInherit"
            Propagation = [System.Security.AccessControl.PropagationFlags]::InheritOnly
            ControlType = [System.Security.AccessControl.AccessControlType]::Allow
        }
        $SID_AuthUsers = @{
            Rights      = [System.Security.AccessControl.FileSystemRights] "ReadAndExecute, Synchronize"
            Inheritance = [System.Security.AccessControl.InheritanceFlags] "ContainerInherit, ObjectInherit"
            Propagation = [System.Security.AccessControl.PropagationFlags]::None
            ControlType = [System.Security.AccessControl.AccessControlType]::Allow
        }
    }

    Write-Host "==> Ajustando NTFS..." -ForegroundColor Cyan
    Ensure-NTFS -Path $sysvolPath -DesiredAcl $desiredAcl
    Ensure-NTFS -Path $domainRoot -DesiredAcl $desiredAcl
    Ensure-NTFS -Path $scriptsPath -DesiredAcl $desiredAcl

    Write-Host "==> Validando/ajustando compartilhamentos..." -ForegroundColor Cyan
    # Cria/ajusta shares (com Caching=None quando suportado)
    NewOrFix-SmbShare -Name 'SYSVOL'   -Path $sysvolPath  | Out-Null
    NewOrFix-SmbShare -Name 'NETLOGON' -Path $scriptsPath | Out-Null

    # Permissões dos shares
    $fullShareSids = @($SID_Administrators, $SID_SYSTEM)
    $readShareSids = @($SID_AuthUsers)

    Ensure-SmbShareAccess -Name 'SYSVOL'   -FullSidList $fullShareSids -ReadSidList $readShareSids
    Ensure-SmbShareAccess -Name 'NETLOGON' -FullSidList $fullShareSids -ReadSidList $readShareSids

    # Status SysVolReady (diagnóstico)
    $regPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'
    $ready = (Get-ItemProperty -Path $regPath -Name 'SysVolReady' -ErrorAction SilentlyContinue).SysVolReady
    if ($null -ne $ready) { Write-Host ("SysVolReady        : {0}" -f $ready) }

    Write-Host ""
    Write-Host "   Concluído. SYSVOL/NETLOGON corrigidos conforme boas práticas." -ForegroundColor Green
    Write-Host "   Shares -> Full: Administrators,SYSTEM | Read: Authenticated Users | Caching: None (se suportado)"
    Write-Host "   NTFS  -> Admin/SYSTEM Full; CREATOR OWNER Full (herdado); Authenticated Users Read+Execute"

} catch {
    Write-Error "Falha: $($_.Exception.Message)"
    throw
}
