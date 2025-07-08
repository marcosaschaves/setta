# --- Criar diretório de log ---
$logDir = "C:\Users\Public\Scripts"
if (-not (Test-Path $logDir)) {
    New-Item -Path $logDir -ItemType Directory -Force | Out-Null
}
$logFile = Join-Path $logDir "seguranca_log.txt"
Add-Content -Path $logFile -Value "[$(Get-Date)] Início da execução" -Encoding UTF8

# Verifica se o processo avp.exe (Kaspersky) está rodando
$procKaspersky = Get-Process -Name "avp" -ErrorAction SilentlyContinue

if ($procKaspersky) {
    $kavStatus = "Protegido"
    $kavNome = "Kaspersky (via processo)"
} elseif ($kaspersky) {
    # fallback para o método WMI se o processo não estiver rodando
    if ($kaspersky.productState -band 0x10) {
        $kavStatus = "Protegido"
    } else {
        $kavStatus = "Parado"
    }
    $kavNome = $kaspersky.displayName
} else {
    $kavStatus = "Não encontrado"
    $kavNome = "-"
}


# --- Windows Defender ---
try {
    $defender = Get-MpComputerStatus
    if ($defender.AntivirusEnabled -and $defender.AntispywareEnabled) {
        $defenderStatus = "Ativo"
    } else {
        $defenderStatus = "Desativado"
    }
} catch {
    $defenderStatus = "Indefinido"
}

# --- Firewall ---
$fwPerfis = Get-NetFirewallProfile | Where-Object { $_.Enabled -eq "True" }
if ($fwPerfis.Count -ge 1) {
    $firewallStatus = "Ativo"
} else {
    $firewallStatus = "Desativado"
}

# --- Gerenciador do Firewall ---
try {
    $fwProd = Get-CimInstance -Namespace root/SecurityCenter2 -Class FirewallProduct |
              Select-Object -First 1 -ExpandProperty displayName
    if ($fwProd -like "*Kaspersky*") {
        $gerenciadorFirewall = "Kaspersky"
    } elseif ($fwProd -like "*Windows*") {
        $gerenciadorFirewall = "Windows"
    } else {
        $gerenciadorFirewall = "Indefinido"
    }
} catch {
    $gerenciadorFirewall = "Indefinido"
}

# --- Versão do Windows ---
$versao = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").DisplayVersion
if ($versao) {
    $winVer = "Windows 11 $versao"
} else {
    $winVer = "Desconhecido"
}

# --- Serial e usuário logado ---
$serial = (Get-CimInstance Win32_BIOS).SerialNumber
try {
    $userWMI = (Get-WmiObject Win32_ComputerSystem).UserName
    if ($userWMI) {
        $usuario = $userWMI.Split('\')[-1]
    } else {
        $usuario = $env:USERNAME
    }
} catch {
    $usuario = $env:USERNAME
}

# --- BitLocker com verificação de permissão ---
$bitlockerStatus = "Indefinido"
$adminCheck = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent() `
).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")

if ($adminCheck) {
    try {
        $bl = Get-BitLockerVolume -MountPoint "C:"
        if ($bl.ProtectionStatus -eq 1) {
            $bitlockerStatus = "Ativo"
        } else {
            $bitlockerStatus = "Inativo"
        }
    } catch {
        $bitlockerStatus = "Não aplicado"
    }
} else {
    $bitlockerStatus = "Permissão insuficiente"
}

# --- Uptime ---
try {
    $inicio = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
    $tempo = New-TimeSpan -Start $inicio
    $uptimeFormatado = "$($tempo.Days) dias, $($tempo.Hours) horas"
} catch {
    $uptimeFormatado = "Indefinido"
}

# --- Atualizações do Windows ---
try {
    $qtd = (Get-WmiObject -Class Win32_QuickFixEngineering | Measure-Object).Count
    if ($qtd -gt 0) {
        $windowsUpdateStatus = "Atualizado"
    } else {
        $windowsUpdateStatus = "Possivelmente desatualizado"
    }
} catch {
    $windowsUpdateStatus = "Indefinido"
}

# --- Corpo do envio ---
$data = @{
    hostname             = $env:COMPUTERNAME
    usuario_logado       = $usuario
    numero_serie         = $serial
    kaspersky_nome       = $kavNome
    kaspersky_status     = $kavStatus
    defender_status      = $defenderStatus
    firewall_status      = $firewallStatus
    gerenciador_firewall = $gerenciadorFirewall
    versao_windows       = $winVer
    bitlocker_status     = $bitlockerStatus
    tempo_atividade      = $uptimeFormatado
    windows_update       = $windowsUpdateStatus
}

# --- Log dos dados enviados ---
Add-Content -Path $logFile -Value "--- Dados enviados ---" -Encoding UTF8
$data.GetEnumerator() | Sort-Object Name | ForEach-Object {
    Add-Content -Path $logFile -Value "$($_.Name): $($_.Value)" -Encoding UTF8
}

# --- Envia para API ---
try {
    Invoke-RestMethod -Uri "http://10.3.117.81/glpi_lite/api/receber_seg_data.php" -Method POST -Body $data
    Add-Content -Path $logFile -Value "[$(Get-Date)] ? Enviado com sucesso para $($data.hostname)" -Encoding UTF8
} catch {
    Add-Content -Path $logFile -Value "[$(Get-Date)] ? ERRO: $($_.Exception.Message)" -Encoding UTF8
}