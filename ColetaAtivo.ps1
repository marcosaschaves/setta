# =================================================================
# 🧱 Coleta de HARDWARE e SOFTWARE para Microsoft Intune
# =================================================================
# Este script coleta informações de hardware e software e envia para a API.
# Projetado para ser executado como um script de remediação no Microsoft Intune.
# O script irá retornar um código de saída 0 para sucesso e 1 para falha.
# =================================================================

# Define o caminho do log para fácil depuração no Intune
$logDirPath = "C:\ProgramData\Koppieti"
$logFilePath = "$logDirPath\HardwareInventory.log"

# NOVO: Verifica e cria o diretório de log se ele não existir
if (-not (Test-Path -Path $logDirPath)) {
    try {
        New-Item -ItemType Directory -Path $logDirPath -Force | Out-Null
    } catch {
        # Se a criação falhar, o script continuará, mas o log não será gravado no arquivo
        Write-Output "❌ Erro fatal: Não foi possível criar o diretório de log em '$logDirPath'. Erro: $($_.Exception.Message)"
    }
}

# Define uma função de log que também escreve para o arquivo de log
function Write-Log {
    Param(
        [Parameter(Mandatory=$true)]
        [string]$message,
        [string]$level = "INFO"
    )
    $logEntry = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$level] $message"
    Write-Output $logEntry
    try {
        Add-Content -Path $logFilePath -Value $logEntry
    } catch {
        # Em caso de falha no log, apenas imprime na tela.
        Write-Output "❌ Erro ao escrever no log: $($_.Exception.Message)"
    }
}

# Define o nível de ação de erro e a política de execução para garantir que o script funcione
$ErrorActionPreference = "Stop"
try {
    Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force
} catch {
    Write-Log -message "Falha ao definir a política de execução, mas continuando. Erro: $($_.Exception.Message)" -level "WARN"
}

# URL da API para envio dos dados de hardware e software combinados
$API_URL = "http://10.3.117.81:81/koppieti/api/inv_receber_dados.php"

# =================================================================
# LÓGICA PRINCIPAL DO SCRIPT
# =================================================================
try {
    # Inicializa variáveis para evitar erros de objeto nulo
    $so = $null
    $equipamento = $null
    $bios = $null
    $baseBoard = $null
    $discosRaw = $null
    $processor = $null

    Write-Log -message "Iniciando a coleta de inventário..."

    try {
        $ultimoLogon = (Get-WmiObject -Class Win32_LogonSession -Filter "LogonType = 2" | Sort-Object StartTime -Descending | Select-Object -First 1).StartTime
        $ultimo_login = [System.Management.ManagementDateTimeConverter]::ToDateTime($ultimoLogon)
    } catch {
        $ultimo_login = Get-Date
        Write-Log -message "Não foi possível coletar a data do último logon. Usando a data atual." -level "WARN"
    }

    # --- Coleta de Hardware ---
    try {
        Write-Log -message "Coletando informações de hardware..."
        # Garante que os objetos WMI sejam coletados, ou permaneçam nulos em caso de falha
        $so = Get-WmiObject Win32_OperatingSystem
        $equipamento = Get-WmiObject Win32_ComputerSystem
        $bios = Get-WmiObject Win32_BIOS
        $baseBoard = Get-WmiObject Win32_BaseBoard
        $discosRaw = Get-PhysicalDisk
        $processor = Get-WmiObject Win32_Processor
        $monitors = Get-WmiObject -Class Win32_DesktopMonitor
        $videoController = Get-WmiObject -Class Win32_VideoController
        $memorySticks = Get-WmiObject -Class Win32_PhysicalMemory
        $memoryArray = Get-WmiObject -Class Win32_PhysicalMemoryArray

        # Função auxiliar para verificar e retornar valores, evitando erros de objeto nulo
        function Get-Value($obj, $property, $defaultValue = $null) {
            if ($obj -and $obj.$property) {
                return $obj.$property
            }
            return $defaultValue
        }

        # --- Coleta das informações de hardware faltantes ---
        # Coleta de Monitores
        $activeMonitors = Get-WmiObject -Class Win32_DesktopMonitor | Where-Object { $_.MonitorStatus -eq 1 }
        $quantidadeMonitores = $activeMonitors.Count
        
        # Coleta a resolução da tela principal
        $resolucaoTela = "N/A"
        foreach ($vc in $videoController) {
            if ($vc.CurrentHorizontalResolution -gt 0 -and $vc.CurrentVerticalResolution -gt 0) {
                $resolucaoTela = "$($vc.CurrentHorizontalResolution) x $($vc.CurrentVerticalResolution)"
                break
            }
        }
        Write-Log -message "Resolução da tela: $resolucaoTela"

        # Coleta o modelo do monitor
        $modeloMonitor = "N/A"
        if ($monitors -and $monitors.Count -gt 0) {
            $modeloMonitor = ($monitors | Select-Object -ExpandProperty Name) -join ' / '
        }
        
        # Coleta de CPU
        $clockCpu = Get-Value $processor 'MaxClockSpeed'
        $nucleosCpu = Get-Value $processor 'NumberOfCores'
        $temperaturaCpu = "N/A"
        try {
            $tempWMI = (Get-WmiObject -Namespace root\WMI -Class MSAcpi_ThermalZoneTemperature).CurrentTemperature
            if ($tempWMI -and ($tempWMI | Select-Object -First 1) -gt 0) {
                $tempValue = ($tempWMI | Select-Object -First 1)
                $temperaturaCpu = [math]::Round(($tempValue / 10) - 273.15, 2)
            }
        } catch {
            Write-Log -message "Não foi possível coletar a temperatura da CPU." -level "WARN"
            $temperaturaCpu = "N/A"
        }
        Write-Log -message "Temperatura da CPU: $temperaturaCpu °C"

        # Coleta de Memória RAM
        $pentesMemoria = $memorySticks.Count
        $slotsDisponiveis = $memoryArray.MemoryDevices - $pentesMemoria
        
        # Coleta de Plano de Energia
        $planoEnergia = "N/A"
        try {
            $powerConfig = (powercfg /getactivescheme | Out-String).Trim()
            if ($powerConfig -match '\((.*)\)') {
                $planoEnergia = $matches[1]
            }
        } catch {
            Write-Log -message "Não foi possível coletar o plano de energia." -level "WARN"
            $planoEnergia = "N/A"
        }
        Write-Log -message "Plano de energia: $planoEnergia"
        
        # Coleta o tipo de dispositivo (Notebook ou Desktop)
        $tipoDispositivo = "Desktop"
        if ($equipamento.PCSystemType -eq 2) {
            $tipoDispositivo = "Notebook"
        }
        Write-Log -message "Tipo de dispositivo: $tipoDispositivo"

        # Objeto de Hardware (Ajustado para corresponder à consulta do script PHP)
        $hardwareData = [PSCustomObject]@{
            data_coleta             = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
            nome_maquina            = $env:COMPUTERNAME
            usuario_logado          = "$env:USERNAME@$(Get-Value $equipamento 'Domain')"
            tipo_dispositivo        = $tipoDispositivo
            quantidade_monitores    = $quantidadeMonitores
            resolucao_tela          = $resolucaoTela
            versao_bios             = Get-Value $bios 'SMBIOSBIOSVersion'
            data_bios               = [datetime]::ParseExact((Get-Value $bios 'ReleaseDate' '19700101').Substring(0,8), 'yyyyMMdd', $null).ToString('yyyy-MM-dd HH:mm:ss')
            data_criacao_windows    = [datetime]::ParseExact((Get-Value $so 'InstallDate' '19700101').Substring(0,8), 'yyyyMMdd', $null).ToString('yyyy-MM-dd HH:mm:ss')
            ram_total_gb            = [math]::Round((Get-Value $equipamento 'TotalPhysicalMemory' 0) / 1GB, 0)
            pentes_memoria          = $pentesMemoria
            slots_disponiveis       = $slotsDisponiveis
            temperatura_cpu         = $temperaturaCpu
            os                      = Get-Value $so 'Caption'
            versao_os               = Get-Value $so 'Version'
            plano_energia           = $planoEnergia
            modelo_cpu              = Get-Value (Get-WmiObject Win32_Processor) 'Name'
            clock_cpu               = $clockCpu
            nucleos_cpu             = $nucleosCpu
            tag                     = Get-Value (Get-WmiObject Win32_SystemEnclosure) 'SMBIOSAssetTag'
            serial                  = Get-Value $bios 'SerialNumber'
            modelo_monitor          = $modeloMonitor
            fabricante_placa_mae    = Get-Value $baseBoard 'Manufacturer'
            modelo_placa_mae        = Get-Value $baseBoard 'Product'
        }
        Write-Log -message "Coleta de hardware concluída."
    } catch {
        Write-Log -message "❌ Erro grave na coleta de hardware: $($_.Exception.Message)" -level "ERROR"
        exit 1
    }


    # ==========================
    # 📦 Coleta de SOFTWARE
    # ==========================
    $dataHora = Get-Date
    $softwares = @()
    $coletados = @{}
    $regPaths = @(
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )

    Write-Log -message "Iniciando a coleta de software..."
    foreach ($path in $regPaths) {
        try {
            $apps = Get-ItemProperty $path -ErrorAction SilentlyContinue |
                Where-Object { $_.DisplayName -and $_.DisplayVersion }
            foreach ($app in $apps) {
                $chave = "$($app.DisplayName)|$($app.DisplayVersion)"
                if (-not $coletados.ContainsKey($chave)) {
                    $dataInstalacao = ""
                    try {
                        if ($app.PSObject.Properties['InstallDate']) {
                            $raw = "$($app.InstallDate)"
                            if ($raw -match '^\d{8}$') {
                                $dataInstalacao = [datetime]::ParseExact($raw, 'yyyyMMdd', $null).ToString('yyyy-MM-dd')
                            }
                        }
                    } catch { $dataInstalacao = "" }

                    $softwares += [PSCustomObject]@{
                        nome_maquina        = $env:COMPUTERNAME
                        data_coleta         = $dataHora.ToString('yyyy-MM-dd HH:mm:ss')
                        nome_programa       = $app.DisplayName
                        versao_programa     = $app.DisplayVersion
                        tamanho_programa    = $null
                        data_instalacao     = $dataInstalacao
                        fabricante_programa = $app.Publisher
                    }
                    $coletados[$chave] = $true
                }
            }
        } catch {
            Write-Log -message "❌ Erro ao coletar software no registro ${path}: $($_.Exception.Message)" -level "ERROR"
        }
    }
    Write-Log -message "Coleta de software concluída. Coletados $($softwares.Count) programas."

    # ==========================
    # 📤 Envio para API
    # ==========================

    $headers = @{
        "User-Agent" = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3"
    }

    $payload = @{
        hardware = $hardwareData
        software = $softwares
    }

    Write-Log -message "Iniciando envio de dados completos para a API..."
    $json = $payload | ConvertTo-Json -Depth 6
    $bodyBytes = [System.Text.Encoding]::UTF8.GetBytes($json)

    $response = Invoke-RestMethod -Uri $API_URL -Method Post -Body $bodyBytes -ContentType "application/json" -Headers $headers -Verbose
    Write-Log -message "✅ Coleta de inventário enviada com sucesso para a API."
    Write-Log -message "Resposta do servidor: $response"

    # Em caso de sucesso, o script retorna 0
    exit 0
} catch {
    Write-Log -message "❌ Erro fatal no script: $($_.Exception.Message)" -level "FATAL"
    # Em caso de falha, o script retorna 1
    exit 1
}
