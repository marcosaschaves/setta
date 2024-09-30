<#
    IntunePaper | Jornada 365
    Script para aplicar papel de parede e tela de bloqueio via Intune.
    Adaptado para funcionar corretamente no Microsoft Intune em Windows 10 e 11 Pro
    Autor: Sergio Sant'Ana Junior
    Versao: 4.1
    Compativel com PowerShell 5.x e 7.x, Windows 10 e Windows 11
    Ultima modificacao: 04/09/2024
#>

# ============================ CONFIGURACOES ============================
$directoryPath = "C:\users\Public\Pictures\Intune"
$wallpaperUrl = "https://raw.githubusercontent.com/marcosaschaves/setta/main/wallpaper_out.png"
$lockScreenUrl = "https://raw.githubusercontent.com/marcosaschaves/setta/main/lockscreen_out.png"
$wallpaperPath = "$directoryPath\wallpaper_out.png"
$lockScreenPath = "$directoryPath\lockscreen_out.png"
$lockScreenRegKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization"
$RegKeyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\PersonalizationCSP"
$spotlightRegKey = "HKLM:\Software\Policies\Microsoft\Windows\CloudContent"
$logFile = "C:\ProgramData\IntuneWallpaperLog.txt" # Caminho do arquivo de log
$maxRetries = 3
$retryDelay = 5

# Valores para o registro
$DesktopStatus = "DesktopImageStatus"
$LockScreenStatus = "LockScreenImageStatus"
$DesktopPathReg = "DesktopImagePath"
$DesktopUrlReg = "DesktopImageUrl"
$LockScreenPathReg = "LockScreenImagePath"
$LockScreenUrlReg = "LockScreenImageUrl"
$StatusValue = 1
$DesktopImageValue = $wallpaperPath
$LockScreenImageValue = $lockScreenPath

# ============================ FUNCOES ============================

# Funcao para registrar logs no arquivo de log
function Log-Message {
    param (
        [string]$message
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "$timestamp - $message"
    Add-Content -Path $logFile -Value $logEntry
}

# Funcao para garantir a criacao do diretorio e baixar as imagens de forma robusta
function Ensure-DirectoryAndDownloadImages {
    if (-Not (Test-Path -Path $directoryPath)) {
        New-Item -Path $directoryPath -ItemType Directory -Force
        Log-Message "Diretorio criado: $directoryPath"
    } else {
        Log-Message "Diretorio ja existe: $directoryPath"
    }

    # Remover imagens existentes, se necessario
    if (Test-Path -Path $wallpaperPath) { Remove-Item -Path $wallpaperPath -Force }
    if (Test-Path -Path $lockScreenPath) { Remove-Item -Path $lockScreenPath -Force }

    # Tentar baixar as imagens
    try {
        Log-Message "Baixando imagens de papel de parede e tela de bloqueio..."
        Invoke-WebRequest -Uri $wallpaperUrl -OutFile $wallpaperPath -UseBasicParsing
        Invoke-WebRequest -Uri $lockScreenUrl -OutFile $lockScreenPath -UseBasicParsing

        if (-Not (Test-Path -Path $wallpaperPath)) { throw "Erro ao baixar o papel de parede." }
        if (-Not (Test-Path -Path $lockScreenPath)) { throw "Erro ao baixar a tela de bloqueio." }

        Log-Message "Imagens baixadas com sucesso."
    } catch {
        Log-Message "Erro ao baixar as imagens: $_"
        exit 1
    }
}

# Funcao para desativar o Windows Spotlight
function Disable-WindowsSpotlight {
    Log-Message "Desativando Windows Spotlight..."

    # Verifica se a chave de registro existe, e cria se necessário
    if (-Not (Test-Path $spotlightRegKey)) {
        New-Item -Path $spotlightRegKey -Force | Out-Null
        Log-Message "Chave de registro criada: $spotlightRegKey"
    }

    # Desativar Windows Spotlight via registro
    Set-ItemProperty -Path $spotlightRegKey -Name 'DisableWindowsConsumerFeatures' -Value 1
    Set-ItemProperty -Path $spotlightRegKey -Name 'DisableWindowsSpotlightFeatures' -Value 1
    Set-ItemProperty -Path $spotlightRegKey -Name 'DisableWindowsSpotlightOnActionCenter' -Value 1
    Set-ItemProperty -Path $spotlightRegKey -Name 'DisableWindowsSpotlightOnLockScreen' -Value 1
    Set-ItemProperty -Path $spotlightRegKey -Name 'DisableWindowsSpotlightSuggestions' -Value 1
    Log-Message "Windows Spotlight desativado."
}

# Funcao para forcar a atualizacao do papel de parede usando a API do Windows
function Force-WallpaperUpdate {
    Add-Type @"
    using System;
    using System.Runtime.InteropServices;
    public class Wallpaper {
        [DllImport("user32.dll", CharSet = CharSet.Auto)]
        public static extern int SystemParametersInfo(int uAction, int uParam, string lpvParam, int fuWinIni);
        public const int SPI_SETDESKWALLPAPER = 20;
        public const int SPIF_UPDATEINIFILE = 0x01;
        public const int SPIF_SENDCHANGE = 0x02;
    }
"@
    [Wallpaper]::SystemParametersInfo([Wallpaper]::SPI_SETDESKWALLPAPER, 0, $wallpaperPath, [Wallpaper]::SPIF_UPDATEINIFILE -bor [Wallpaper]::SPIF_SENDCHANGE)
    Log-Message "Papel de parede atualizado via API do Windows."
}

# Funcao para garantir que a chave de registro Personalization exista
function Ensure-PersonalizationRegKey {
    if (-Not (Test-Path $lockScreenRegKey)) {
        New-Item -Path $lockScreenRegKey -Force | Out-Null
        Log-Message "Chave de registro criada: $lockScreenRegKey"
    } else {
        Log-Message "Chave de registro já existe: $lockScreenRegKey"
    }
}

# Funcao para aplicar o papel de parede via registro do Windows
function Apply-WallpaperRegistry {
    Ensure-PersonalizationRegKey  # Verifica se a chave de Personalization existe

    for ($i = 0; $i -lt $maxRetries; $i++) {
        try {
            Log-Message "Aplicando papel de parede via registro (Tentativa $($i+1) de $maxRetries)..."
            
            # Definir o papel de parede no registro
            Set-ItemProperty -Path $lockScreenRegKey -Name 'WallPaper' -Value $wallpaperPath

            # Forçar a atualização do papel de parede
            Force-WallpaperUpdate
            Start-Sleep -Seconds 2
            Log-Message "Papel de parede aplicado com sucesso via registro do Windows."

            break
        } catch {
            Log-Message "Erro ao aplicar o papel de parede via registro: $_"
            if ($i -lt $maxRetries - 1) { Start-Sleep -Seconds $retryDelay }
            else { Log-Message "Falha ao aplicar o papel de parede apos $maxRetries tentativas."; exit 1 }
        }
    }
}

# Funcao para aplicar a tela de bloqueio via registro
function Apply-LockScreen {
    Ensure-PersonalizationRegKey  # Verifica se a chave de Personalization existe

    for ($i = 0; $i -lt $maxRetries; $i++) {
        try {
            Log-Message "Aplicando tela de bloqueio (Tentativa $($i+1) de $maxRetries)..."

            # Aplicar a tela de bloqueio via reg.exe
            & reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization" /v LockScreenImage /t REG_SZ /d $lockScreenPath /f
            & reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization" /v LockScreenOverlayImage /t REG_SZ /d $lockScreenPath /f

            Log-Message "Tela de bloqueio aplicada via registro do Windows."

            break
        } catch {
            Log-Message "Erro ao aplicar a tela de bloqueio: $_"
            if ($i -lt $maxRetries - 1) { Start-Sleep -Seconds $retryDelay }
            else { Log-Message "Falha ao aplicar a tela de bloqueio apos $maxRetries tentativas."; exit 1 }
        }
    }

    Log-Message "Aplicacao da tela de bloqueio concluida."
}

# Funcao para aplicar configuracoes no registro HKLM\PersonalizationCSP
function Apply-RegistrySettings {
    Log-Message "Aplicando configuracoes no registro PersonalizationCSP..."

    if (-Not (Test-Path -Path $RegKeyPath)) {
        New-Item -Path $RegKeyPath -Force | Out-Null
        Log-Message "Caminho de registro criado: $RegKeyPath"
    }

    New-ItemProperty -Path $RegKeyPath -Name $DesktopStatus -Value $StatusValue -PropertyType DWORD -Force | Out-Null
    New-ItemProperty -Path $RegKeyPath -Name $LockScreenStatus -Value $StatusValue -PropertyType DWORD -Force | Out-Null
    New-ItemProperty -Path $RegKeyPath -Name $DesktopPathReg -Value $DesktopImageValue -PropertyType STRING -Force | Out-Null
    New-ItemProperty -Path $RegKeyPath -Name $DesktopUrlReg -Value $DesktopImageValue -PropertyType STRING -Force | Out-Null
    New-ItemProperty -Path $RegKeyPath -Name $LockScreenPathReg -Value $LockScreenImageValue -PropertyType STRING -Force | Out-Null
    New-ItemProperty -Path $RegKeyPath -Name $LockScreenUrlReg -Value $LockScreenImageValue -PropertyType STRING -Force | Out-Null

    Log-Message "Configuracoes aplicadas no registro PersonalizationCSP com sucesso."
}

# Funcao para verificar e instalar a Intune Management Extension (IME)
function Ensure-IntuneManagementExtension {
    Log-Message "Verificando Intune Management Extension..."
    $imePath = "C:\Program Files (x86)\Microsoft Intune Management Extension\agentexecutor.exe"
    if (-Not (Test-Path $imePath)) {
        Log-Message "Intune Management Extension nao encontrado. Instalando..."
        # Baixar e instalar a IME
        $imeUrl = "https://go.microsoft.com/fwlink/?linkid=2090973"
        $imeInstaller = "$env:TEMP\IntuneManagementExtension.msi"
        Invoke-WebRequest -Uri $imeUrl -OutFile $imeInstaller
        Start-Process msiexec.exe -ArgumentList "/i $imeInstaller /quiet /norestart" -Wait
        Remove-Item -Path $imeInstaller -Force
        Log-Message "Intune Management Extension instalado com sucesso."
    } else {
        Log-Message "Intune Management Extension ja esta instalada."
    }
}

# Funcao principal para executar o processo
function Main {
    Log-Message "Iniciando a aplicacao do papel de parede e tela de bloqueio..."
    Ensure-IntuneManagementExtension
    Disable-WindowsSpotlight
    Ensure-DirectoryAndDownloadImages
    Apply-WallpaperRegistry
    Apply-LockScreen
    Apply-RegistrySettings
    Log-Message "Processo concluido com sucesso. Papel de parede e tela de bloqueio aplicados."
}

# Executar a funcao principal
Main
