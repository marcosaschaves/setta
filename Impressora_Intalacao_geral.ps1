# ==========================================================
# 1. LISTA MESTRA DE USUÁRIOS E SENHAS (Sua base de dados)
# ==========================================================
$UserDatabase = @{
    "andrchaves"         = @{ srvUser = "andre";             srvPass = 'Setta!' }
    "administracao"       = @{ srvUser = "administracao";     srvPass = 'Setta!' }
    "alexandretavares"    = @{ srvUser = "alexandre";         srvPass = 'Setta!!' }
    "barbaramileyde"      = @{ srvUser = "Barbara.Mileyde";   srvPass = 'Setta!' }
    "biancasantos"        = @{ srvUser = "bianca";            srvPass = 'Setta@@26@' }
    "brauliobraz"         = @{ srvUser = "braulio";           srvPass = 'Setta!' }
    "brunasilva"          = @{ srvUser = "bruna.silva";       srvPass = 'Setta!@25' }
    "brunoteixeira"       = @{ srvUser = "bruno.teixeira";    srvPass = 'Setta!@' }
    "cristianagama"       = @{ srvUser = "cristiana.gama";    srvPass = 'Setta!' }
    "emersonfelipesoares" = @{ srvUser = "Emerson.Felipe";    srvPass = 'Setta14' }
    "fabianamichelle"     = @{ srvUser = "fabiana";           srvPass = 'Setta!' }
    "felipecattaneo"      = @{ srvUser = "felipe.cattaneo";   srvPass = 'Setta@log25' }
    "fernandomagalhaes"   = @{ srvUser = "fernando.magalhaes"; srvPass = 'Setta!' }
    "gilmasampaio"        = @{ srvUser = "Gilma";             srvPass = 'Setta@2626!' }
    "janainacavalvanti"   = @{ srvUser = "janaina.cavalcanti"; srvPass = 'Setta@2626!' }
    "jessicamoraes"       = @{ srvUser = "jessica.moraes";    srvPass = 'Setta!' }
    "johnnylyon"          = @{ srvUser = "Johnny.Lyon";       srvPass = 'Setta!123' }
    "julianaferraz"       = @{ srvUser = "juliana.ferraz";    srvPass = 'Setta!22$FR1' }
    "juridico"            = @{ srvUser = "juridico";          srvPass = 'Jur@Setta!' }
    "kaiocosta"           = @{ srvUser = "kaio.costa";        srvPass = 'Setta@log' }
    "kallynesales"        = @{ srvUser = "Kallyne.sales";     srvPass = 'Setta!' }
    "kelenmoraes"         = @{ srvUser = "kelen.moraes";      srvPass = 'Setta!' }
    "leticiabarros"       = @{ srvUser = "leticia";           srvPass = 'Setta!' }
    "lucasoliveira"       = @{ srvUser = "lucas.oliveira";    srvPass = 'Setta!' }
    "lucianavilar"        = @{ srvUser = "luciana.vilar";     srvPass = 'Setta!' }
    "luispetribu"         = @{ srvUser = "luis.petribu";      srvPass = 'Setta25@' }
    "mariaelena"          = @{ srvUser = "Elena";             srvPass = 'Setta!' }
    "nichellievangelista" = @{ srvUser = "NICHELLI";          srvPass = 'Setta01' }
    "niltonnascimento"    = @{ srvUser = "nilton.nascimento"; srvPass = 'Setta!' }
    "paulopereira"        = @{ srvUser = "Paulo";             srvPass = 'Setta2099' }
    "paulosergio"         = @{ srvUser = "paulo.sergio";      srvPass = 'Setta@log' }
    "prendsoncorreia"     = @{ srvUser = "prendson";          srvPass = 'Setta!!' }
    "rafaelavieira"       = @{ srvUser = "rafaela.vieira";    srvPass = 'Setta!' }
    "raquelprimo"         = @{ srvUser = "RAQUEL";            srvPass = 'Setta!' }
    "rebecauchoa"         = @{ srvUser = "rebeca.uchoa";      srvPass = 'Alvorada!' }
    "renatosantos"        = @{ srvUser = "renato";            srvPass = 'Setta!25' }
    "sergionascimento"    = @{ srvUser = "sergio.nascimento"; srvPass = 'Se@123642@#' }
    "sergiooliveira"      = @{ srvUser = "sergio.oliveira";   srvPass = 'Setta!log' }
    "thaynarosa"          = @{ srvUser = "thayna.rosa";       srvPass = 'Setta!' }
    "wandersonsilva"      = @{ srvUser = "wanderson.silva";   srvPass = 'Setta@log' }
    "yslarielesales"      = @{ srvUser = "Yslariele.sales";   srvPass = 'Setta@!' }
}

# ==========================================================
# 2. CONFIGURAÇÕES FIXAS
# ==========================================================
$ServerIP   = "10.3.116.18"
$Printer    = "\\10.3.116.18\setta-01"

# Identificação Automática do Usuário Logado
$rawUser = $env:USERNAME.ToLower()
$localKey = $rawUser -replace '[^a-z0-9]', '' # Transforma andre.chaves em andrechaves

# 3. VERIFICAÇÃO NA LISTA
if ($UserDatabase.ContainsKey($localKey)) {
    $UserName = $UserDatabase[$localKey].srvUser
    $Password = $UserDatabase[$localKey].srvPass
} else {
    Write-Host "Usuário [$localKey] não encontrado na lista. Abortando." -ForegroundColor Red
    exit
}

# 4. CONFIGURAÇÃO DE LOG (Baseado no seu script)
$logPath = "C:\Temp"
$logFile = "$logPath\Log_Setup_$UserName.txt"
if (!(Test-Path $logPath)) { New-Item -ItemType Directory -Path $logPath -Force | Out-Null }

function Write-Log {
    param ([string]$Message, [string]$Status = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "[$timestamp] [$Status] - $Message" | Out-File -FilePath $logFile -Append -Encoding UTF8
    Write-Host "[$Status] $Message"
}

Write-Log "--- INÍCIO DO SCRIPT ($UserName) ---"

# 5. INJETAR CREDENCIAL NO GERENCIADOR
try {
    Write-Log "Limpando credenciais antigas e adicionando novas..."
    cmdkey /delete:$ServerIP 2>$null
    cmdkey /add:$ServerIP /user:$UserName /pass:$Password
    Write-Log "Credencial registrada com sucesso." "SUCCESS"
} catch {
    Write-Log "Erro ao registrar cmdkey: $_" "ERROR"
}

# 6. FORÇAR AUTENTICAÇÃO IPC$ (Seu "Segredo")
try {
    Write-Log "Estabelecendo sessão de rede com o servidor..."
    net use "\\$ServerIP\IPC$" /user:$UserName $Password /persistent:no
    Write-Log "Sessão estabelecida." "SUCCESS"
} catch {
    Write-Log "Falha na pré-autenticação: $_" "WARNING"
}

# 7. REMOVER IMPRESSORA "LOCAL" (Se existir)
try {
    if (Get-Printer -Name "LOCAL" -ErrorAction SilentlyContinue) {
        Remove-Printer -Name "LOCAL"
        Write-Log "Impressora 'LOCAL' removida." "SUCCESS"
    }
} catch { Write-Log "Erro ao remover LOCAL: $_" "ERROR" }

# 8. INSTALAR NOVA IMPRESSORA
try {
    $existing = Get-Printer -Name $Printer -ErrorAction SilentlyContinue
    if (-not $existing) {
        Write-Log "Instalando $Printer..."
        Add-Printer -ConnectionName $Printer
        Start-Sleep -Seconds 5
        Write-Log "Impressora instalada." "SUCCESS"
    } else {
        Write-Log "Impressora já instalada." "INFO"
    }

    # 9. DEFINIR COMO PADRÃO
    Write-Log "Definindo como padrão..."
    $escaped = $Printer.Replace('\', '\\')
    $wmiPrinter = Get-CimInstance -Class Win32_Printer -Filter "Name = '$escaped'"
    if ($wmiPrinter) {
        Invoke-CimMethod -InputObject $wmiPrinter -MethodName SetDefaultPrinter | Out-Null
        Write-Log "Definida como padrão com sucesso." "SUCCESS"
    }
} catch {
    Write-Log "Falha na etapa final: $($_.Exception.Message)" "ERROR"
}

# LIMPEZA
net use "\\$ServerIP\IPC$" /delete /y 2>$null
Write-Log "--- SCRIPT FINALIZADO ---"