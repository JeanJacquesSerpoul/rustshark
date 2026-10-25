<#
.SYNOPSIS
    Installe RustShark sous Windows : prérequis, compilation et installation.

.DESCRIPTION
    1. Vérifie et installe si besoin les prérequis (outils C++ MSVC, Rust,
       cible WebAssembly, Trunk, CLI Tauri, Npcap).
    2. Compile l'application en mode release.
    3. Installe RustShark (installateur NSIS, ou copie portable).

    À lancer depuis une console PowerShell, à la racine du projet ou ailleurs :
        powershell -ExecutionPolicy Bypass -File scripts\install-windows.ps1

.PARAMETER Yes
    Répond « oui » à toutes les questions (installation sans interaction,
    sauf Npcap dont la licence gratuite impose l'installateur graphique).

.PARAMETER SkipPrereqs
    Ne vérifie pas les prérequis (déjà installés).

.PARAMETER BuildOnly
    Compile l'installateur sans l'exécuter.

.PARAMETER Portable
    Pas d'installateur : copie rustshark.exe dans %LOCALAPPDATA%\Programs\RustShark
    et crée un raccourci dans le menu Démarrer.

.PARAMETER Uninstall
    Désinstalle RustShark (et propose d'effacer réglages et clés API).
#>
[CmdletBinding()]
param(
    [switch]$Yes,
    [switch]$SkipPrereqs,
    [switch]$BuildOnly,
    [switch]$Portable,
    [switch]$Uninstall
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$Root = Split-Path -Parent $PSScriptRoot
$TargetDir = Join-Path $Root 'target'
if ($env:CARGO_TARGET_DIR) { $TargetDir = $env:CARGO_TARGET_DIR }
$AppName = 'RustShark'
$PortableDir = Join-Path $env:LOCALAPPDATA "Programs\$AppName"
$StartMenuLink = Join-Path $env:APPDATA "Microsoft\Windows\Start Menu\Programs\$AppName.lnk"
# Réglages : identifiant actuel, puis ancien identifiant.
$ConfigDirs = @(
    (Join-Path $env:APPDATA 'io.github.jeanjacquesserpoul.rustshark'),
    (Join-Path $env:APPDATA 'com.rustshark.app')
)

# ---------------------------------------------------------------------------
# Outils
# ---------------------------------------------------------------------------

function Write-Step([string]$Text) { Write-Host "`n==> $Text" -ForegroundColor Cyan }
function Write-Ok([string]$Text) { Write-Host "    [OK] $Text" -ForegroundColor Green }
function Write-Info([string]$Text) { Write-Host "    $Text" }
function Write-Warn([string]$Text) { Write-Host "    [!] $Text" -ForegroundColor Yellow }

function Confirm-Action([string]$Question) {
    if ($Yes) { return $true }
    $answer = Read-Host "    $Question [O/n]"
    return ($answer -eq '' -or $answer -match '^(o|oui|y|yes)$')
}

function Test-Command([string]$Name) {
    return [bool](Get-Command $Name -ErrorAction SilentlyContinue)
}

# Recharge le PATH après une installation (sans rouvrir la console).
function Update-SessionPath {
    $machine = [Environment]::GetEnvironmentVariable('Path', 'Machine')
    $user = [Environment]::GetEnvironmentVariable('Path', 'User')
    $env:Path = "$machine;$user;$env:USERPROFILE\.cargo\bin"
}

function Invoke-Checked([string]$Exe, [string[]]$Arguments) {
    & $Exe @Arguments
    if ($LASTEXITCODE -ne 0) { throw "La commande « $Exe $($Arguments -join ' ') » a échoué (code $LASTEXITCODE)." }
}

function Install-WithWinget([string]$Id, [string[]]$Extra = @()) {
    if (-not (Test-Command 'winget')) {
        throw "winget est introuvable. Installez « App Installer » depuis le Microsoft Store, ou installez $Id manuellement."
    }
    $wingetArgs = @('install', '--id', $Id, '-e', '--accept-package-agreements', '--accept-source-agreements') + $Extra
    Invoke-Checked 'winget' $wingetArgs
    Update-SessionPath
}

# ---------------------------------------------------------------------------
# Prérequis
# ---------------------------------------------------------------------------

function Test-MsvcTools {
    $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
    if (-not (Test-Path $vswhere)) { return $false }
    $path = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
    return [bool]$path
}

function Test-WebView2 {
    $guid = '{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}'
    $keys = @(
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\$guid",
        "HKLM:\SOFTWARE\Microsoft\EdgeUpdate\Clients\$guid",
        "HKCU:\SOFTWARE\Microsoft\EdgeUpdate\Clients\$guid"
    )
    foreach ($k in $keys) {
        $v = (Get-ItemProperty -Path $k -Name pv -ErrorAction SilentlyContinue).pv
        if ($v -and $v -ne '0.0.0.0') { return $true }
    }
    return $false
}

function Test-Npcap {
    return (Test-Path (Join-Path $env:SystemRoot 'System32\Npcap\wpcap.dll'))
}

function Install-Npcap {
    Write-Info "Npcap est le pilote de capture réseau (gratuit) utilisé par RustShark."
    Write-Info "Sa licence gratuite n'autorise pas l'installation silencieuse : l'installateur va s'ouvrir."
    if (-not (Confirm-Action 'Télécharger et lancer l''installateur Npcap ?')) {
        Write-Warn 'Npcap non installé : RustShark pourra ouvrir des fichiers, mais pas capturer en direct.'
        return
    }
    $url = $null
    try {
        $page = Invoke-WebRequest -Uri 'https://npcap.com/' -UseBasicParsing
        $m = [regex]::Match($page.Content, 'dist/npcap-[0-9.]+\.exe')
        if ($m.Success) { $url = "https://npcap.com/$($m.Value)" }
    } catch { }
    if (-not $url) {
        Write-Warn 'Version de Npcap introuvable automatiquement : ouverture de la page de téléchargement.'
        Start-Process 'https://npcap.com/#download'
        Read-Host '    Installez Npcap puis appuyez sur Entrée pour continuer'
        return
    }
    $file = Join-Path $env:TEMP (Split-Path $url -Leaf)
    Write-Info "Téléchargement de $url"
    Invoke-WebRequest -Uri $url -OutFile $file -UseBasicParsing
    $sig = Get-AuthenticodeSignature $file
    if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch 'Insecure\.Com') {
        Remove-Item $file -Force
        throw "La signature de l'installateur Npcap n'est pas valide ($($sig.Status)). Installation annulée."
    }
    Write-Info 'Installateur signé par Insecure.Com LLC : lancement (acceptez la demande d''administrateur)…'
    Start-Process -FilePath $file -Verb RunAs -Wait
    Remove-Item $file -Force -ErrorAction SilentlyContinue
    if (Test-Npcap) { Write-Ok 'Npcap installé' } else { Write-Warn 'Npcap ne semble pas installé.' }
}

function Install-Prerequisites {
    Write-Step 'Vérification des prérequis'

    if (Test-MsvcTools) {
        Write-Ok 'Outils de compilation C++ (MSVC)'
    } else {
        Write-Warn 'Les outils de compilation C++ de Microsoft sont absents (nécessaires à Rust).'
        if (-not (Confirm-Action 'Installer Visual Studio Build Tools 2022 (≈ 2 Go) ?')) { throw 'Outils MSVC requis.' }
        Install-WithWinget 'Microsoft.VisualStudio.2022.BuildTools' @('--override', '--wait --passive --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended')
        Write-Ok 'Build Tools installés'
    }

    Update-SessionPath
    if (Test-Command 'cargo') {
        Write-Ok "Rust ($((& rustc --version) -join ''))"
    } else {
        if (-not (Confirm-Action 'Rust est absent. L''installer avec rustup ?')) { throw 'Rust requis.' }
        Install-WithWinget 'Rustlang.Rustup'
        Invoke-Checked 'rustup' @('default', 'stable')
        Write-Ok 'Rust installé'
    }

    $targets = & rustup target list --installed
    if ($targets -contains 'wasm32-unknown-unknown') {
        Write-Ok 'Cible wasm32-unknown-unknown'
    } else {
        Invoke-Checked 'rustup' @('target', 'add', 'wasm32-unknown-unknown')
        Write-Ok 'Cible wasm32-unknown-unknown ajoutée'
    }

    if (Test-Command 'trunk') {
        Write-Ok "Trunk ($((& trunk --version) -join ''))"
    } else {
        Write-Info 'Installation de Trunk (quelques minutes)…'
        Invoke-Checked 'cargo' @('install', 'trunk', '--locked')
        Write-Ok 'Trunk installé'
    }

    $tauriVersion = & cargo tauri --version 2>$null
    if ($LASTEXITCODE -eq 0 -and $tauriVersion -match ' 2\.') {
        Write-Ok "CLI Tauri ($tauriVersion)"
    } else {
        Write-Info 'Installation de la CLI Tauri 2 (quelques minutes)…'
        Invoke-Checked 'cargo' @('install', 'tauri-cli', '--version', '^2', '--locked')
        Write-Ok 'CLI Tauri installée'
    }

    if (Test-WebView2) {
        Write-Ok 'WebView2'
    } else {
        Write-Warn 'WebView2 absent : l''installateur de RustShark le téléchargera automatiquement.'
    }

    if (Test-Npcap) { Write-Ok 'Npcap' } else { Install-Npcap }
}

# ---------------------------------------------------------------------------
# Compilation et installation
# ---------------------------------------------------------------------------

function Invoke-Build {
    Write-Step 'Compilation de RustShark (mode release, plusieurs minutes la première fois)'
    # Un RustShark lancé depuis le dossier de compilation verrouille l'exécutable.
    $releaseExe = Join-Path $TargetDir 'release\rustshark.exe'
    $running = Get-Process rustshark -ErrorAction SilentlyContinue | Where-Object { $_.Path -eq $releaseExe }
    if ($running) {
        throw "RustShark est ouvert depuis $releaseExe (PID $($running.Id -join ', ')). Fermez-le puis relancez le script."
    }
    # Trunk refuse NO_COLOR=1 (il attend true/false).
    if ($env:NO_COLOR) { $env:NO_COLOR = 'true' }
    Push-Location $Root
    try {
        if ($Portable) {
            Invoke-Checked 'cargo' @('tauri', 'build', '--no-bundle')
        } else {
            Invoke-Checked 'cargo' @('tauri', 'build', '--bundles', 'nsis')
        }
    } finally {
        Pop-Location
    }
    Write-Ok 'Compilation terminée'
}

function New-Shortcut([string]$Target, [string]$Link) {
    $shell = New-Object -ComObject WScript.Shell
    $s = $shell.CreateShortcut($Link)
    $s.TargetPath = $Target
    $s.WorkingDirectory = Split-Path $Target
    $s.Description = 'Analyseur de trafic réseau pour tous'
    $s.Save()
}

function Install-App {
    if ($Portable) {
        Write-Step "Installation portable dans $PortableDir"
        New-Item -ItemType Directory -Force $PortableDir | Out-Null
        $exe = Join-Path $PortableDir "$AppName.exe"
        Copy-Item (Join-Path $TargetDir 'release\rustshark.exe') $exe -Force
        New-Shortcut $exe $StartMenuLink
        Write-Ok "Raccourci créé dans le menu Démarrer : $AppName"
        return
    }
    $nsisDir = Join-Path $TargetDir 'release\bundle\nsis'
    $setup = Get-ChildItem $nsisDir -Filter '*-setup.exe' -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if (-not $setup) { throw "Installateur NSIS introuvable dans $nsisDir." }
    if ($BuildOnly) {
        Write-Step 'Installateur prêt'
        Write-Ok $setup.FullName
        return
    }
    Write-Step "Installation via $($setup.Name)"
    # /S = installation silencieuse (installateur NSIS de Tauri).
    if ($Yes) {
        $p = Start-Process -FilePath $setup.FullName -ArgumentList '/S' -Wait -PassThru
    } else {
        $p = Start-Process -FilePath $setup.FullName -Wait -PassThru
    }
    if ($p.ExitCode -ne 0) { throw "L'installateur a renvoyé le code $($p.ExitCode)." }
    Write-Ok 'RustShark est installé (menu Démarrer > RustShark)'
}

# ---------------------------------------------------------------------------
# Désinstallation
# ---------------------------------------------------------------------------

function Remove-App {
    Write-Step 'Désinstallation de RustShark'
    $found = $false
    $uninstallKeys = @(
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )
    $entries = Get-ItemProperty $uninstallKeys -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -like "$AppName*" }
    foreach ($e in $entries) {
        $found = $true
        $cmd = $e.QuietUninstallString
        if (-not $cmd) { $cmd = "$($e.UninstallString) /S" }
        Write-Info "Exécution : $cmd"
        Start-Process -FilePath 'cmd.exe' -ArgumentList '/c', $cmd -Wait
        Write-Ok "$($e.DisplayName) désinstallé"
    }
    if (Test-Path $PortableDir) {
        $found = $true
        Remove-Item $PortableDir -Recurse -Force
        Write-Ok 'Version portable supprimée'
    }
    if (Test-Path $StartMenuLink) { Remove-Item $StartMenuLink -Force }
    if (-not $found) { Write-Warn 'Aucune installation de RustShark trouvée.' }

    $existing = @($ConfigDirs | Where-Object { Test-Path $_ })
    if ($existing.Count -gt 0 -and (Confirm-Action 'Supprimer aussi les réglages et profils d''analyse ?')) {
        $existing | ForEach-Object { Remove-Item $_ -Recurse -Force }
        Write-Ok 'Réglages supprimés'
    }
    $creds = & cmdkey /list | Select-String -Pattern 'rustshark' | ForEach-Object {
        ($_ -replace '^\s*(Cible|Target)\s*:\s*', '' -replace '^.*target=', '').Trim()
    }
    if ($creds -and (Confirm-Action 'Effacer les clés API RustShark du Gestionnaire d''identification ?')) {
        foreach ($c in $creds) { & cmdkey "/delete:$c" | Out-Null }
        Write-Ok 'Clés API effacées'
    }
}

# ---------------------------------------------------------------------------

Write-Host "RustShark — installation Windows" -ForegroundColor White
try {
    if ($Uninstall) {
        Remove-App
    } else {
        if (-not $SkipPrereqs) { Install-Prerequisites }
        Invoke-Build
        Install-App
        if (-not $BuildOnly) {
            Write-Host "`nTerminé ! Lancez RustShark depuis le menu Démarrer." -ForegroundColor Green
        }
    }
} catch {
    Write-Host "`n[ERREUR] $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
