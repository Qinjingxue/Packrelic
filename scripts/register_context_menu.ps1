param(
    [string]$AppPath,
    [string]$PythonPath,
    [string]$MenuText,
    [string]$IconPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Resolve-Launcher {
    param(
        [string]$RepoRoot,
        [string]$PreferredAppPath,
        [string]$PreferredPythonPath
    )

    if ($PreferredAppPath) {
        $resolvedApp = (Resolve-Path -LiteralPath $PreferredAppPath).Path
        return @{
            Mode = "app"
            AppPath = $resolvedApp
            IconPath = $resolvedApp
        }
    }

    $exeCandidates = @(
        (Join-Path $RepoRoot "sunpack.exe"),
        (Join-Path $RepoRoot "dist\sunpack\sunpack.exe"),
        (Join-Path $RepoRoot "dist\sunpack.exe")
    )
    foreach ($candidate in $exeCandidates) {
        if (Test-Path -LiteralPath $candidate) {
            $resolvedExe = (Resolve-Path -LiteralPath $candidate).Path
            return @{
                Mode = "app"
                AppPath = $resolvedExe
                IconPath = $resolvedExe
            }
        }
    }

    $defaultScript = Join-Path $RepoRoot "sunpack_cli.py"
    if (-not (Test-Path -LiteralPath $defaultScript)) {
        throw "No usable script entry was found. Expected sunpack_cli.py at the repository root."
    }
    $resolvedScript = (Resolve-Path -LiteralPath $defaultScript).Path

    $pythonCandidates = @()
    if ($PreferredPythonPath) {
        $pythonCandidates += $PreferredPythonPath
    }
    foreach ($commandName in @("python", "py")) {
        $command = Get-Command $commandName -ErrorAction SilentlyContinue
        if ($command) {
            $pythonCandidates += $command.Source
        }
    }
    $pythonCandidates = $pythonCandidates | Select-Object -Unique

    foreach ($candidate in $pythonCandidates) {
        if (Test-Path -LiteralPath $candidate) {
            $resolvedPython = (Resolve-Path -LiteralPath $candidate).Path
            return @{
                Mode = "python"
                AppPath = $resolvedPython
                ScriptPath = $resolvedScript
                IconPath = $resolvedPython
            }
        }
    }

    throw "No usable Python interpreter was found. Please pass -PythonPath explicitly."
}

function New-CommandString {
    param(
        [hashtable]$Launcher,
        [string]$TargetToken,
        [bool]$PromptPasswords
    )

    $passwordArg = if ($PromptPasswords) { " --ask-pw" } else { "" }
    if ($Launcher.Mode -eq "app") {
        return ('"{0}" extract "{1}"{2} --pause' -f $Launcher.AppPath, $TargetToken, $passwordArg)
    }

    return ('"{0}" "{1}" extract "{2}"{3} --pause' -f $Launcher.AppPath, $Launcher.ScriptPath, $TargetToken, $passwordArg)
}

function Set-ContextMenuParent {
    param(
        [string]$KeyPath,
        [string]$MenuLabel,
        [string]$IconValue
    )

    $null = New-Item -Path $KeyPath -Force
    Set-Item -Path $KeyPath -Value $MenuLabel
    Set-ItemProperty -Path $KeyPath -Name "MUIVerb" -Value $MenuLabel
    Set-ItemProperty -Path $KeyPath -Name "Icon" -Value $IconValue
    Set-ItemProperty -Path $KeyPath -Name "SubCommands" -Value ""
}

function Set-ContextMenuCommand {
    param(
        [string]$ParentKeyPath,
        [string]$CommandName,
        [string]$MenuLabel,
        [string]$CommandLine,
        [string]$IconValue
    )

    $keyPath = Join-Path (Join-Path $ParentKeyPath "shell") $CommandName
    $null = New-Item -Path $keyPath -Force
    Set-Item -Path $keyPath -Value $MenuLabel
    Set-ItemProperty -Path $keyPath -Name "MUIVerb" -Value $MenuLabel
    Set-ItemProperty -Path $keyPath -Name "Icon" -Value $IconValue
    $commandKey = Join-Path $keyPath "command"
    $null = New-Item -Path $commandKey -Force
    Set-Item -Path $commandKey -Value $CommandLine
}

function Get-DefaultMenuText {
    param([string]$RepoRoot)

    $configPath = Join-Path $RepoRoot "smart_unpacker_config.json"
    if (-not (Test-Path -LiteralPath $configPath)) {
        return "Smart Unpacker"
    }

    try {
        $payload = Get-Content -LiteralPath $configPath -Raw | ConvertFrom-Json
        $language = [string]$payload.cli.language
        if ($language.Trim().ToLower().StartsWith("zh")) {
            return New-ChineseMenuText
        }
    } catch {
    }
    return "Smart Unpacker"
}

function New-ChineseMenuText {
    return -join @(
        [char]0x667A,
        [char]0x80FD,
        [char]0x89E3,
        [char]0x538B
    )
}

function Get-SubMenuTexts {
    param([string]$MenuText)

    if ($MenuText -eq (New-ChineseMenuText)) {
        return @{
            Prompt = "交互输入密码解压"
            Direct = "直接解压"
        }
    }
    return @{
        Prompt = "Extract with password prompt"
        Direct = "Extract directly"
    }
}

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Split-Path -Parent $scriptDir
$launcher = Resolve-Launcher -RepoRoot $repoRoot -PreferredAppPath $AppPath -PreferredPythonPath $PythonPath
$resolvedIconPath = if ($IconPath) { (Resolve-Path -LiteralPath $IconPath).Path } else { $launcher.IconPath }
$resolvedMenuText = if ($MenuText) { $MenuText } else { Get-DefaultMenuText -RepoRoot $repoRoot }

$folderKey = "HKCU:\Software\Classes\Directory\shell\SmartUnpacker"
$backgroundKey = "HKCU:\Software\Classes\Directory\Background\shell\SmartUnpacker"
$subMenuTexts = Get-SubMenuTexts -MenuText $resolvedMenuText

$folderPromptCommand = New-CommandString -Launcher $launcher -TargetToken "%1" -PromptPasswords $true
$folderDirectCommand = New-CommandString -Launcher $launcher -TargetToken "%1" -PromptPasswords $false
$backgroundPromptCommand = New-CommandString -Launcher $launcher -TargetToken "%V" -PromptPasswords $true
$backgroundDirectCommand = New-CommandString -Launcher $launcher -TargetToken "%V" -PromptPasswords $false

Set-ContextMenuParent -KeyPath $folderKey -MenuLabel $resolvedMenuText -IconValue $resolvedIconPath
Set-ContextMenuCommand -ParentKeyPath $folderKey -CommandName "PromptPassword" -MenuLabel $subMenuTexts.Prompt -CommandLine $folderPromptCommand -IconValue $resolvedIconPath
Set-ContextMenuCommand -ParentKeyPath $folderKey -CommandName "DirectExtract" -MenuLabel $subMenuTexts.Direct -CommandLine $folderDirectCommand -IconValue $resolvedIconPath
Set-ContextMenuParent -KeyPath $backgroundKey -MenuLabel $resolvedMenuText -IconValue $resolvedIconPath
Set-ContextMenuCommand -ParentKeyPath $backgroundKey -CommandName "PromptPassword" -MenuLabel $subMenuTexts.Prompt -CommandLine $backgroundPromptCommand -IconValue $resolvedIconPath
Set-ContextMenuCommand -ParentKeyPath $backgroundKey -CommandName "DirectExtract" -MenuLabel $subMenuTexts.Direct -CommandLine $backgroundDirectCommand -IconValue $resolvedIconPath

Write-Host "Context menu registration completed." -ForegroundColor Green
Write-Host "Folder menu key:" $folderKey
Write-Host "Directory background key:" $backgroundKey
Write-Host "Launch mode:" $launcher.Mode
if ($launcher.Mode -eq "app") {
    Write-Host "App path:" $launcher.AppPath
} else {
    Write-Host "Python path:" $launcher.AppPath
    Write-Host "Script path:" $launcher.ScriptPath
}
Write-Host ""
Write-Host ('You can now right-click a folder or directory background and choose "{0}" -> "{1}" or "{2}".' -f $resolvedMenuText, $subMenuTexts.Prompt, $subMenuTexts.Direct)
