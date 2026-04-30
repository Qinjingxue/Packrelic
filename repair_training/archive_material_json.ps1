[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = "Medium")]
param(
    [string]$MaterialRoot = "repair_training\material",
    [string]$DatasetRoot = "repair_training\datasets",
    [string]$BundleName = "",
    [string]$Formats = "",
    [string[]]$Sample = @(),
    [switch]$Move,
    [switch]$ManifestOnly,
    [switch]$Overwrite
)

$ErrorActionPreference = "Stop"
if ($env:OS -ne "Windows_NT") {
    throw "repair training scripts are Windows-only"
}

$RepoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")

function Resolve-RepoPath {
    param([Parameter(Mandatory = $true)][string]$PathText)
    if ([System.IO.Path]::IsPathRooted($PathText)) {
        return [System.IO.Path]::GetFullPath($PathText)
    }
    return [System.IO.Path]::GetFullPath((Join-Path $RepoRoot $PathText))
}

function Test-PathInside {
    param(
        [Parameter(Mandatory = $true)][string]$Child,
        [Parameter(Mandatory = $true)][string]$Parent
    )
    $childFull = [System.IO.Path]::GetFullPath($Child).TrimEnd('\')
    $parentFull = [System.IO.Path]::GetFullPath($Parent).TrimEnd('\')
    return $childFull.Equals($parentFull, [System.StringComparison]::OrdinalIgnoreCase) -or
        $childFull.StartsWith($parentFull + "\", [System.StringComparison]::OrdinalIgnoreCase)
}

function ConvertTo-NameSet {
    param([string[]]$Values)
    $set = @{}
    foreach ($value in $Values) {
        foreach ($part in "$value".Split(",")) {
            $name = $part.Trim()
            if ($name) {
                $set[$name.ToLowerInvariant()] = $true
            }
        }
    }
    return $set
}

function Get-RelativePathCompat {
    param(
        [Parameter(Mandatory = $true)][string]$BasePath,
        [Parameter(Mandatory = $true)][string]$ChildPath
    )
    $baseFull = [System.IO.Path]::GetFullPath($BasePath).TrimEnd('\') + "\"
    $childFull = [System.IO.Path]::GetFullPath($ChildPath)
    $baseUri = New-Object System.Uri($baseFull)
    $childUri = New-Object System.Uri($childFull)
    return [System.Uri]::UnescapeDataString($baseUri.MakeRelativeUri($childUri).ToString()).Replace('/', '\')
}

$MaterialPath = Resolve-RepoPath $MaterialRoot
$DatasetPath = Resolve-RepoPath $DatasetRoot
$TrainingRoot = Resolve-RepoPath "repair_training"
if (-not (Test-PathInside -Child $MaterialPath -Parent $TrainingRoot)) {
    throw "Refusing to read material outside repair_training: $MaterialPath"
}
if (-not (Test-PathInside -Child $DatasetPath -Parent $TrainingRoot)) {
    throw "Refusing to write dataset bundle outside repair_training: $DatasetPath"
}

if (-not (Test-Path -LiteralPath $MaterialPath)) {
    throw "Material root does not exist: $MaterialPath"
}

$formatSet = ConvertTo-NameSet @($Formats)
$sampleSet = ConvertTo-NameSet $Sample
if (-not $BundleName) {
    $BundleName = "material_json_" + (Get-Date -Format "yyyyMMdd_HHmmss")
}
$BundlePath = Join-Path $DatasetPath $BundleName
New-Item -ItemType Directory -Path $BundlePath -Force | Out-Null

$patterns = if ($ManifestOnly) {
    @("damage_manifest.jsonl", "damage_manifest.pretty.json")
} else {
    @("*.jsonl", "*.json")
}

$files = New-Object System.Collections.Generic.List[System.IO.FileInfo]
foreach ($pattern in $patterns) {
    Get-ChildItem -LiteralPath $MaterialPath -Recurse -File -Filter $pattern -Force | ForEach-Object {
        $relative = Get-RelativePathCompat -BasePath $MaterialPath -ChildPath $_.FullName
        $parts = $relative -split '[\\/]'
        $format = if ($parts.Length -ge 1) { $parts[0].ToLowerInvariant() } else { "" }
        $sampleName = if ($parts.Length -ge 2) { $parts[1].ToLowerInvariant() } else { "" }
        if ($formatSet.Count -gt 0 -and -not $formatSet.ContainsKey($format)) {
            return
        }
        if ($sampleSet.Count -gt 0 -and -not $sampleSet.ContainsKey($sampleName)) {
            return
        }
        $files.Add($_)
    }
}

$summary = [ordered]@{
    material_root = $MaterialPath
    dataset_root = $DatasetPath
    bundle = $BundlePath
    moved = 0
    copied = 0
    skipped = 0
    mode = if ($Move) { "move" } else { "copy" }
    manifest_only = [bool]$ManifestOnly
    filters = [ordered]@{
        formats = @($formatSet.Keys | Sort-Object)
        samples = @($sampleSet.Keys | Sort-Object)
    }
}

foreach ($file in $files) {
    $relative = Get-RelativePathCompat -BasePath $MaterialPath -ChildPath $file.FullName
    $target = Join-Path $BundlePath $relative
    $targetDir = Split-Path -Parent $target
    New-Item -ItemType Directory -Path $targetDir -Force | Out-Null
    if ((Test-Path -LiteralPath $target) -and -not $Overwrite) {
        $summary.skipped++
        continue
    }
    if ($Move) {
        if ($PSCmdlet.ShouldProcess($file.FullName, "move to $target")) {
            Move-Item -LiteralPath $file.FullName -Destination $target -Force:$Overwrite
            $summary.moved++
        }
    } else {
        if ($PSCmdlet.ShouldProcess($file.FullName, "copy to $target")) {
            Copy-Item -LiteralPath $file.FullName -Destination $target -Force:$Overwrite
            $summary.copied++
        }
    }
}

$summary | ConvertTo-Json -Depth 5
