[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
Set-Location $repoRoot

$script:StepResults = @()

function Invoke-TestStep {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Label,
        [Parameter(Mandatory = $true)]
        [string[]]$Command
    )

    Write-Host ""
    Write-Host "==> $Label" -ForegroundColor Cyan

    $argsList = @()
    if ($Command.Length -gt 1) {
        $argsList = $Command[1..($Command.Length - 1)]
    }

    $startTime = Get-Date
    & $Command[0] $argsList
    $exitCode = $LASTEXITCODE
    $duration = ((Get-Date) - $startTime).TotalSeconds

    $script:StepResults += [pscustomobject]@{
        Label = $Label
        ExitCode = $exitCode
        DurationSeconds = [math]::Round($duration, 2)
    }

    if ($exitCode -ne 0) {
        throw "Test step failed: $Label (exit code $exitCode)"
    }

    Write-Host ("    PASS ({0:N2}s)" -f $duration) -ForegroundColor Green
}

function Get-PythonCommand {
    foreach ($candidate in @("python", "py")) {
        try {
            & $candidate --version *> $null
            if ($LASTEXITCODE -eq 0) {
                return $candidate
            }
        } catch {
        }
    }

    throw "Python interpreter not found in PATH."
}

$python = Get-PythonCommand

Invoke-TestStep -Label "CLI and module unit tests" -Command @(
    $python, "-m", "unittest",
    "tests.cli_unit_test",
    "tests.module_unit_test",
    "tests.generated_samples_smoke_test",
    "tests.game_runtime_semantic_test"
)

Invoke-TestStep -Label "CLI passwords smoke test" -Command @(
    $python, "smart-unpacker.py", "passwords", "--json"
)

Invoke-TestStep -Label "Disguised detection profile test" -Command @(
    $python, "tests\disguised_detection_profile_test.py", "--limit", "5"
)

Write-Host ""
Write-Host "Summary" -ForegroundColor Cyan
foreach ($result in $script:StepResults) {
    Write-Host ("  PASS  {0,-36} {1,6:N2}s" -f $result.Label, $result.DurationSeconds) -ForegroundColor Green
}

Write-Host ""
Write-Host "GitHub Actions CI checks passed." -ForegroundColor Green
