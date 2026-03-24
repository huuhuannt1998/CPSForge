# =============================================================================
# CPSForge — Full Live Eval Run Script
# =============================================================================
# Runs all 6 experiments (scripted + random x 3 scenes) against the real PLC.
#
# Prerequisites:
#   1. PLC at 192.168.0.1 is online and running the TIA Portal v17 project.
#   2. Factory I/O scene(s) are loaded and in PLAY mode.
#   3. .env has CPSFORGE_LIVE_WRITES=true
#   4. Emergency stop is accessible.
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File scripts\run_live_eval.ps1
# =============================================================================

$ErrorActionPreference = "Stop"

# Ensure we're in the project root
Set-Location $PSScriptRoot\..

# Verify .env has live writes enabled
$envContent = Get-Content .env -Raw
if ($envContent -notmatch "CPSFORGE_LIVE_WRITES=true") {
    Write-Host "[ERROR] .env does not have CPSFORGE_LIVE_WRITES=true" -ForegroundColor Red
    exit 1
}

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  CPSForge Full Live Evaluation Run" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

# Quick PLC connectivity check
Write-Host "[1/8] Checking PLC connectivity..." -ForegroundColor Yellow
python -m cpsforge plc probe
if ($LASTEXITCODE -ne 0) {
    Write-Host "[ERROR] PLC probe failed. Ensure PLC is online at 192.168.0.1" -ForegroundColor Red
    exit 1
}
Write-Host "[OK] PLC is reachable.`n" -ForegroundColor Green

# Define experiment runs
# All 21 Factory I/O scenes
$allScenes = @(
    "from_a_to_b",
    "from_a_to_b_sr",
    "filling_tank",
    "queue_items",
    "assembler",
    "assembler_analog",
    "warehouse",
    "buffer_station",
    "converge_station",
    "elevator_advanced",
    "elevator_basic",
    "level_control",
    "palletizer",
    "pick_place_basic",
    "pick_place_xyz",
    "production_line",
    "separating_station",
    "sorting_height_advanced",
    "sorting_height_basic",
    "sorting_weight",
    "sorting_station"
)

# Build experiment list: scripted + random for every scene
$experiments = @()
foreach ($s in $allScenes) {
    $experiments += @{ scene = $s; attacker = "scripted"; config = "live_scripted_$s" }
    $experiments += @{ scene = $s; attacker = "random";   config = "live_random_$s" }
}

$total = $experiments.Count
$idx = 0
$results = @()

foreach ($exp in $experiments) {
    $idx++
    $scene = $exp.scene
    $attacker = $exp.attacker
    $config = $exp.config

    Write-Host "`n[$($idx+1)/$($total+2)] Running: $attacker on $scene" -ForegroundColor Yellow
    Write-Host "  Experiment config: $config" -ForegroundColor DarkGray
    Write-Host "  This will issue REAL PLC writes." -ForegroundColor Red

    # Run the experiment (--no-dry-run + --eval-run)
    # The typer.confirm() prompt is bypassed by piping "y"
    "y" | python -m cpsforge run attack `
        --scene $scene `
        --attacker $attacker `
        --experiment $config `
        --no-dry-run `
        --eval-run

    if ($LASTEXITCODE -ne 0) {
        Write-Host "  [WARN] Run exited with non-zero code: $LASTEXITCODE" -ForegroundColor Yellow
        $results += "$attacker on $scene : FAILED (exit $LASTEXITCODE)"
    } else {
        Write-Host "  [OK] Run complete." -ForegroundColor Green
        $results += "$attacker on $scene : SUCCESS"
    }

    # Brief pause for PLC to stabilize between runs
    Write-Host "  Pausing 5s for PLC stabilization..." -ForegroundColor DarkGray
    Start-Sleep -Seconds 5
}

# Generate experiment summaries
Write-Host "`n[$($total+2)/$($total+2)] Generating experiment summaries..." -ForegroundColor Yellow

$summaryExperiments = @()
foreach ($s in $allScenes) {
    $summaryExperiments += "live_scripted_$s"
    $summaryExperiments += "live_random_$s"
}

foreach ($expName in $summaryExperiments) {
    if (Test-Path "data\raw\$expName") {
        python -m cpsforge report summarize --experiment $expName 2>$null
        if ($LASTEXITCODE -eq 0) {
            Write-Host "  Summary: $expName" -ForegroundColor Green
        }
    }
}

# Print results summary
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  Results Summary" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
foreach ($r in $results) {
    $color = if ($r -match "SUCCESS") { "Green" } else { "Yellow" }
    Write-Host "  $r" -ForegroundColor $color
}
Write-Host ""
