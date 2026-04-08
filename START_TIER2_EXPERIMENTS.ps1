# ==========================================================================
# START_TIER2_EXPERIMENTS.ps1 — Launch Tier 2 (Deep State MitM) experiments
# ==========================================================================
#
# This script runs the Tier 2 experiment matrix: DeepStateMITMAttacker
# targeting internal PLC state variables (setpoints, thresholds, enable flags)
# that the PLC logic never overwrites.
#
# PREREQUISITES:
#   1. PLC is connected (192.168.0.1, Siemens S7-1200)
#   2. Factory I/O is running with the correct scene loaded
#   3. Run from PowerShell (NOT Git Bash)
#
# EXPERIMENT MATRIX:
#   2 models (base, finetuned) × 2 contexts (partial, full) × 
#   5 defenses (none, state_consistency, state_combined, llm_defender, llm_combined) × 
#   3 scenes × 3 repeats = 180 cells
#
# Recommended: Start with a small pilot (1 repeat, 1 scene) to validate
# before running the full matrix.
#
# USAGE:
#   # Pilot (1 scene, 1 repeat):
#   .\START_TIER2_EXPERIMENTS.ps1 -Pilot
#
#   # Full matrix:
#   .\START_TIER2_EXPERIMENTS.ps1 -Full
#
#   # Custom:
#   py -3 run_experiments.py --rqs TIER2 --scenes level_control --repeats 1 --live
# ==========================================================================

param(
    [switch]$Pilot,
    [switch]$Full,
    [switch]$DryRun
)

$ErrorActionPreference = "Stop"

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  CPSForge Tier 2 — Deep State MitM Experiments" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

# Check PLC connectivity
Write-Host "Checking PLC connectivity..." -ForegroundColor Yellow
$plcReachable = Test-NetConnection -ComputerName 192.168.0.1 -Port 102 -InformationLevel Quiet -WarningAction SilentlyContinue
if (-not $plcReachable) {
    Write-Host "ERROR: PLC at 192.168.0.1:102 is not reachable!" -ForegroundColor Red
    Write-Host "  - Check network connection to PLC" -ForegroundColor Red
    Write-Host "  - Verify PLC is powered on" -ForegroundColor Red
    exit 1
}
Write-Host "  PLC connected: OK" -ForegroundColor Green

# Kill any existing Python processes to free GPU memory
Write-Host "Cleaning up GPU memory..." -ForegroundColor Yellow
Get-Process -Name python -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2

if ($Pilot) {
    Write-Host ""
    Write-Host "MODE: PILOT (Level Control only, 1 repeat, base model)" -ForegroundColor Magenta
    Write-Host "  Cells: 5 defenses × 1 context × 1 repeat = 5 cells" -ForegroundColor Magenta
    Write-Host ""
    
    if ($DryRun) {
        py -3 run_experiments.py --rqs TIER2 --scenes level_control --repeats 1 --dry-run
    } else {
        py -3 run_experiments.py --rqs TIER2 --scenes level_control --repeats 1 --live
    }
}
elseif ($Full) {
    Write-Host ""
    Write-Host "MODE: FULL MATRIX" -ForegroundColor Magenta
    Write-Host "  2 models × 2 contexts × 5 defenses × 3 scenes × 3 repeats = 180 cells" -ForegroundColor Magenta
    Write-Host "  Estimated time: 12-20 hours (depends on LLM inference speed)" -ForegroundColor Magenta
    Write-Host ""
    Write-Host "WARNING: This is a long run. Use --yes to skip scene-switch prompts." -ForegroundColor Yellow
    
    if ($DryRun) {
        py -3 run_experiments.py --rqs TIER2 --repeats 3 --dry-run --yes
    } else {
        py -3 run_experiments.py --rqs TIER2 --repeats 3 --live --yes
    }
}
else {
    Write-Host ""
    Write-Host "USAGE:" -ForegroundColor Yellow
    Write-Host "  .\START_TIER2_EXPERIMENTS.ps1 -Pilot         # Quick validation (5 cells)" -ForegroundColor White
    Write-Host "  .\START_TIER2_EXPERIMENTS.ps1 -Full          # Full matrix (180 cells)" -ForegroundColor White
    Write-Host "  .\START_TIER2_EXPERIMENTS.ps1 -Pilot -DryRun # Dry run (no PLC writes)" -ForegroundColor White
    Write-Host ""
    Write-Host "Or run directly:" -ForegroundColor Yellow
    Write-Host '  py -3 run_experiments.py --rqs TIER2 --scenes level_control --repeats 1 --live' -ForegroundColor White
}

Write-Host ""
Write-Host "Done." -ForegroundColor Green
