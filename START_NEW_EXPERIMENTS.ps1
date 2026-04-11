# =============================================================================
# CPSForge -- New Attack-Class Experiments (EXP-2,3,6,8)
# Run from PowerShell. NOT Git Bash.
# =============================================================================
# Usage:
#   cd C:\Users\hbui11\Desktop\CPSForge\.claude\worktrees\recursing-davinci
#   .\START_NEW_EXPERIMENTS.ps1
#
# Load scenes in Factory I/O in this order:
#   Level Control       -> Scene 12 (DB14)
#   Sorting by Weight   -> Scene 20 (DB22)
#   Sorting by Height   -> Scene 19 (DB21)
#
# Each EXP runs 3 repeats per scene. Kill Python between EXPs.
# =============================================================================

Set-Location "C:\Users\hbui11\Desktop\CPSForge\.claude\worktrees\recursing-davinci"
$python = "py"

function Run-Exp {
    param($ConfigName, $Label, $Live=$false, $Save=$true)
    Write-Host ""
    Write-Host ">>> $Label" -ForegroundColor Cyan
    Write-Host "    Config: $ConfigName"
    if (-not $Live) { Write-Host "    DRY RUN -- toggle LIVE for real PLC writes" -ForegroundColor Yellow }
    if (-not $Save) { Write-Host "    SAVE OFF -- results will NOT be written to disk" -ForegroundColor Yellow }

    $liveVal = if ($Live) { 'True' } else { 'False' }
    $saveVal = if ($Save) { 'True' } else { 'False' }

    $script = @"
import sys, os
# Worktree has no models/ dir -- run from main repo root so relative paths resolve
os.chdir(r'C:\Users\hbui11\Desktop\CPSForge')
sys.path.insert(0, r'C:\Users\hbui11\Desktop\CPSForge\.claude\worktrees\recursing-davinci')
from cpsforge.core.config import get_config_loader
from cpsforge.runner.online_runner import OnlineExperimentRunner
from pathlib import Path

loader = get_config_loader()
cfg = loader.load_experiment('$ConfigName')
cfg.live_writes_enabled = $liveVal
cfg.save_trace = $saveVal
cfg.save_metrics = $saveVal
runner = OnlineExperimentRunner(config=cfg, loader=loader, output_base=Path('data/raw'))
run_id = runner.run()
print(f'Completed: {run_id}')
"@

    $tmpFile = ".\__cpsforge_run__.py"
    Set-Content -Path $tmpFile -Value $script -Encoding UTF8
    & $python $tmpFile
    Remove-Item $tmpFile -ErrorAction SilentlyContinue
}

Write-Host ""
Write-Host "==========================================" -ForegroundColor Green
Write-Host " CPSForge New Experiments (EXP-2,3,6,8)"  -ForegroundColor Green
Write-Host "==========================================" -ForegroundColor Green
Write-Host ""
Write-Host "Available:"
Write-Host "  [2A] EXP-2 Maroochy   -- Level Control     (300 steps)"
Write-Host "  [2B] EXP-2 Maroochy   -- Sorting by Weight (300 steps)"
Write-Host "  [2C] EXP-2 Maroochy   -- Sorting by Height (300 steps)"
Write-Host "  [3A] EXP-3 German Steel-- Level Control    (state bypass)"
Write-Host "  [3B] EXP-3 German Steel-- Sorting by Weight"
Write-Host "  [3C] EXP-3 German Steel-- Sorting by Height"
Write-Host "  [6A] EXP-6 TRITON      -- Level Control    (safety interlock)"
Write-Host "  [6B] EXP-6 TRITON      -- Sorting by Weight"
Write-Host "  [6C] EXP-6 TRITON      -- Sorting by Height"
Write-Host "  [8A] EXP-8 Oldsmar     -- Level Control    (extreme setpoint)"
Write-Host ""
Write-Host "  -- By scene (recommended: run all EXPs on one scene, then switch) --"
Write-Host "  [LC]   All EXPs on Level Control     (EXP-2A, 3A, 6A, 8A)"
Write-Host "  [SW]   All EXPs on Sorting by Weight (EXP-2B, 3B, 6B)"
Write-Host "  [SH]   All EXPs on Sorting by Height (EXP-2C, 3C, 6C)"
Write-Host "  [ALL]  All scenes in order: LC -> SW -> SH"
Write-Host ""
Write-Host "  -- By experiment type --"
Write-Host "  [ALL2] Run all EXP-2 cells (requires manual scene switches)"
Write-Host "  [ALL3] Run all EXP-3 cells"
Write-Host "  [ALL6] Run all EXP-6 cells"
Write-Host ""
Write-Host "  [LIVE] Toggle live writes (default: DRY RUN)"
Write-Host "  [SAVE] Toggle result saving (default: SAVE ON)"
Write-Host "  [Q]    Quit"
Write-Host ""

$live = $false
$save = $true

do {
    $liveStr = if ($live) { "LIVE" } else { "DRY" }
    $saveStr = if ($save) { "SAVE ON" } else { "SAVE OFF" }
    $choice = Read-Host "[$liveStr | $saveStr] Enter choice"
    switch ($choice.ToUpper()) {
        "LIVE" {
            $live = -not $live
            $status = if ($live) { "LIVE WRITES ENABLED" } else { "DRY RUN" }
            Write-Host "Mode: $status" -ForegroundColor $(if ($live) { "Red" } else { "Yellow" })
        }
        "SAVE" {
            $save = -not $save
            $status = if ($save) { "SAVE ON" } else { "SAVE OFF" }
            Write-Host "Save: $status" -ForegroundColor $(if ($save) { "Green" } else { "Yellow" })
        }
        "2A" { Run-Exp "exp02_maroochy_level_control"  "EXP-2 Maroochy -- Level Control" $live $save }
        "2B" { Run-Exp "exp02_maroochy_sorting_weight" "EXP-2 Maroochy -- Sorting by Weight" $live $save }
        "2C" { Run-Exp "exp02_maroochy_sorting_height" "EXP-2 Maroochy -- Sorting by Height" $live $save }
        "3A" { Run-Exp "exp03_german_steel_level_control"  "EXP-3 German Steel -- Level Control" $live $save }
        "3B" { Run-Exp "exp03_german_steel_sorting_weight" "EXP-3 German Steel -- Sorting by Weight" $live $save }
        "3C" { Run-Exp "exp03_german_steel_sorting_height" "EXP-3 German Steel -- Sorting by Height" $live $save }
        "6A" { Run-Exp "exp06_triton_level_control"  "EXP-6 TRITON -- Level Control" $live $save }
        "6B" { Run-Exp "exp06_triton_sorting_weight" "EXP-6 TRITON -- Sorting by Weight" $live $save }
        "6C" { Run-Exp "exp06_triton_sorting_height" "EXP-6 TRITON -- Sorting by Height" $live $save }
        "8A" { Run-Exp "exp08_oldsmar_level_control" "EXP-8 Oldsmar -- Level Control" $live $save }
        "LC" {
            Write-Host "Load Level Control (Scene 12) in Factory I/O, then press Enter" -ForegroundColor Yellow
            Read-Host
            Run-Exp "exp02_maroochy_level_control"         "EXP-2 Maroochy -- Level Control"      $live $save
            Run-Exp "exp03_german_steel_level_control"     "EXP-3 German Steel -- Level Control"  $live $save
            Run-Exp "exp06_triton_level_control"           "EXP-6 TRITON -- Level Control"        $live $save
            Run-Exp "exp08_oldsmar_level_control"          "EXP-8 Oldsmar -- Level Control"       $live $save
            Write-Host "Level Control done. Switch to next scene." -ForegroundColor Green
        }
        "SW" {
            Write-Host "Load Sorting by Weight (Scene 20) in Factory I/O, then press Enter" -ForegroundColor Yellow
            Read-Host
            Run-Exp "exp02_maroochy_sorting_weight"        "EXP-2 Maroochy -- Sorting by Weight"      $live $save
            Run-Exp "exp03_german_steel_sorting_weight"    "EXP-3 German Steel -- Sorting by Weight"  $live $save
            Run-Exp "exp06_triton_sorting_weight"          "EXP-6 TRITON -- Sorting by Weight"        $live $save
            Write-Host "Sorting by Weight done. Switch to next scene." -ForegroundColor Green
        }
        "SH" {
            Write-Host "Load Sorting by Height (Scene 19) in Factory I/O, then press Enter" -ForegroundColor Yellow
            Read-Host
            Run-Exp "exp02_maroochy_sorting_height"        "EXP-2 Maroochy -- Sorting by Height"      $live $save
            Run-Exp "exp03_german_steel_sorting_height"    "EXP-3 German Steel -- Sorting by Height"  $live $save
            Run-Exp "exp06_triton_sorting_height"          "EXP-6 TRITON -- Sorting by Height"        $live $save
            Write-Host "Sorting by Height done. All scenes complete." -ForegroundColor Green
        }
        "ALL" {
            Write-Host "=== ALL EXPERIMENTS IN SCENE ORDER ===" -ForegroundColor Cyan
            Write-Host "Load Level Control (Scene 12) in Factory I/O, then press Enter" -ForegroundColor Yellow
            Read-Host
            Run-Exp "exp02_maroochy_level_control"         "EXP-2 Maroochy -- Level Control"      $live $save
            Run-Exp "exp03_german_steel_level_control"     "EXP-3 German Steel -- Level Control"  $live $save
            Run-Exp "exp06_triton_level_control"           "EXP-6 TRITON -- Level Control"        $live $save
            Run-Exp "exp08_oldsmar_level_control"          "EXP-8 Oldsmar -- Level Control"       $live $save
            Write-Host "Level Control done. Load Sorting by Weight (Scene 20), then press Enter" -ForegroundColor Yellow
            Read-Host
            Run-Exp "exp02_maroochy_sorting_weight"        "EXP-2 Maroochy -- Sorting by Weight"      $live $save
            Run-Exp "exp03_german_steel_sorting_weight"    "EXP-3 German Steel -- Sorting by Weight"  $live $save
            Run-Exp "exp06_triton_sorting_weight"          "EXP-6 TRITON -- Sorting by Weight"        $live $save
            Write-Host "Sorting by Weight done. Load Sorting by Height (Scene 19), then press Enter" -ForegroundColor Yellow
            Read-Host
            Run-Exp "exp02_maroochy_sorting_height"        "EXP-2 Maroochy -- Sorting by Height"      $live $save
            Run-Exp "exp03_german_steel_sorting_height"    "EXP-3 German Steel -- Sorting by Height"  $live $save
            Run-Exp "exp06_triton_sorting_height"          "EXP-6 TRITON -- Sorting by Height"        $live $save
            Write-Host "=== ALL EXPERIMENTS COMPLETE ===" -ForegroundColor Green
        }
        "ALL2" {
            Write-Host "Load Level Control (Scene 12) in Factory I/O, then press Enter" -ForegroundColor Yellow
            Read-Host
            Run-Exp "exp02_maroochy_level_control" "EXP-2 LC" $live $save
            Write-Host "Load Sorting by Weight (Scene 20), then press Enter" -ForegroundColor Yellow
            Read-Host
            Run-Exp "exp02_maroochy_sorting_weight" "EXP-2 SW" $live $save
            Write-Host "Load Sorting by Height (Scene 19), then press Enter" -ForegroundColor Yellow
            Read-Host
            Run-Exp "exp02_maroochy_sorting_height" "EXP-2 SH" $live $save
        }
        "ALL3" {
            Write-Host "Load Level Control (Scene 12), then press Enter" -ForegroundColor Yellow
            Read-Host
            Run-Exp "exp03_german_steel_level_control" "EXP-3 LC" $live $save
            Write-Host "Load Sorting by Weight (Scene 20), then press Enter" -ForegroundColor Yellow
            Read-Host
            Run-Exp "exp03_german_steel_sorting_weight" "EXP-3 SW" $live $save
            Write-Host "Load Sorting by Height (Scene 19), then press Enter" -ForegroundColor Yellow
            Read-Host
            Run-Exp "exp03_german_steel_sorting_height" "EXP-3 SH" $live $save
        }
        "ALL6" {
            Write-Host "Load Level Control (Scene 12), then press Enter" -ForegroundColor Yellow
            Read-Host
            Run-Exp "exp06_triton_level_control" "EXP-6 LC" $live $save
            Write-Host "Load Sorting by Weight (Scene 20), then press Enter" -ForegroundColor Yellow
            Read-Host
            Run-Exp "exp06_triton_sorting_weight" "EXP-6 SW" $live $save
            Write-Host "Load Sorting by Height (Scene 19), then press Enter" -ForegroundColor Yellow
            Read-Host
            Run-Exp "exp06_triton_sorting_height" "EXP-6 SH" $live $save
        }
        "Q" { break }
        "" { <# ignore empty Enter #> }
        default { Write-Host "Unknown choice: '$choice'  (try LC, SW, SH, ALL, LIVE, SAVE, Q)" -ForegroundColor Red }
    }
} while ($choice.ToUpper() -ne "Q")
