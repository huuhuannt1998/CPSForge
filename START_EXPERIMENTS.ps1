# CPSForge Experiment Launcher — PowerShell
# Run this file from PowerShell (NOT Git Bash):
#   Right-click > Run with PowerShell
#   OR: cd C:\Users\hbui11\Desktop\CPSForge && .\START_EXPERIMENTS.ps1

Set-Location "C:\Users\hbui11\Desktop\CPSForge"
$python = "C:\Users\hbui11\AppData\Local\Programs\Python\Python313\python.exe"

Write-Host ""
Write-Host "=========================================="
Write-Host " CPSForge v2 Experiment Runner"
Write-Host "=========================================="
Write-Host ""
Write-Host "Available commands:"
Write-Host ""
Write-Host "  [1] Verify current scene (read-only PLC poll)"
Write-Host "  [2] Run RQ1 -- Level Control  (scene 12 must be loaded)"
Write-Host "  [3] Run RQ1 -- All 5 scenes   (prompts for each scene)"
Write-Host "  [4] Run RQ1+RQ2+RQ3+RQ4       (full deep study)"
Write-Host "  [5] Run RQ5                   (cross-model, needs all models)"
Write-Host "  [6] Download missing models   (Qwen2.5-3B, Phi-4-mini, SmolLM3)"
Write-Host "  [7] Check model download status"
Write-Host "  [Q] Quit"
Write-Host ""

$choice = Read-Host "Enter choice"

switch ($choice) {
    "1" {
        $scene = Read-Host "Scene name (level_control / sorting_weight / filling_tank / from_a_to_b / sorting_height_basic)"
        & $python verify_plc_scene.py --scene $scene --steps 10
    }
    "2" {
        Write-Host ""
        Write-Host ">>> Starting RQ1 — Level Control (Scene 12, DB14)"
        Write-Host "    Factory I/O Scene 12 must be loaded and running."
        Write-Host ""
        & $python run_experiments.py --rqs RQ1 --scenes level_control --repeats 3 --live --yes
    }
    "3" {
        Write-Host ""
        Write-Host ">>> Starting RQ1 — All 5 scenes"
        Write-Host "    The script will prompt you to switch scenes."
        Write-Host ""
        & $python run_experiments.py --rqs RQ1 --repeats 3 --live
    }
    "4" {
        Write-Host ""
        Write-Host ">>> Starting RQ1+RQ2+RQ3+RQ4 (deep study)"
        Write-Host "    Requires Qwen3.5-4B base + finetuned models."
        Write-Host "    The script will prompt for scene switches."
        Write-Host ""
        & $python run_experiments.py --rqs RQ1 RQ2 RQ3 RQ4 --repeats 3 --live
    }
    "5" {
        Write-Host ""
        Write-Host ">>> Starting RQ5 — Cross-model"
        Write-Host "    Requires ALL 5 models downloaded."
        Write-Host ""
        & $python run_experiments.py --rqs RQ5 --repeats 3 --live
    }
    "6" {
        Write-Host ""
        Write-Host ">>> Downloading missing models (Qwen2.5-3B, Phi-4-mini, SmolLM3)..."
        Write-Host "    ~20 GB total. This will take a while."
        Write-Host ""
        & $python download_models.py
    }
    "7" {
        Write-Host ""
        & $python -c @"
from pathlib import Path
models = [
    ('models/qwen3.5-4b',           'Qwen3.5-4B (primary)'),
    ('models/qwen3-1.7b',           'Qwen3-1.7B'),
    ('models/qwen2.5-3b-instruct',  'Qwen2.5-3B-Instruct'),
    ('models/phi-4-mini-instruct',  'Phi-4-mini-instruct'),
    ('models/smollm3-3b',           'SmolLM3-3B'),
]
print()
for path, name in models:
    p = Path(path)
    if p.is_dir() and (p / 'config.json').exists():
        size = sum(f.stat().st_size for f in p.rglob('*') if f.is_file())
        print(f'  [OK    ] {name:30s}  {size/1e9:.1f} GB  {path}')
    else:
        print(f'  [MISSING] {name:30s}  {path}')
print()
"@
    }
    "Q" { Write-Host "Bye." }
    default { Write-Host "Invalid choice." }
}

Write-Host ""
Write-Host "Done. Press any key to exit..."
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
