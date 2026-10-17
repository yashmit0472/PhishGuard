param([string]$Python = 'python')
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
Push-Location $projectRoot
try {
    Push-Location frontend
    try { npm.cmd ci; if ($LASTEXITCODE -ne 0) { throw 'npm ci failed' }; npm.cmd run build; if ($LASTEXITCODE -ne 0) { throw 'Frontend build failed' } }
    finally { Pop-Location }
    & $Python -m PyInstaller --noconfirm --clean --onedir --console --name PhishGuard --paths backend --add-data 'frontend/dist;frontend/dist' --exclude-module numpy --exclude-module scipy --exclude-module sklearn --exclude-module torch --exclude-module cv2 --exclude-module PIL --exclude-module oletools --exclude-module dns --exclude-module magic backend/local_app.py
    if ($LASTEXITCODE -ne 0) { throw 'Windows build failed' }
    Copy-Item -LiteralPath README.md -Destination dist/PhishGuard/README.md
    Copy-Item -LiteralPath extension -Destination dist/PhishGuard/extension -Recurse -Force
    Copy-Item -LiteralPath docs/GMAIL_SETUP.md -Destination dist/PhishGuard/GMAIL_SETUP.md
    New-Item -ItemType Directory -Path dist/PhishGuard/docs -Force | Out-Null
    Copy-Item -Path docs/ACCESSIBILITY_TESTS.md,docs/DEMO.md,docs/FEEDS_AND_PRIVACY.md,docs/GMAIL_SETUP.md,docs/LOCAL_ARCHITECTURE.md,docs/PRIVACY_MIGRATION.md,docs/RULES.md -Destination dist/PhishGuard/docs
    Copy-Item -LiteralPath docs/fixtures -Destination dist/PhishGuard/docs/fixtures -Recurse -Force
    Copy-Item -LiteralPath docs/evaluation -Destination dist/PhishGuard/docs/evaluation -Recurse -Force
    Write-Output 'Package ready: dist/PhishGuard/PhishGuard.exe. Keep the whole folder together.'
} finally { Pop-Location }
