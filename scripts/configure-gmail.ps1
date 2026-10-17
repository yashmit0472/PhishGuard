param([Parameter(Mandatory=$true)][string]$ClientId)
if ($ClientId -notmatch '^[0-9]+-[A-Za-z0-9_-]+\.apps\.googleusercontent\.com$') { throw 'Expected the public Chrome OAuth client ID, not an API key or secret.' }
$manifestPath = Join-Path (Split-Path -Parent $PSScriptRoot) 'extension/manifest.json'
$manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
$manifest.oauth2.client_id = $ClientId
$manifest | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $manifestPath -Encoding UTF8
Write-Output 'OAuth client ID configured. Reload the extension in Chrome.'
