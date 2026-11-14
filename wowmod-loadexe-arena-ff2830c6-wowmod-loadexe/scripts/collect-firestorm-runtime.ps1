#requires -Version 5.1
$ErrorActionPreference = 'Continue'

$Root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$Exe = Join-Path $Root 'wowmod.exe'
$HookDll = Join-Path $Root 'wowmod_hook.dll'
$Config = Join-Path $Root 'examples\12.0.7\wowmod.firestorm.json'
$DumpDir = Join-Path $Root 'examples\12.0.7\runtime-dumps'
$WowmodLog = Join-Path $Root 'examples\12.0.7\wowmod.log'
$TranscriptPath = Join-Path $Root 'firestorm-launch-output.txt'
$ArchivePath = Join-Path $Root 'firestorm-runtime-dumps.zip'
$StartedAt = Get-Date
$FreshAfter = $StartedAt.AddSeconds(-2)

Write-Host 'Firestorm 12.0.7 runtime dump collector'
Write-Host 'This runs the bundled launcher; it does not turn on automatic hook installation.'
Write-Host ''

$missing = @()
if (-not (Test-Path -LiteralPath $Exe)) { $missing += $Exe }
if (-not (Test-Path -LiteralPath $HookDll)) { $missing += $HookDll }
if (-not (Test-Path -LiteralPath $Config)) { $missing += $Config }
if ($missing.Count -gt 0) {
    Write-Host 'Required file(s) missing. Download/extract the latest branch package first:' -ForegroundColor Red
    $missing | ForEach-Object { Write-Host "  $_" -ForegroundColor Red }
    exit 1
}

try {
    if (Test-Path -LiteralPath $TranscriptPath) { Remove-Item -LiteralPath $TranscriptPath -Force }
    Start-Transcript -Path $TranscriptPath -Force | Out-Null
    Write-Host 'Launching with the Firestorm sample config.'
    Write-Host 'When the game opens, leave it running for at least 20 seconds so the scan can finish.'
    Write-Host 'If wowmod.exe stays open while the game is running, close the game after that; collection continues automatically.'
    Write-Host ''
    Push-Location $Root
    try {
        & $Exe launch --config $Config
        $launchExitCode = $LASTEXITCODE
        Write-Host "wowmod launch exit code: $launchExitCode"
    } finally {
        Pop-Location
    }
} catch {
    Write-Host "Launch error: $_" -ForegroundColor Red
} finally {
    try { Stop-Transcript | Out-Null } catch {}
}

# If launch returns as soon as the game starts, wait for the delayed memory scan.
# If the launcher's Windows-hook path waits for game exit, the report will already exist here.
$ReportPath = Join-Path $DumpDir 'runtime-report.json'
$Deadline = (Get-Date).AddSeconds(90)
while ((Get-Date) -lt $Deadline) {
    if ((Test-Path -LiteralPath $ReportPath) -and
        (Get-Item -LiteralPath $ReportPath).LastWriteTime -ge $FreshAfter) {
        break
    }
    Start-Sleep -Seconds 2
}

$files = @()
if (Test-Path -LiteralPath $TranscriptPath) { $files += $TranscriptPath }
if (Test-Path -LiteralPath $WowmodLog) { $files += $WowmodLog }
if (Test-Path -LiteralPath $DumpDir) {
    $freshDumps = @(Get-ChildItem -LiteralPath $DumpDir -File -Recurse -ErrorAction SilentlyContinue |
        Where-Object { $_.LastWriteTime -ge $FreshAfter })
    if ($freshDumps.Count -gt 0) { $files += @($freshDumps | ForEach-Object { $_.FullName }) }
}

$reportIsFresh = (Test-Path -LiteralPath $ReportPath) -and
    ((Get-Item -LiteralPath $ReportPath).LastWriteTime -ge $FreshAfter)
if ($reportIsFresh) {
    Add-Content -LiteralPath $TranscriptPath -Value "`r`nCollector status: fresh runtime-report.json found."
    Write-Host 'Fresh runtime report found.' -ForegroundColor Green
} else {
    if (Test-Path -LiteralPath $TranscriptPath) {
        Add-Content -LiteralPath $TranscriptPath -Value "`r`nCollector status: no fresh runtime-report.json. The DLL may not have entered the game process."
    }
    Write-Host 'No fresh runtime-report.json was produced. The archive will still include the launch output and wowmod.log.' -ForegroundColor Yellow
}

$files = @($files | Select-Object -Unique)
try {
    if (Test-Path -LiteralPath $ArchivePath) { Remove-Item -LiteralPath $ArchivePath -Force }
    Compress-Archive -LiteralPath $files -DestinationPath $ArchivePath -CompressionLevel Optimal -Force
    Write-Host ''
    Write-Host "Collection complete: $ArchivePath" -ForegroundColor Green
    Write-Host 'Attach this ZIP to the Arena chat. Do not commit it to Git or upload the whole game directory.'
} catch {
    Write-Host "Could not create ZIP: $_" -ForegroundColor Red
    Write-Host 'The files to attach are:'
    $files | ForEach-Object { Write-Host "  $_" }
}
