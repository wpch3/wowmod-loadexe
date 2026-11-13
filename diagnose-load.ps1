# wowmod_hook.dll load diagnostic (ASCII-only for Windows PowerShell 5.1)
# Usage:  powershell -ExecutionPolicy Bypass -File .\scripts\diagnose-load.ps1
# Or from the game dir:  powershell -ExecutionPolicy Bypass -File .\diagnose-load.ps1
param([string]$DllPath = "")

$ErrorActionPreference = "Continue"

function Resolve-Dll {
  if ($DllPath -and (Test-Path $DllPath)) { return (Resolve-Path $DllPath).Path }
  $c = @(
    (Join-Path $PSScriptRoot "wowmod_hook.dll"),
    (Join-Path (Split-Path -Parent $PSScriptRoot) "wowmod_hook.dll"),
    (Join-Path (Get-Location).Path "wowmod_hook.dll"),
    ".\wowmod_hook.dll"
  )
  foreach ($p in $c) { if (Test-Path $p) { return (Resolve-Path $p).Path } }
  return $null
}

$p = Resolve-Dll
Write-Host "=== wowmod_hook.dll load diagnostic ==="
if (-not $p) {
  Write-Host "NOT FOUND: wowmod_hook.dll. Put it next to wowmod.exe, or pass -DllPath."
  exit 1
}
Write-Host "Path : $p"
$item = Get-Item $p
Write-Host "Size : $($item.Length) bytes"

# PE machine check
try {
  $b = [IO.File]::ReadAllBytes($p)
  $pe = [BitConverter]::ToInt32($b, 0x3C)
  $machine = [BitConverter]::ToUInt16($b, $pe + 4)
  $arch = switch ($machine) { 0x8664 { "x64 (OK)" } 0x14c { "x86 (WRONG: client is x64)" } default { "0x{0:X4}" -f $machine } }
  Write-Host "PE   : $arch ; machine=0x$('{0:X4}' -f $machine)"
} catch { Write-Host "PE   : parse failed: $_" }

$zone = $null
try { $zone = Get-Item -Path $p -Stream Zone.Identifier -ErrorAction SilentlyContinue } catch {}
if ($zone) { Write-Host ('ZONE : BLOCKED (run: Unblock-File "' + $p + '")') } else { Write-Host "ZONE : clean" }

if (-not ("LoaderProbe" -as [type])) {
  Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public class LoaderProbe {
  [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
  public static extern IntPtr LoadLibraryW(string name);
  [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
  public static extern IntPtr LoadLibraryExW(string name, IntPtr reserved, uint flags);
  [DllImport("kernel32.dll", SetLastError=true)]
  public static extern bool FreeLibrary(IntPtr h);
}
"@
}

function Explain([int]$e) {
  switch ($e) {
    0     { "OK" }
    2     { "ERROR_FILE_NOT_FOUND - file missing" }
    3     { "ERROR_PATH_NOT_FOUND - bad path" }
    5     { "ERROR_ACCESS_DENIED - Defender/ASR, integrity level, or protected process" }
    32    { "ERROR_SHARING_VIOLATION - file in use" }
    126   { "ERROR_MOD_NOT_FOUND - a dependency is missing (UCRT / VC++ redist)" }
    127   { "ERROR_PROC_NOT_FOUND - missing export" }
    193   { "ERROR_BAD_EXE_FORMAT - wrong bitness or invalid PE" }
    216   { "ERROR_EXE_MACHINE_TYPE_MISMATCH - architecture mismatch" }
    998   { "ERROR_NOACCESS - invalid memory access" }
    1114  { "ERROR_DLL_INIT_FAILED - DllMain failed or returned FALSE" }
    default { "see https://learn.microsoft.com/windows/win32/debug/system-error-codes" }
  }
}

# Probe 1: map PE only, no DllMain, no dependency resolution
$h1 = [LoaderProbe]::LoadLibraryExW($p, [IntPtr]::Zero, 0x00000001)
$e1 = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
Write-Host ""
Write-Host "Probe 1 (PE map only, no DllMain): handle=$h1  error=$e1  $(Explain $e1)"
if ($h1 -ne [IntPtr]::Zero) { [void][LoaderProbe]::FreeLibrary($h1) }

# Probe 2: full load in THIS process (runs DllMain, resolves dependencies).
# WOWMOD_PROBE stops the injected DLL from spawning its background scan thread,
# so FreeLibrary here is safe.
$env:WOWMOD_PROBE = "1"
$h2 = [LoaderProbe]::LoadLibraryW($p)
$e2 = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
Write-Host "Probe 2 (full load here):         handle=$h2  error=$e2  $(Explain $e2)"
if ($h2 -ne [IntPtr]::Zero) { [void][LoaderProbe]::FreeLibrary($h2) }

Write-Host ""
if ($h2 -eq [IntPtr]::Zero) {
  Write-Host "RESULT: the DLL itself cannot load. Most likely:"
  Write-Host "  - error 126 -> install VC++ 2015-2022 x64 Redistributable (UCRT)"
  Write-Host "  - error 193/216 -> wrong bitness, rebuild as x64"
  Write-Host "  - error 5 -> Defender/ASR or protected folder; move files out of Downloads"
  Write-Host "  - error 1114 -> DllMain init failure; check wowmod.log"
} else {
  Write-Host "RESULT: the DLL loads fine in PowerShell."
  Write-Host "  The failure inside the game process is likely injection timing or security policy."
  Write-Host "  The launcher now retries after resuming the main thread (hooks.injectRetry=true)."
  Write-Host "  If it still fails, try:"
  Write-Host "   1) Run PowerShell as Administrator"
  Write-Host "   2) Move wowmod.exe + wowmod_hook.dll to a simple path like D:\wowmod"
  Write-Host "   3) Add that folder to Windows Defender exclusions"
  Write-Host "   4) Send this output plus wowmod.log back for analysis"
}
