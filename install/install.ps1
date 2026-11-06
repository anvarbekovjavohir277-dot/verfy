# Installs the standalone verfy CLI on Windows. Python is included; nothing else is needed.
#
#   irm https://verfy.dev/install.ps1 | iex
#
# Before running it you can set $env:VERFY_VERSION = "1.2.3" to pin a version,
# $env:VERFY_INSTALL_DIR to move it (default %LOCALAPPDATA%\Programs\verfy) and
# $env:VERFY_NO_MODIFY_PATH = "1" to leave your user PATH alone; $env:VERFY_DOWNLOAD_BASE
# replaces the release URL (a mirror, or a local test server).
# Builds: https://github.com/anvarbekovjavohir277-dot/verfy-releases

& {
  $ErrorActionPreference = "Stop"
  $ProgressPreference = "SilentlyContinue"
  $repo = "anvarbekovjavohir277-dot/verfy-releases"

  if (-not [Environment]::Is64BitOperatingSystem) {
    Write-Host "verfy: error: there is no standalone build for 32-bit Windows; use: pip install verfy" -ForegroundColor Red
    return
  }
  # Windows on ARM runs the x64 build through its built-in emulation.
  $file = "verfy-windows-x64.zip"
  if ($env:VERFY_DOWNLOAD_BASE) { $base = $env:VERFY_DOWNLOAD_BASE }
  elseif ($env:VERFY_VERSION) {
    if ($env:VERFY_VERSION -notmatch '^\d+\.\d+\.\d+$') {
      Write-Host "verfy: error: VERFY_VERSION must look like 1.2.3" -ForegroundColor Red
      return
    }
    $base = "https://github.com/$repo/releases/download/v$($env:VERFY_VERSION)"
  }
  else { $base = "https://github.com/$repo/releases/latest/download" }

  [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
  $tmp = Join-Path ([IO.Path]::GetTempPath()) ("verfy-" + [guid]::NewGuid().ToString("N"))
  New-Item -ItemType Directory -Path $tmp | Out-Null
  try {
    Write-Host "verfy: downloading $file"
    Invoke-WebRequest -Uri "$base/$file" -OutFile (Join-Path $tmp $file) -UseBasicParsing
    Invoke-WebRequest -Uri "$base/SHA256SUMS" -OutFile (Join-Path $tmp "SHA256SUMS") -UseBasicParsing

    $want = $null
    foreach ($row in Get-Content (Join-Path $tmp "SHA256SUMS")) {
      $parts = $row.Trim() -split "\s+"
      if ($parts.Count -ge 2 -and ($parts[1] -eq $file -or $parts[1] -eq "*$file")) { $want = $parts[0].ToLower() }
    }
    if (-not $want) { throw "$file is not listed in SHA256SUMS" }
    $got = (Get-FileHash -Path (Join-Path $tmp $file) -Algorithm SHA256).Hash.ToLower()
    if ($got -ne $want) { throw "checksum mismatch for $file; nothing was installed" }

    # The checksum shows the download is whole, not who built it: both come from the same release.
    # The attestation shows this repository's workflow built it. Checking it needs a signed-in GitHub CLI.
    $checked = $false
    if (-not $env:VERFY_DOWNLOAD_BASE -and (Get-Command gh -ErrorAction SilentlyContinue)) {
      cmd /c "gh auth status >nul 2>&1"
      if ($LASTEXITCODE -eq 0) {
        cmd /c "gh attestation verify `"$(Join-Path $tmp $file)`" -R $repo >nul 2>&1"
        if ($LASTEXITCODE -ne 0) { throw "the build attestation of $file did not verify; nothing was installed" }
        $checked = $true
      }
    }
    if ($checked) { Write-Host "verfy: build attestation verified" }
    else { Write-Host "verfy: checksum verified: the download is whole, but that does not show who built it; see https://verfy.dev/security#verify" }

    Expand-Archive -Path (Join-Path $tmp $file) -DestinationPath $tmp
    $exe = Join-Path $tmp "verfy\verfy.exe"
    $out = (& $exe --version | Out-String).Trim()
    if ($out -match "^verfy (\d+\.\d+\.\d+)$") { $version = $Matches[1] }
    else { throw "the downloaded verfy did not start on this system (it printed: $out); use: pip install verfy" }

    if ($env:VERFY_INSTALL_DIR) { $root = $env:VERFY_INSTALL_DIR } else { $root = Join-Path $env:LOCALAPPDATA "Programs\verfy" }
    $dest = Join-Path $root "current"
    New-Item -ItemType Directory -Force -Path $root | Out-Null
    if (Test-Path $dest) {
      # a running verfy (for example a Claude Code hook) keeps its files open; move the old copy aside first
      $old = Join-Path $root ("old-" + [guid]::NewGuid().ToString("N"))
      try { Move-Item -Path $dest -Destination $old }
      catch { throw "the installed verfy is in use; close Claude Code and other agents, then run the installer again" }
      Remove-Item -Recurse -Force $old -ErrorAction SilentlyContinue
    }
    Move-Item -Path (Join-Path $tmp "verfy") -Destination $dest
    Get-ChildItem -Path $root -Directory -Filter "old-*" -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host "verfy: installed verfy $version in $dest"

    $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
    if (-not $userPath) { $userPath = "" }
    if (($userPath -split ";") -notcontains $dest) {
      if ($env:VERFY_NO_MODIFY_PATH) {
        Write-Host "verfy: $dest is not on your PATH; add it to use verfy from any terminal"
      } else {
        [Environment]::SetEnvironmentVariable("Path", ((@($userPath.TrimEnd(";"), $dest) | Where-Object { $_ }) -join ";"), "User")
        Write-Host "verfy: added $dest to your user PATH; new terminals will find verfy"
      }
    }
    if (($env:Path -split ";") -notcontains $dest) { $env:Path = "$dest;$env:Path" }
    Write-Host "verfy: next: verfy init; verfy hook install"
  }
  catch {
    Write-Host "verfy: error: $($_.Exception.Message)" -ForegroundColor Red
  }
  finally {
    Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
  }
}
