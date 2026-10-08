<#
.SYNOPSIS
  Verify the Authenticode signature of every Windows release artifact.

.DESCRIPTION
  Runs on the Windows release runner after the SignPath signing request
  (ADR 0324) and before the artifacts are attached to the GitHub Release. The
  signing request is a remote round trip: this check fails the lane if the
  signed artifacts did not come back, were signed by an unexpected certificate,
  or were extracted into the wrong directory.

  It verifies the three artifacts the artifact configuration signs:
  the NSIS installer, the portable executable, and the two first-party
  executables inside the portable ZIP.

.PARAMETER ReleaseDirectory
  Directory that holds the packaged release artifacts
  (normally apps/desktop/release).

.PARAMETER Version
  Release version without a leading "v" (normally apps/desktop/package.json).

.PARAMETER ExpectedPublisher
  Certificate common name every signature must carry. Defaults to the SignPath
  Foundation certificate that signs this project's artifacts.

.EXAMPLE
  powershell -NoProfile -ExecutionPolicy Bypass -File scripts/verify-windows-release-signing.ps1 `
    -ReleaseDirectory apps/desktop/release -Version 0.17.0
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)][string]$ReleaseDirectory,
  [Parameter(Mandatory = $true)][string]$Version,
  [string]$ExpectedPublisher = "SignPath Foundation"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
Add-Type -AssemblyName System.IO.Compression.FileSystem

function Assert-SignedArtifact {
  param(
    [Parameter(Mandatory = $true)][string]$Path,
    [Parameter(Mandatory = $true)][string]$Label
  )

  $signature = Get-AuthenticodeSignature -LiteralPath $Path
  if ($signature.Status -ne [System.Management.Automation.SignatureStatus]::Valid) {
    throw "$Label is not validly signed: $Path ($($signature.Status): $($signature.StatusMessage))"
  }
  $subject = $signature.SignerCertificate.Subject
  if ($ExpectedPublisher -and ($subject -notlike "*CN=$ExpectedPublisher*")) {
    throw "$Label was signed by an unexpected certificate: $subject"
  }
  $timestamp = $signature.TimeStamperCertificate
  if ($timestamp -eq $null) {
    Write-Warning "$Label carries no timestamp counter-signature; the signature expires with the certificate."
  }
  Write-Host "signed: $Label <- $subject"
}

function Expand-SignedZipMember {
  param(
    [Parameter(Mandatory = $true)][string]$ArchivePath,
    [Parameter(Mandatory = $true)][string]$EntryName,
    [Parameter(Mandatory = $true)][string]$DestinationDirectory
  )

  $archive = [System.IO.Compression.ZipFile]::OpenRead($ArchivePath)
  try {
    $entry = $archive.GetEntry($EntryName)
    if ($entry -eq $null) {
      throw "$([System.IO.Path]::GetFileName($ArchivePath)) does not contain $EntryName"
    }
    $destination = Join-Path $DestinationDirectory ([System.IO.Path]::GetFileName($EntryName))
    [System.IO.Compression.ZipFileExtensions]::ExtractToFile($entry, $destination, $true)
    return $destination
  }
  finally {
    $archive.Dispose()
  }
}

$releaseRoot = (Resolve-Path -LiteralPath $ReleaseDirectory).Path
$installer = Join-Path $releaseRoot "PI-Desktop-Setup-$Version.exe"
$portable = Join-Path $releaseRoot "PI-Desktop-Portable-$Version.exe"
$portableZip = Join-Path $releaseRoot "PI-Desktop-Portable-$Version.zip"

foreach ($artifact in @($installer, $portable, $portableZip)) {
  if (-not (Test-Path -LiteralPath $artifact)) {
    throw "Missing Windows release artifact: $artifact"
  }
}

Assert-SignedArtifact -Path $installer -Label "NSIS installer"
Assert-SignedArtifact -Path $portable -Label "portable executable"

# The ZIP distribution is extracted by the user, so its executables have to
# carry their own signatures: the archive has no signature of its own.
$extractionRoot = Join-Path ([System.IO.Path]::GetTempPath()) "pi-desktop-signature-check-$([guid]::NewGuid().ToString('N'))"
New-Item -ItemType Directory -Path $extractionRoot | Out-Null
try {
  foreach ($entryName in @("PI-Desktop.exe", "resources/bin/pi-desktop-host-core.exe")) {
    $extracted = Expand-SignedZipMember -ArchivePath $portableZip -EntryName $entryName -DestinationDirectory $extractionRoot
    Assert-SignedArtifact -Path $extracted -Label $entryName
  }
}
finally {
  Remove-Item -LiteralPath $extractionRoot -Recurse -Force
}

Write-Host "All Windows release artifacts carry valid Authenticode signatures."
