# Builds the two Nexus archives from carry\dist and prints their SHA-256.
#
#   powershell -ExecutionPolicy Bypass -File "<repo>\carry\package.ps1"
#
# BountyTeleportation-<version>.zip      manual install: plugin, ini, readme, licences
# BountyTeleportation-<version>-DMM.zip  Definitive Mod Manager: the plugin alone,
#                                which is all DMM registers. The plugin writes
#                                the same ini itself on a first run, so the mod
#                                is complete without it.
#
# Run build.bat first; this script packages what is in dist and refuses if the
# plugin there is older than the sources.
[CmdletBinding()]
param([switch] $Unsigned)

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$dist = Join-Path $here 'dist'
$root = Split-Path -Parent $here

$version = (Select-String -Path (Join-Path $here 'src\version.h') -Pattern '#define BT_VERSION\s+"([^"]+)"').Matches[0].Groups[1].Value
if (-not $version) { throw 'no BT_VERSION in src\version.h' }

$asi = Join-Path $dist 'BountyTeleportation.asi'
$ini = Join-Path $dist 'BountyTeleportation.ini'
foreach ($f in @($asi, $ini)) { if (-not (Test-Path $f)) { throw "missing $f; run build.bat" } }

# Five of the plugin's sources live in the probe next door, so both trees
# count when deciding whether the built plugin is stale.
$newestSource = Get-ChildItem (Join-Path $here 'src'), (Join-Path $root 'mod\src') -Recurse -File |
    Sort-Object LastWriteTime -Descending | Select-Object -First 1
if ($newestSource.LastWriteTime -gt (Get-Item $asi).LastWriteTime) {
    throw "$($newestSource.Name) is newer than the built plugin; run build.bat first"
}

# The addresses are the whole mod, so check them against the executable before
# building an archive around them.
$verify = Join-Path $root 'research\verify_carry.py'
if (Test-Path $verify) {
    & py -3 $verify | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "verify_carry.py found a mismatch; run it and read the output" }
    Write-Host 'verify_carry.py: all six addresses match the executable'
}

# Sign before packaging, never after: these archives carry the plugin and the
# checksums on the Nexus page are of the signed file.
if (-not $Unsigned) {
    $sig = Get-AuthenticodeSignature $asi
    if ($sig.Status -ne 'Valid') {
        throw "$asi is not signed (status $($sig.Status)). Run carry\scripts\sign.ps1, or pass -Unsigned to package anyway."
    }
    Write-Host ("Signed by {0}" -f $sig.SignerCertificate.Subject)
}

$staging = Join-Path $env:TEMP "bt-package-$version"
Remove-Item $staging -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Path $staging | Out-Null
Copy-Item $asi, $ini $staging
Copy-Item (Join-Path $here 'README.md') $staging
Copy-Item (Join-Path $root 'LICENSE') $staging
Copy-Item (Join-Path $root 'THIRD_PARTY_NOTICES.md') $staging

$plain = Join-Path $dist "BountyTeleportation-$version.zip"
$dmm = Join-Path $dist "BountyTeleportation-$version-DMM.zip"
Remove-Item $plain, $dmm -Force -ErrorAction SilentlyContinue
Compress-Archive -Path (Join-Path $staging '*') -DestinationPath $plain
Compress-Archive -Path $asi -DestinationPath $dmm
Remove-Item $staging -Recurse -Force

Write-Host "`nBounty Teleportation $version"
foreach ($z in @($plain, $dmm)) {
    Write-Host ("  {0,-34} {1,9:N0} bytes" -f (Split-Path $z -Leaf), (Get-Item $z).Length)
    [System.IO.Compression.ZipFile]::OpenRead($z).Entries | ForEach-Object { Write-Host "      $($_.FullName)" }
}
Write-Host "`nSHA-256:"
Get-FileHash $dmm, $plain, $asi -Algorithm SHA256 |
    ForEach-Object { Write-Host ("{0}  {1}" -f $_.Hash.ToLower(), (Split-Path $_.Path -Leaf)) }
