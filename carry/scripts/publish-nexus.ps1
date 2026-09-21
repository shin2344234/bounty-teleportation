<#
.SYNOPSIS
    Publish the current release to the Bounty Teleportation mod page.

.DESCRIPTION
    A wrapper around Publish-NexusModUpdate.ps1 that fills in the three things
    that never change and the two that follow from the version, so a release
    does not depend on remembering an id.

        Mod id  38521561681384   the v3 id, not the 3560 in the page URL
        File id 8001705          the active "BountyTeleportation 1.0.0 DMM" entry

    Both were read back with nexus-ids.py on 20 September 2026, once page 3560
    was up and 1.0.0 had been uploaded by hand, and they are stable for the
    life of the page. This wrapper is for the releases after 1.0.0. Running it
    for a version already listed would post the changelog a second time, and
    the check below refuses that.

    The file id is the one worth being careful about. Point a release at the
    wrong one and it attaches as a version of some other file.

    The version comes from mod/src/version.h, and the archive and changelog are
    derived from it, so this only ever publishes what package.ps1 built.

    Report only unless you pass -Apply, same as the script it wraps.

    The previous version is left listed, never archived. Archiving hides it,
    and people who need an older build (kfen72 asked, 9 September 2026) then
    have nothing to download. Nothing has to be done by hand for that: Nexus
    demotes the previous file to old_version on its own once the new one goes
    up as primary, and an old_version file keeps its download button and only
    loses the headline slot. Confirmed against Master Looter page 3402, where
    1.6.32 and every build before it read old_version and all download.
    -ArchivePrevious is the opt-in for pulling a build outright, which is the
    thing Seth does not want.

.EXAMPLE
    .\publish-nexus.ps1
    .\publish-nexus.ps1 -Apply
#>
[CmdletBinding()]
param(
    # Nothing is sent to Nexus without this.
    [switch] $Apply,

    # Override the version read from version.h.
    [string] $Version,

    # Archive the previous version. Off by default and meant to stay off:
    # archiving hides a build, and older ones are kept downloadable on purpose.
    # Nexus demotes the previous file to old_version by itself, so nothing is
    # owed here.
    [switch] $ArchivePrevious
)

$ErrorActionPreference = 'Stop'

$here = $PSScriptRoot
$mod  = Split-Path $here -Parent
$repo = Split-Path $mod -Parent

if ([string]::IsNullOrWhiteSpace($Version)) {
    $header = Join-Path $mod 'src\version.h'
    $match  = Select-String -LiteralPath $header -Pattern '#define\s+BT_VERSION\s+"([^"]+)"'
    if (-not $match) { throw "No BT_VERSION in $header" }
    $Version = $match.Matches[0].Groups[1].Value
}

$archive   = Join-Path $mod  ("dist\BountyTeleportation-{0}-DMM.zip" -f $Version)
$changelog = Join-Path $repo ("private\nexus\nexus-changelog-{0}.txt" -f $Version)

if (-not (Test-Path -LiteralPath $archive)) {
    throw "No archive at $archive. Run package.ps1 first."
}
if (-not (Test-Path -LiteralPath $changelog)) {
    throw "No changelog at $changelog. Write it before publishing."
}

Write-Host ("Version $Version, from version.h") -ForegroundColor Cyan

# The changelog endpoint appends rather than replaces, so a second run for one
# version posts the text twice. Check what is already up there and refuse
# rather than leave a duplicated page to clean up by hand.
# The two ids from nexus-ids.py, in one place. They were written out twice,
# once in the duplicate check and once in the arguments, which is one edit away
# from a release attaching itself to the wrong file entry.
#
# Read back from the API on 20 September 2026, once page 3560 was published and
# 1.0.0 was uploaded by hand. They are stable for the life of the page. Get
# them wrong and a release publishes onto somebody else's page, which is how a
# Glint Spotter announcement reached the Flight Freedom page on 14 September
# 2026. Re-read them with nexus-ids.py if the page is ever restructured.
#
# 8001708 is the other entry, the manual archive. This wrapper does not touch
# it; that one goes through Publish-NexusModUpdate.ps1 with -FileId directly,
# and publishing the wrapper alone leaves the main download a version behind.
$ids = @{
    FileId = '8001705'          # the active "BountyTeleportation 1.0.0 DMM" entry
    ModId  = '38521561681384'   # the v3 mod id, not the 3560 in the page URL
}
foreach ($pair in $ids.GetEnumerator()) {
    if ($pair.Value -eq 'SET-ME') {
        throw ("{0} is not set in publish-nexus.ps1. The Bounty Teleportation page has to exist and 1.0.0 " +
               "has to be uploaded by hand before anything here can publish. Run nexus-ids.py once it " +
               "does and paste the ids in." -f $pair.Key)
    }
}

if ($Apply) {
    $key = $env:NEXUS_API_KEY
    if ([string]::IsNullOrWhiteSpace($key)) {
        $keyFile = Join-Path $here 'keys.local.env'
        if (Test-Path -LiteralPath $keyFile) {
            foreach ($line in Get-Content -LiteralPath $keyFile) {
                $t = $line.Trim()
                if ($t -match '^\s*(#|$)') { continue }
                $n, $v = $t -split '=', 2
                if ($n.Trim() -eq 'NEXUS_API_KEY') { $key = $v.Trim().Trim('"').Trim("'"); break }
            }
        }
    }
    if (-not [string]::IsNullOrWhiteSpace($key)) {
        try {
            $existing = Invoke-RestMethod -Uri "https://api.nexusmods.com/v3/mod-files/$($ids.FileId)/versions" `
                                          -Headers @{ 'apikey' = $key } -Method Get
            $already = $existing.data.versions | Where-Object { $_.version -eq $Version }
            if ($already) {
                Write-Host ""
                Write-Host ("Version {0} is already on the mod page, uploaded {1}." -f $Version, $already[0].uploaded_at) -ForegroundColor Red
                Write-Host "Publishing it again would list a second copy and post the changelog twice." -ForegroundColor Red
                Write-Host "Nothing was sent. Bump version.h and rebuild, or pass -Version for a different one." -ForegroundColor Red
                exit 1
            }
        } catch {
            Write-Warning ("Could not check what is already published ({0}); continuing." -f $_.Exception.Message)
        }
    }
}

$args = @{
    FilePath                  = $archive
    FileId                    = $ids.FileId
    ModId                     = $ids.ModId
    Version                   = $Version
    DisplayName               = ("BountyTeleportation {0} DMM" -f $Version)
    ChangelogPath             = $changelog
    Category                  = 'main'
    UpdateModVersion          = $true
    PrimaryModManagerDownload = $true
}
if ($ArchivePrevious) { $args['ArchiveExistingFile'] = $true }
if ($Apply)             { $args['Apply']               = $true }

& (Join-Path $here 'Publish-NexusModUpdate.ps1') @args

if ($Apply) {
    Write-Host ""
    Write-Host "Still manual, because the v3 API has no endpoint for either:" -ForegroundColor Yellow
    Write-Host "  the page description  -> private\nexus\nexus-description.bbcode"
    Write-Host ("  the update post       -> private\nexus\nexus-post-{0}.bbcode" -f $Version)
}
