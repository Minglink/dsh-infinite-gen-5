<#
  Builds a verified v1.4.0+ headless-slim IG5 runtime donor and companion third-party
  compliance source archive into an independent output directory.
  Never modifies the read-only 1.0.0 donor or the source repository in place.
#>
[CmdletBinding()]
param(
    [string]$DonorRuntimeRoot,
    [string]$SourceRoot,
    [string]$OutputRoot,
    [string]$TargetVersion = '1.4.0',
    [switch]$SkipSourcesZip,
    [switch]$SkipDonorVerify
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'runtime_pack.ps1')

if (-not (Test-IG5VersionAtLeast $TargetVersion '1.4.0')) {
    throw "Slim donor target version must be >= 1.4.0 (got '$TargetVersion'); keep 1.0.0-1.3.0 sealed donor untouched."
}
$repo = if ($SourceRoot) { Get-IG5FullPath $SourceRoot } else { Get-IG5FullPath (Join-Path $PSScriptRoot '..') }
$donor = if ($DonorRuntimeRoot) { Get-IG5FullPath $DonorRuntimeRoot } else { Get-IG5FullPath (Join-Path $repo 'runtimes') }
if (-not $OutputRoot) {
    $OutputRoot = Join-Path $env:USERPROFILE (".dsh\ig5\releases\IG5-$TargetVersion-slim-donor-" + (Get-Date -Format 'yyyyMMdd-HHmmss'))
}
$output = Get-IG5FullPath $OutputRoot
Assert-IG5NoReparsePath $donor
Assert-IG5NoReparsePath $repo
Assert-IG5NoReparsePath $output
foreach ($protected in @($repo, $donor)) {
    if ($output -eq $protected -or $output.StartsWith($protected + '\', [StringComparison]::OrdinalIgnoreCase)) {
        throw "Slim donor output directory must live outside source/donor trees: $output"
    }
}
if (Test-IG5Path $output) { throw "Slim donor output directory already exists: $output" }

if (-not $SkipDonorVerify) {
    $donorValidated = Assert-IG5RuntimePack $donor
    $donorManifestSha = Get-IG5Hash $donorValidated.ManifestPath
} else {
    $donorManifestPath = Join-Path $donor 'manifest.json'
    if (-not (Test-IG5Path $donorManifestPath Leaf)) { throw "Missing donor manifest.json: $donorManifestPath" }
    $donorManifestSha = Get-IG5Hash $donorManifestPath
}

$ghidraCfg = Read-IG5Text (Join-Path $donor 'ghidra\runtime.json') | ConvertFrom-Json
$javaRel = ('ghidra/' + ([string]$ghidraCfg.javaHome).Replace('\', '/').Trim('/'))
$ghidraRel = ('ghidra/' + ([string]$ghidraCfg.ghidraHome).Replace('\', '/').Trim('/'))

function Test-IG5SlimExcludedRuntimeFile {
    param([string]$Relative)
    $rel = $Relative.Replace('\', '/')
    # JDK non-headless/dev artifacts (keep bin/, conf/, lib/modules, legal/)
    if ($rel.StartsWith("$javaRel/jmods/", [StringComparison]::OrdinalIgnoreCase)) { return $true }
    if ($rel.Equals("$javaRel/lib/src.zip", [StringComparison]::OrdinalIgnoreCase)) { return $true }
    if ($rel.Equals("$javaRel/lib/ct.sym", [StringComparison]::OrdinalIgnoreCase)) { return $true }
    # Ghidra non-headless GUI/docs/server/BSim/extension zips (keep Decompiler, Base, FunctionID, Processors/*/data/languages, pyghidra, licenses)
    if ($rel.StartsWith("$ghidraRel/docs/", [StringComparison]::OrdinalIgnoreCase)) { return $true }
    if ($rel.StartsWith("$ghidraRel/Extensions/Ghidra/", [StringComparison]::OrdinalIgnoreCase) -and $rel.EndsWith('.zip', [StringComparison]::OrdinalIgnoreCase)) { return $true }
    if ($rel.StartsWith("$ghidraRel/Ghidra/Debug/", [StringComparison]::OrdinalIgnoreCase)) { return $true }
    if ($rel.StartsWith("$ghidraRel/Ghidra/Features/BSim/", [StringComparison]::OrdinalIgnoreCase)) { return $true }
    if ($rel.StartsWith("$ghidraRel/Ghidra/Features/GhidraServer/", [StringComparison]::OrdinalIgnoreCase)) { return $true }
    return $false
}

$parentDir = Split-Path $output -Parent
[IO.Directory]::CreateDirectory((ConvertTo-IG5IOPath $parentDir)) | Out-Null
$token = [Guid]::NewGuid().ToString('N')
$stage = Join-Path $parentDir ".ig5-slim-donor-$token"
$utf8NoBom = [Text.UTF8Encoding]::new($false)

try {
    [IO.Directory]::CreateDirectory((ConvertTo-IG5IOPath $stage)) | Out-Null
    $slimRuntime = Join-Path $stage 'runtimes'
    [IO.Directory]::CreateDirectory((ConvertTo-IG5IOPath $slimRuntime)) | Out-Null

    $extensions = Assert-IG5RuntimeExtensions $donor
    $records = New-Object 'System.Collections.Generic.List[object]'
    $excludedFiles = 0
    $excludedBytes = [long]0
    $keptBytes = [long]0
    $copiedCount = 0

    Write-Host "[SLIM] Copying headless-slim runtime from $donor ..."
    foreach ($file in (Get-IG5PackFiles $donor | Sort-Object FullName)) {
        $relative = Get-IG5RelativePath $donor $file.FullName
        if ($relative -eq 'manifest.json') { continue }
        if (-not $extensions.ContainsKey($relative) -and (Test-IG5SlimExcludedRuntimeFile $relative)) {
            $excludedFiles++
            $excludedBytes += [long]$file.Length
            continue
        }
        $dest = Resolve-IG5PackPath $slimRuntime $relative
        [IO.Directory]::CreateDirectory((ConvertTo-IG5IOPath (Split-Path $dest -Parent))) | Out-Null
        [IO.File]::Copy((ConvertTo-IG5IOPath $file.FullName), (ConvertTo-IG5IOPath $dest), $true)
        $copiedCount++
        $keptBytes += [long]$file.Length
        if (-not $extensions.ContainsKey($relative)) {
            $records.Add(@{ path = $relative; bytes = [long]$file.Length; sha256 = (Get-IG5Hash $dest) })
        }
        if ($copiedCount % 2048 -eq 0) { Write-Host "[SLIM] Runtime files copied & hashed: $copiedCount ..." }
    }

    $sortedRecords = @($records | Sort-Object { $_.path })
    $manifest = [ordered]@{
        schemaVersion = 1
        pluginVersion = $TargetVersion
        platform = 'win32-x64'
        profile = 'headless-slim'
        createdAt = [DateTime]::UtcNow.ToString('o')
        donorManifestSha256 = $donorManifestSha
        engines = @('ghidra', 'x64dbg')
        excludedSummary = [ordered]@{
            files = $excludedFiles
            bytes = $excludedBytes
            components = @('jdk/jmods', 'jdk/lib/src.zip', 'jdk/lib/ct.sym', 'ghidra/docs', 'ghidra/Extensions/Ghidra/*.zip', 'ghidra/Ghidra/Debug', 'ghidra/Ghidra/Features/BSim', 'ghidra/Ghidra/Features/GhidraServer')
        }
        files = $sortedRecords
    }
    [IO.File]::WriteAllText((ConvertTo-IG5IOPath (Join-Path $slimRuntime 'manifest.json')), ($manifest | ConvertTo-Json -Depth 8), $utf8NoBom)

    Write-Host "[SLIM] Verifying generated $TargetVersion slim runtime with Assert-IG5RuntimePack ..."
    $verifiedSlim = Assert-IG5RuntimePack $slimRuntime

    $sourcesZipPath = ''
    $sourcesZipBytes = [long]0
    $sourcesZipSha = ''
    $companionOut = ''
    if (-not $SkipSourcesZip) {
        $sourcesRoot = Join-Path $repo 'third_party\sources'
        $sourcesManifestPath = Join-Path $sourcesRoot 'manifest.json'
        if (-not (Test-IG5Path $sourcesManifestPath Leaf)) { throw "Missing third_party/sources/manifest.json: $sourcesManifestPath" }
        $sourcesManifest = Read-IG5Text $sourcesManifestPath | ConvertFrom-Json
        $sourcesManifestSha = Get-IG5Hash $sourcesManifestPath
        $provHashes = [ordered]@{}
        foreach ($src in $sourcesManifest.sources) {
            $invRel = ([string]$src.fileInventory).Replace('\', '/')
            $invPath = Resolve-IG5PackPath $sourcesRoot $invRel
            if (-not (Test-IG5Path $invPath Leaf)) { throw "Missing provenance inventory: $invRel" }
            $provHashes[$invRel] = Get-IG5Hash $invPath
        }
        $archiveName = "IG5-$TargetVersion-sources-compliance.zip"
        $sourcesZipPath = Join-Path $stage $archiveName
        Write-Host "[SLIM] Archiving third_party/sources -> $archiveName ..."
        Add-Type -AssemblyName System.IO.Compression
        $sourceFiles = @(Get-IG5PackFiles $sourcesRoot | Sort-Object FullName)
        $zipStream = [IO.File]::Create((ConvertTo-IG5IOPath $sourcesZipPath))
        $zip = [IO.Compression.ZipArchive]::new($zipStream, [IO.Compression.ZipArchiveMode]::Create)
        $archivedCount = 0
        try {
            $buf = New-Object byte[] 262144
            foreach ($f in $sourceFiles) {
                $rel = Get-IG5RelativePath $sourcesRoot $f.FullName
                $entry = $zip.CreateEntry("third_party/sources/$rel", [IO.Compression.CompressionLevel]::Optimal)
                $inStream = [IO.File]::OpenRead((ConvertTo-IG5IOPath $f.FullName))
                $outStream = $entry.Open()
                try {
                    while (($n = $inStream.Read($buf, 0, $buf.Length)) -gt 0) { $outStream.Write($buf, 0, $n) }
                } finally {
                    $outStream.Dispose()
                    $inStream.Dispose()
                }
                $archivedCount++
                if ($archivedCount % 8192 -eq 0) { Write-Host "[SLIM] Compliance sources archived: $archivedCount / $($sourceFiles.Count) ..." }
            }
        } finally {
            $zip.Dispose()
            $zipStream.Dispose()
        }
        $sourcesZipBytes = (New-Object IO.FileInfo (ConvertTo-IG5IOPath $sourcesZipPath)).Length
        $sourcesZipSha = Get-IG5Hash $sourcesZipPath
        $companion = [ordered]@{
            schemaVersion = 1
            pluginVersion = $TargetVersion
            createdAt = [DateTime]::UtcNow.ToString('o')
            archiveName = $archiveName
            archiveBytes = $sourcesZipBytes
            archiveSha256 = $sourcesZipSha
            archivedFileCount = $archivedCount
            sourceManifestSha256 = $sourcesManifestSha
            provenanceSha256 = $provHashes
        }
        $companionOut = Join-Path $stage 'companion-sources.json'
        [IO.File]::WriteAllText((ConvertTo-IG5IOPath $companionOut), ($companion | ConvertTo-Json -Depth 8), $utf8NoBom)
    }

    Move-Item -LiteralPath $stage -Destination $output
    Write-Output ("SLIM_DONOR_ROOT=" + $output)
    Write-Output ("RUNTIME_ROOT=" + (Join-Path $output 'runtimes'))
    Write-Output ("RUNTIME_FILES=" + $verifiedSlim.Files)
    Write-Output ("RUNTIME_TOTAL_COPIED=" + $copiedCount)
    Write-Output ("RUNTIME_BYTES=" + $keptBytes)
    Write-Output ("EXCLUDED_RUNTIME_FILES=" + $excludedFiles)
    Write-Output ("EXCLUDED_RUNTIME_BYTES=" + $excludedBytes)
    if (-not $SkipSourcesZip) {
        Write-Output ("SOURCES_ZIP=" + (Join-Path $output "IG5-$TargetVersion-sources-compliance.zip"))
        Write-Output ("SOURCES_ZIP_BYTES=" + $sourcesZipBytes)
        Write-Output ("SOURCES_ZIP_SHA256=" + $sourcesZipSha)
        Write-Output ("COMPANION_MANIFEST=" + (Join-Path $output 'companion-sources.json'))
    }
} catch {
    if (Test-IG5Path $stage) { Remove-IG5Tree $stage }
    throw
}
