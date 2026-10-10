# Source ZIP installation supplements only pinned runtime/upstream assets.
# The checked-out plugin code is never replaced by release code.
function Get-IG5DistributionDescriptor {
    param([string]$SourceRoot, [string]$PluginVersion)
    try { $d = Read-IG5Text (Join-Path $SourceRoot 'scripts\distribution.json') | ConvertFrom-Json }
    catch { throw 'Invalid scripts/distribution.json' }
    if ($d.schemaVersion -ne 1 -or $d.pluginVersion -ne $PluginVersion -or $d.repository -cne 'Minglink/dsh-infinite-gen-5' -or
        [string]$d.releaseTag -notmatch '^v1\.0\.0-[a-z0-9-]+$' -or [string]$d.assetName -notmatch '^IG5-1\.0\.0-Windows-x64-[a-z0-9-]+\.zip$') { throw 'Distribution identity/version is invalid' }
    foreach ($field in @('runtimeManifestSha256','sourceManifestSha256')) {
        if ([string]$d.$field -notmatch '^[a-f0-9]{64}$') { throw "Invalid distribution SHA-256: $field" }
    }
    if ($d.assetSha256 -and ([string]$d.assetSha256 -notmatch '^[a-f0-9]{64}$' -or [long]$d.assetBytes -le 0 -or [long]$d.assetBytes -gt 2GB)) { throw 'Invalid pinned distribution archive digest/size' }
    $sourcePins = @($d.sourceInventorySha256.PSObject.Properties)
    if (-not $sourcePins.Count -or $sourcePins.Count -gt 16) { throw 'Distribution source inventory pins are missing/invalid' }
    foreach ($pin in $sourcePins) {
        $null = Resolve-IG5PackPath $SourceRoot ([string]$pin.Name)
        if ([string]$pin.Value -notmatch '^[a-f0-9]{64}$') { throw "Invalid source inventory SHA-256: $($pin.Name)" }
    }
    foreach ($name in @('ig5-bridge.dp32','ig5-bridge.dp64')) {
        if ([string]$d.nativeBridgeSha256.$name -notmatch '^[a-f0-9]{64}$' -or
            (Get-IG5Hash (Join-Path $SourceRoot "adapters\x64dbg\native\$name")) -ne $d.nativeBridgeSha256.$name) { throw "Source bridge does not match pinned distribution: $name" }
    }
    return $d
}

function Get-IG5DistributionUrl {
    param($Descriptor)
    return "https://github.com/$($Descriptor.repository)/releases/tag/$($Descriptor.releaseTag)"
}

function Assert-IG5DownloadUrl {
    param([string]$Url)
    $uri = [Uri]$Url
    if ($uri.Scheme -ne 'https' -or -not $uri.IsDefaultPort -or $uri.UserInfo -or
        $uri.Host -notin @('api.github.com','github.com','release-assets.githubusercontent.com','objects.githubusercontent.com','github-releases.githubusercontent.com')) { throw 'Release download redirected to an untrusted URL' }
    return $uri
}

function Invoke-IG5DistributionDownload {
    param([string]$Url, [string]$OutputPath, [long]$MaxBytes, [long]$ExpectedBytes = -1, [switch]$Progress)
    $uri = Assert-IG5DownloadUrl $Url
    $response = $null
    $inputStream = $null
    $outputStream = $null
    $watch = [Diagnostics.Stopwatch]::StartNew()
    $originalTls = [Net.ServicePointManager]::SecurityProtocol
    try {
        [Net.ServicePointManager]::SecurityProtocol = $originalTls -bor [Net.SecurityProtocolType]::Tls12
        for ($redirect = 0; $redirect -le 6; $redirect++) {
            $request = [Net.HttpWebRequest]::Create($uri)
            $request.UserAgent = 'IG5-Source-Installer/1.0.0'
            $request.Accept = 'application/vnd.github+json, application/octet-stream, text/plain'
            $request.Timeout = 20000
            $request.ReadWriteTimeout = 30000
            $request.AllowAutoRedirect = $false
            try { $response = $request.GetResponse() }
            catch { throw "Release network request failed ($($_.Exception.Status)); check connectivity or use -DistributionRoot / -Offline." }
            $status = [int]$response.StatusCode
            if ($status -in @(301,302,303,307,308)) {
                $location = $response.Headers['Location']
                if (-not $location -or $redirect -eq 6) { throw 'Release redirect limit exceeded' }
                $next = [Uri]::new($uri, $location)
                $uri = Assert-IG5DownloadUrl $next.AbsoluteUri
                $response.Close(); $response = $null
                continue
            }
            if ($status -ne 200) { throw "Release request returned HTTP $status" }
            break
        }
        if (-not $response -or $response.ContentLength -gt $MaxBytes -or
            ($ExpectedBytes -ge 0 -and $response.ContentLength -ge 0 -and $response.ContentLength -ne $ExpectedBytes)) { throw 'Release response length is invalid' }
        $inputStream = $response.GetResponseStream()
        if ($OutputPath) { $outputStream = [IO.File]::Create((ConvertTo-IG5IOPath $OutputPath)) }
        else { $outputStream = [IO.MemoryStream]::new() }
        $buffer = New-Object byte[] 1048576
        $received = [long]0
        $nextNotice = [long]0
        while (($read = $inputStream.Read($buffer, 0, $buffer.Length)) -gt 0) {
            $received += $read
            if ($received -gt $MaxBytes -or $watch.Elapsed.TotalSeconds -gt 3600) { throw 'Release download size/time budget exceeded' }
            $outputStream.Write($buffer, 0, $read)
            if ($Progress -and $received -ge $nextNotice) {
                $percent = if ($ExpectedBytes -gt 0) { [Math]::Min(100, [int](100 * $received / $ExpectedBytes)) } else { 0 }
                Write-Progress -Activity 'IG5 full release download' -Status ("{0:N1} / {1:N1} MiB" -f ($received / 1MB), ($ExpectedBytes / 1MB)) -PercentComplete $percent
                Write-Host ("[DOWNLOAD] {0:N1} / {1:N1} MiB ({2}%)" -f ($received / 1MB), ($ExpectedBytes / 1MB), $percent)
                $nextNotice = $received + 64MB
            }
        }
        if ($ExpectedBytes -ge 0 -and $received -ne $ExpectedBytes) { throw 'Release download is truncated' }
        if (-not $OutputPath) { return [Text.Encoding]::UTF8.GetString($outputStream.ToArray()) }
    } finally {
        if ($inputStream) { $inputStream.Dispose() }
        if ($outputStream) { $outputStream.Dispose() }
        if ($response) { $response.Close() }
        [Net.ServicePointManager]::SecurityProtocol = $originalTls
        if ($Progress) { Write-Progress -Activity 'IG5 full release download' -Completed }
    }
}

function Get-IG5ReleaseMetadata {
    param($Descriptor)
    $url = "https://api.github.com/repos/$($Descriptor.repository)/releases/tags/$($Descriptor.releaseTag)"
    for ($attempt = 1; $attempt -le 2; $attempt++) {
        try {
            $text = Invoke-IG5DistributionDownload $url '' 4MB
            $release = $text | ConvertFrom-Json
            if ($release.tag_name -cne $Descriptor.releaseTag -or $release.draft) { throw 'Release metadata identity is invalid' }
            return $release
        } catch { if ($attempt -eq 2) { throw }; Start-Sleep -Milliseconds 500 }
    }
}

function Get-IG5Asset {
    param($Release, [string]$Name, $Descriptor)
    $matches = @($Release.assets | Where-Object { $_.name -ceq $Name })
    if ($matches.Count -ne 1 -or [long]$matches[0].size -le 0) { throw "Pinned release asset unavailable: $Name" }
    $asset = $matches[0]
    $expected = "https://github.com/$($Descriptor.repository)/releases/download/$($Descriptor.releaseTag)/$Name"
    if ($asset.browser_download_url -cne $expected) { throw "Release asset URL identity differs: $Name" }
    return $asset
}

function Expand-IG5VerifiedZip {
    param([string]$ZipPath, [string]$Destination)
    Assert-IG5NoReparsePath $Destination
    if (Test-IG5Path $Destination) { throw 'ZIP destination must not already exist' }
    Add-Type -AssemblyName System.IO.Compression
    $stream = [IO.File]::OpenRead((ConvertTo-IG5IOPath $ZipPath))
    $zip = $null
    try {
        $zip = [IO.Compression.ZipArchive]::new($stream, [IO.Compression.ZipArchiveMode]::Read)
        if ($zip.Entries.Count -lt 1 -or $zip.Entries.Count -gt 100000) { throw 'Release ZIP entry budget is invalid' }
        $seen = @{}
        $nodes = @{}
        $total = [long]0
        # Validate every path/type/length before writing a single extracted file.
        foreach ($entry in $zip.Entries) {
            $relative = [string]$entry.FullName
            $isDirectory = $relative.EndsWith('/')
            $key = $relative.TrimEnd('/')
            if (-not $key -or $relative.Contains('\') -or $relative.StartsWith('/') -or $relative.Contains(':') -or $relative -match '[\x00-\x1f]' -or $key.Length -gt 2048) { throw "Unsafe ZIP path: $relative" }
            foreach ($part in $key.Split('/')) {
                if (-not $part -or $part -in @('.','..') -or $part -match '[<>"|?*]' -or $part.EndsWith('.') -or $part.EndsWith(' ') -or $part -match '^(?i:CON|PRN|AUX|NUL|COM[0-9]|LPT[0-9])(?:\.|$)') { throw "Unsafe ZIP path: $relative" }
            }
            $null = Resolve-IG5PackPath $Destination $key
            if ($seen.ContainsKey($key)) { throw "Duplicate ZIP path: $relative" }
            $seen[$key] = $true
            $attrs = [long]$entry.ExternalAttributes
            $unixType = ($attrs -shr 16) -band 61440
            if (($attrs -band 1024) -or $unixType -notin @(0,32768,16384)) { throw "ZIP link/special entry rejected: $relative" }
            if ($entry.Length -lt 0 -or $entry.Length -gt 512MB -or ($isDirectory -and $entry.Length -ne 0)) { throw "ZIP entry size invalid: $relative" }
            $total += [long]$entry.Length
            if ($total -gt 6GB) { throw 'Release ZIP expanded size budget exceeded' }
            if ($nodes.ContainsKey($key) -and (-not $isDirectory -or -not $nodes[$key])) { throw "ZIP file/directory collision: $relative" }
            $nodes[$key] = $isDirectory
            $parent = $key
            while ($parent.Contains('/')) {
                $parent = $parent.Substring(0, $parent.LastIndexOf('/'))
                if ($nodes.ContainsKey($parent) -and -not $nodes[$parent]) { throw "ZIP file/directory collision: $relative" }
                $nodes[$parent] = $true
            }
        }
        [IO.Directory]::CreateDirectory((ConvertTo-IG5IOPath $Destination)) | Out-Null
        $extractWatch = [Diagnostics.Stopwatch]::StartNew()
        $buffer = New-Object byte[] 1048576
        $actualTotal = [long]0
        $extractCount = 0
        if ($zip.Entries.Count -ge 4096) { Write-Host "[EXTRACT] $($zip.Entries.Count) validated entries; extracting with byte/time limits..." }
        foreach ($entry in $zip.Entries) {
            $full = Resolve-IG5PackPath $Destination ($entry.FullName.TrimEnd('/'))
            if ($entry.FullName.EndsWith('/')) { [IO.Directory]::CreateDirectory((ConvertTo-IG5IOPath $full)) | Out-Null; continue }
            [IO.Directory]::CreateDirectory((ConvertTo-IG5IOPath (Split-Path $full -Parent))) | Out-Null
            $inputStream = $entry.Open()
            $outputStream = [IO.File]::Open((ConvertTo-IG5IOPath $full), [IO.FileMode]::CreateNew, [IO.FileAccess]::Write)
            try {
                $written = [long]0
                while (($read = $inputStream.Read($buffer, 0, $buffer.Length)) -gt 0) {
                    # Enforce central-directory sizes before each write, including forged small lengths.
                    if ($written + $read -gt $entry.Length -or $written + $read -gt 512MB -or $actualTotal + $read -gt 6GB -or $extractWatch.Elapsed.TotalSeconds -gt 1200) { throw "ZIP expanded byte/time budget exceeded: $($entry.FullName)" }
                    $outputStream.Write($buffer, 0, $read)
                    $written += $read
                    $actualTotal += $read
                }
                if ($written -ne $entry.Length) { throw "Truncated ZIP entry: $($entry.FullName)" }
            }
            finally { $outputStream.Dispose(); $inputStream.Dispose() }
            $extractCount++
            if ($zip.Entries.Count -ge 4096 -and $extractCount % 4096 -eq 0) { Write-Host "[EXTRACT] $extractCount / $($zip.Entries.Count) entries" }
        }
        if ($zip.Entries.Count -ge 4096) { Write-Host "[OK] Extracted $extractCount files" }
    } finally { if ($zip) { $zip.Dispose() }; $stream.Dispose() }
}

function Assert-IG5DistributionAssets {
    param([string]$DistributionRoot, $Descriptor, [string]$PluginVersion)
    $root = Get-IG5FullPath $DistributionRoot
    Assert-IG5NoReparsePath $root
    # A donor must be an intact extracted full release, including the outer inventory.
    if (-not (Test-IG5Path $root Container) -or ([IO.File]::GetAttributes((ConvertTo-IG5IOPath $root)) -band [IO.FileAttributes]::ReparsePoint)) { throw 'DistributionRoot must be a real extracted full release directory' }
    $manifestPath = Join-Path $root 'manifest.json'
    try { $release = Read-IG5Text $manifestPath | ConvertFrom-Json }
    catch { throw 'DistributionRoot needs the complete release manifest.json and plugin/ directory' }
    if ($release.schemaVersion -ne 1 -or $release.platform -ne 'win32-x64' -or $release.pluginVersion -ne $PluginVersion -or -not $release.files) { throw 'DistributionRoot release manifest identity/version is invalid' }
    $releaseFiles = @($release.files)
    foreach ($file in $releaseFiles) { if ([string]$file.path -eq 'manifest.json') { throw 'Release inventory must not include itself' } }
    $outerRecord = @{path='manifest.json';bytes=(New-Object IO.FileInfo (ConvertTo-IG5IOPath $manifestPath)).Length;sha256=(Get-IG5Hash $manifestPath)}
    Assert-IG5FileInventory $root @($releaseFiles + @($outerRecord)) 'complete-release' -IncludeExcluded
    $pluginRoot = Join-Path $root 'plugin'
    $null = Assert-IG5PinnedAssets $pluginRoot $Descriptor $PluginVersion
    return $pluginRoot
}

function Assert-IG5PinnedAssets {
    param([string]$PluginRoot, $Descriptor, [string]$PluginVersion)
    $pluginRoot = Get-IG5FullPath $PluginRoot
    Assert-IG5NoReparsePath $pluginRoot
    foreach ($pin in @(@('runtimes\manifest.json','runtimeManifestSha256'), @('third_party\sources\manifest.json','sourceManifestSha256'))) {
        if ((Get-IG5Hash (Join-Path $pluginRoot $pin[0])) -ne $Descriptor.($pin[1])) { throw "Pinned distribution manifest SHA-256 mismatch: $($pin[0])" }
    }
    $runtime = Assert-IG5RuntimePack (Join-Path $pluginRoot 'runtimes')
    if ($runtime.Manifest.pluginVersion -ne $PluginVersion) { throw 'Distribution runtime version mismatch' }
    $sourcesRoot = Join-Path $pluginRoot 'third_party\sources'
    $sourceManifest = Read-IG5Text (Join-Path $sourcesRoot 'manifest.json') | ConvertFrom-Json
    $inventoryPaths = @($sourceManifest.sources | ForEach-Object { [string]$_.fileInventory })
    if ($inventoryPaths.Count -ne @($Descriptor.sourceInventorySha256.PSObject.Properties).Count) { throw 'Distribution source inventory pin count mismatch' }
    foreach ($inventory in $inventoryPaths) {
        $inventoryPath = Resolve-IG5PackPath $sourcesRoot $inventory
        if (-not $Descriptor.sourceInventorySha256.$inventory -or (Get-IG5Hash $inventoryPath) -ne $Descriptor.sourceInventorySha256.$inventory) { throw "Pinned source inventory SHA-256 mismatch: $inventory" }
    }
    Assert-IG5SourceAssets $pluginRoot
    $cfg = Read-IG5Text (Join-Path $pluginRoot 'runtimes\x64dbg\runtime.json') | ConvertFrom-Json
    foreach ($bits in @('32','64')) {
        $relative = if ($bits -eq '64') { [string]$cfg.headlessExe } else { [string]$cfg.headless32Exe }
        $debugDir = Split-Path (Resolve-IG5PackPath (Join-Path $pluginRoot 'runtimes\x64dbg') $relative) -Parent
        $name = "ig5-bridge.dp$bits"
        if ((Get-IG5Hash (Join-Path $debugDir "plugins\$name")) -ne $Descriptor.nativeBridgeSha256.$name) { throw "Distribution native bridge mismatch: $name" }
    }
    return $runtime
}

function Remove-IG5BootstrapWorkspace {
    param([string]$Path)
    $safe = Get-IG5FullPath $Path
    $boundary = (Get-IG5FullPath ([IO.Path]::GetTempPath())) + '\'
    if (-not $safe.StartsWith($boundary, [StringComparison]::OrdinalIgnoreCase) -or (Split-Path $safe -Leaf) -notmatch '^ig5-bootstrap-[a-f0-9]{32}$') { throw 'Unsafe bootstrap workspace cleanup path' }
    if (Test-IG5Path $safe) {
        if ([IO.File]::GetAttributes((ConvertTo-IG5IOPath $safe)) -band [IO.FileAttributes]::ReparsePoint) { throw 'Bootstrap workspace cannot be a link' }
        Remove-IG5Tree $safe
    }
}

function Copy-IG5PinnedArchive {
    param([string]$Source, [string]$Destination, [long]$ExpectedBytes)
    if ($ExpectedBytes -le 0 -or $ExpectedBytes -gt 2GB) { throw 'Invalid archive copy budget' }
    $inputStream = [IO.File]::Open((ConvertTo-IG5IOPath $Source), [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    $outputStream = $null
    try {
        if ($inputStream.Length -ne $ExpectedBytes) { throw 'DistributionArchive size changed before copy' }
        $outputStream = [IO.File]::Open((ConvertTo-IG5IOPath $Destination), [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
        $buffer = New-Object byte[] 1048576
        $copied = [long]0
        while (($read = $inputStream.Read($buffer,0,$buffer.Length)) -gt 0) {
            if ($copied + $read -gt $ExpectedBytes) { throw 'DistributionArchive exceeded fixed copy budget' }
            $outputStream.Write($buffer,0,$read)
            $copied += $read
        }
        if ($copied -ne $ExpectedBytes) { throw 'DistributionArchive truncated during copy' }
    } finally { if ($outputStream) { $outputStream.Dispose() }; $inputStream.Dispose() }
}

function New-IG5SourceDistribution {
    param([string]$SourceRoot, [string]$PluginVersion, [string]$DistributionRoot, [switch]$Offline, [string]$DistributionArchive, [object[]]$CoreFiles)
    Assert-IG5PluginSource $SourceRoot -CoreOnly
    $expectedCore = if ($PSBoundParameters.ContainsKey('CoreFiles')) { @($CoreFiles) } else { @(Get-IG5CoreInventory $SourceRoot) }
    Assert-IG5FileInventory $SourceRoot $expectedCore 'source-core-before-preparation' -IgnoredPrefixes @('runtimes/','third_party/sources/')
    $d = Get-IG5DistributionDescriptor $SourceRoot $PluginVersion
    $releaseUrl = Get-IG5DistributionUrl $d
    if ($DistributionRoot -and $DistributionArchive) { throw 'Choose either DistributionRoot or DistributionArchive, not both' }
    $sourceBoundary = (Get-IG5FullPath $SourceRoot) + '\'
    if ($DistributionArchive -and (Get-IG5FullPath $DistributionArchive).StartsWith($sourceBoundary, [StringComparison]::OrdinalIgnoreCase)) { throw 'Place DistributionArchive outside the plugin source directory; the ZIP must not become plugin code' }
    if ($DistributionRoot) {
        $donorBoundary = (Get-IG5FullPath $DistributionRoot) + '\'
        if ($donorBoundary.StartsWith($sourceBoundary, [StringComparison]::OrdinalIgnoreCase) -or $sourceBoundary.StartsWith($donorBoundary, [StringComparison]::OrdinalIgnoreCase)) { throw 'DistributionRoot and plugin source must be separate non-overlapping directories' }
    }
    if ($Offline -and -not $DistributionRoot -and -not $DistributionArchive) { throw "Source ZIP lacks runtime/upstream assets. Offline: use -DistributionArchive '<pinned-full-release.zip>' -Offline, verified -DistributionRoot '<extracted-full-release-root>' -Offline, or download/extract the full ZIP from $releaseUrl and run plugin\install.ps1." }
    $workspace = Join-Path ([IO.Path]::GetTempPath()) ('ig5-bootstrap-' + [Guid]::NewGuid().ToString('N'))
    try {
        Assert-IG5NoReparsePath $workspace
        [IO.Directory]::CreateDirectory((ConvertTo-IG5IOPath $workspace)) | Out-Null
        if ($DistributionArchive) {
            if (-not $d.assetSha256) { throw 'Offline archive recovery requires a fixed assetSha256 and assetBytes in scripts/distribution.json' }
            $archiveInput = Get-IG5FullPath $DistributionArchive
            Assert-IG5NoReparsePath $archiveInput
            if (-not (Test-IG5Path $archiveInput Leaf)) { throw "DistributionArchive file not found: $archiveInput" }
            if ((New-Object IO.FileInfo (ConvertTo-IG5IOPath $archiveInput)).Length -ne [long]$d.assetBytes) { throw "DistributionArchive size differs from pinned $($d.assetName); expected $($d.assetBytes) bytes" }
            $zipPath = Join-Path $workspace 'full-release.zip'
            Copy-IG5PinnedArchive $archiveInput $zipPath ([long]$d.assetBytes)
            if ((Get-IG5Hash $zipPath) -ne [string]$d.assetSha256) { throw "DistributionArchive SHA-256 differs from the fixed published $($d.assetName); do not change the checksum or manifest" }
            Write-Host '[OK] Local original ZIP matches the fixed published SHA-256. Extracting without changing the original source...'
            $extracted = Join-Path $workspace 'release'
            Expand-IG5VerifiedZip $zipPath $extracted
            $donor = Assert-IG5DistributionAssets $extracted $d $PluginVersion
        } elseif ($DistributionRoot) {
            Write-Host "[SOURCE ZIP] Using local full-release assets: $DistributionRoot"
            $donor = Assert-IG5DistributionAssets $DistributionRoot $d $PluginVersion
        } else {
            Write-Host "[SOURCE ZIP] Runtime/upstream assets absent. Downloading pinned full release: $releaseUrl"
            $release = Get-IG5ReleaseMetadata $d
            $asset = Get-IG5Asset $release $d.assetName $d
            $checksum = Get-IG5Asset $release ($d.assetName + '.sha256') $d
            if ([long]$asset.size -gt 2GB -or [long]$checksum.size -gt 64KB) { throw 'Release asset size exceeds installer budget' }
            if ($d.assetSha256 -and [long]$asset.size -ne [long]$d.assetBytes) { throw 'Published ZIP size differs from the fixed distribution pin' }
            Write-Host ("[SOURCE ZIP] {0}; {1:N1} MiB. Local plugin source is preserved." -f $d.assetName, ([long]$asset.size / 1MB))
            $checksumText = Invoke-IG5DistributionDownload $checksum.browser_download_url '' 64KB ([long]$checksum.size)
            $match = [regex]::Match($checksumText.Trim(), '^([a-fA-F0-9]{64})[ \t]+\*?([^\r\n]+)$')
            if (-not $match.Success -or $match.Groups[2].Value.Trim() -cne $d.assetName) { throw 'Release .sha256 file must identify the pinned ZIP exactly' }
            $expectedHash = $match.Groups[1].Value.ToLowerInvariant()
            if ($d.assetSha256 -and $expectedHash -cne [string]$d.assetSha256) { throw 'Published ZIP checksum differs from the fixed distribution pin' }
            if ($asset.digest -and ([string]$asset.digest -notmatch '^sha256:[a-fA-F0-9]{64}$' -or ([string]$asset.digest).Substring(7).ToLowerInvariant() -ne $expectedHash)) { throw 'GitHub asset digest differs from release .sha256' }
            $zipPath = Join-Path $workspace 'full-release.zip'
            Invoke-IG5DistributionDownload $asset.browser_download_url $zipPath 2GB ([long]$asset.size) -Progress
            if ((Get-IG5Hash $zipPath) -ne $expectedHash) { throw 'Downloaded release ZIP SHA-256 mismatch' }
            Write-Host '[OK] ZIP checksum verified. Extracting and checking complete file inventories...'
            $extracted = Join-Path $workspace 'release'
            Expand-IG5VerifiedZip $zipPath $extracted
            $donor = Assert-IG5DistributionAssets $extracted $d $PluginVersion
        }
        $prepared = Join-Path $workspace 'prepared-plugin'
        Copy-IG5Pack $SourceRoot $prepared @('runtimes','third_party/sources')
        Copy-IG5Pack (Join-Path $donor 'runtimes') (Join-Path $prepared 'runtimes')
        Copy-IG5Pack (Join-Path $donor 'third_party\sources') (Join-Path $prepared 'third_party\sources')
        Assert-IG5PluginSource $prepared -CoreOnly
        Assert-IG5FileInventory $prepared $expectedCore 'prepared-core' -IgnoredPrefixes @('runtimes/','third_party/sources/')
        # A verified donor may change during copying. Re-bind the copied assets
        # to the fixed pins, then check their actual inventories exactly once.
        $null = Assert-IG5PinnedAssets $prepared $d $PluginVersion
        Write-Host '[OK] Pinned assets prepared; source code retained. Starting validated installation.'
        return [pscustomobject]@{Root=$prepared;Workspace=$workspace}
    } catch {
        Remove-IG5BootstrapWorkspace $workspace
        throw "Source ZIP preparation failed: $($_.Exception.Message)`nUse the full ZIP at $releaseUrl; extract it completely and run plugin\install.ps1, or provide -DistributionRoot '<extracted-full-release-root>' -Offline. No DSH profile was changed."
    }
}
