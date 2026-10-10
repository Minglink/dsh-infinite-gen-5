# Shared, read-only runtime validation for installation and portable packaging.
$script:IG5RuntimeCaches = @('downloads', 'sessions', 'projects', 'native-build', 'toolchain', 'clientdeps', '.cache', '__pycache__')

function Get-IG5FullPath {
    param([Parameter(Mandatory)][string]$Path)
    if ($env:OS -ne 'Windows_NT') { return [IO.Path]::GetFullPath($Path).TrimEnd('/') }
    $value = $Path.Replace('/', '\')
    if ($value.StartsWith('\\?\UNC\')) { $value = '\\' + $value.Substring(8) }
    elseif ($value.StartsWith('\\?\')) { $value = $value.Substring(4) }
    if ($value -notmatch '^(?:[A-Za-z]:\\|\\\\[^\\]+\\[^\\]+(?:\\|$))') { $value = (Get-Location).ProviderPath.TrimEnd('\') + '\' + $value }
    $rootMatch = [regex]::Match($value, '^(?:[A-Za-z]:\\|\\\\[^\\]+\\[^\\]+(?:\\|$))')
    if (-not $rootMatch.Success) { throw "无效绝对路径: $Path" }
    $rootPart = $rootMatch.Value.TrimEnd('\') + '\'
    $parts = New-Object 'System.Collections.Generic.List[string]'
    foreach ($part in $value.Substring($rootMatch.Length).Split('\')) {
        if (-not $part -or $part -eq '.') { continue }
        if ($part -eq '..') { if ($parts.Count) { $parts.RemoveAt($parts.Count - 1) }; continue }
        $parts.Add($part)
    }
    if (-not $parts.Count) { return $rootPart }
    return $rootPart + ($parts -join '\')
}

function ConvertTo-IG5IOPath {
    param([string]$Path)
    $full = Get-IG5FullPath $Path
    if ($env:OS -ne 'Windows_NT') { return $full }
    if ($full.StartsWith('\\')) { return '\\?\UNC\' + $full.Substring(2) }
    return '\\?\' + $full
}
function Test-IG5Path {
    param([string]$Path, [ValidateSet('Any','Leaf','Container')][string]$PathType='Any')
    $io = ConvertTo-IG5IOPath $Path
    if ($PathType -eq 'Leaf') { return [IO.File]::Exists($io) }
    if ($PathType -eq 'Container') { return [IO.Directory]::Exists($io) }
    return [IO.File]::Exists($io) -or [IO.Directory]::Exists($io)
}
function Get-IG5Hash {
    param([string]$Path)
    $stream = [IO.File]::OpenRead((ConvertTo-IG5IOPath $Path))
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return [BitConverter]::ToString($sha.ComputeHash($stream)).Replace('-', '').ToLowerInvariant() }
    finally { $sha.Dispose(); $stream.Dispose() }
}
function Read-IG5Text { param([string]$Path) return [IO.File]::ReadAllText((ConvertTo-IG5IOPath $Path), [Text.Encoding]::UTF8) }

function Assert-IG5NoReparsePath {
    param([string]$Path)
    $candidate = Get-IG5FullPath $Path
    while ($candidate) {
        if ((Test-IG5Path $candidate) -and ([IO.File]::GetAttributes((ConvertTo-IG5IOPath $candidate)) -band [IO.FileAttributes]::ReparsePoint)) { throw "Path ancestor cannot be a link: $candidate" }
        $parent = Split-Path $candidate -Parent
        if (-not $parent -or $parent -eq $candidate) { break }
        $candidate = $parent
    }
}

function Remove-IG5Tree {
    param([Parameter(Mandatory)][string]$Path)
    $io = ConvertTo-IG5IOPath $Path
    if (-not (Test-IG5Path $Path)) { return }
    $attributes = [IO.File]::GetAttributes($io)
    if ($attributes -band [IO.FileAttributes]::Directory) {
        if (-not ($attributes -band [IO.FileAttributes]::ReparsePoint)) {
            foreach ($child in (New-Object IO.DirectoryInfo $io).GetFileSystemInfos()) { Remove-IG5Tree $child.FullName }
        }
        [IO.Directory]::Delete($io, $false)
    } else {
        if ($attributes -band [IO.FileAttributes]::ReadOnly) { [IO.File]::SetAttributes($io, ($attributes -band (-bnot [IO.FileAttributes]::ReadOnly))) }
        [IO.File]::Delete($io)
    }
}

function Resolve-IG5PackPath {
    param([Parameter(Mandatory)][string]$Root, [Parameter(Mandatory)][string]$Relative)
    if ([IO.Path]::IsPathRooted($Relative) -or $Relative -match '(^|[\\/])\.\.([\\/]|$)' -or $Relative.Contains(':')) {
        throw "运行包路径必须为包内相对路径: $Relative"
    }
    $base = Get-IG5FullPath $Root
    $full = Get-IG5FullPath ($base + [IO.Path]::DirectorySeparatorChar + $Relative)
    if (-not $full.StartsWith($base + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
        throw "运行包路径超出根目录: $Relative"
    }
    return $full
}

function Test-IG5ExcludedPath {
    param([string]$Relative, [switch]$RuntimeRoot)
    $parts = $Relative.Replace('\', '/').Split('/')
    if ($parts -contains '.git') { return $true }
    if ($parts[0] -eq 'plugin') { $parts = @($parts | Select-Object -Skip 1) }
    if ($parts[0] -eq '.downloads') { return $true }
    # Vendored upstream source trees retain every source path except their Git metadata.
    if ($parts.Count -ge 2 -and $parts[0] -eq 'third_party' -and $parts[1] -eq 'sources') { return $false }
    if ($parts -contains '__pycache__' -or $parts -contains '.pytest_cache' -or $parts -contains 'node_modules') { return $true }
    if ($parts[0] -eq 'runtimes') { $parts = @($parts | Select-Object -Skip 1); $RuntimeRoot = $true }
    if ($RuntimeRoot -and $parts.Count -ge 2 -and $parts[0] -in @('ghidra','x64dbg') -and $parts[1] -in $script:IG5RuntimeCaches) { return $true }
    return $false
}

function Get-IG5PackFiles {
    param([Parameter(Mandatory)][string]$Root, [switch]$IncludeExcluded)
    $base = Get-IG5FullPath $Root
    $isRuntime = (Test-IG5Path (Join-Path $base 'ghidra\runtime.json')) -or (Test-IG5Path (Join-Path $base 'x64dbg\runtime.json'))
    $isSourceTree = $base -match '(^|[\\/])third_party[\\/]sources(?:[\\/]|$)'
    $pending = New-Object 'System.Collections.Generic.Stack[string]'
    $pending.Push($base)
    while ($pending.Count) {
        $dir = $pending.Pop()
        $directoryInfo = New-Object IO.DirectoryInfo (ConvertTo-IG5IOPath $dir)
        foreach ($entry in $directoryInfo.GetFileSystemInfos()) {
            $relative = Get-IG5RelativePath $base $entry.FullName
            $filterPath = if ($isSourceTree) { 'third_party/sources/' + $relative } else { $relative }
            if (-not $IncludeExcluded -and (Test-IG5ExcludedPath $filterPath -RuntimeRoot:$isRuntime)) { continue }
            if ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "发行目录不能含链接: $($entry.FullName)" }
            if ($entry -is [IO.DirectoryInfo]) { $pending.Push((Get-IG5FullPath $entry.FullName)) }
            else { [pscustomobject]@{Name=$entry.Name;FullName=(Get-IG5FullPath $entry.FullName);Length=$entry.Length;Attributes=$entry.Attributes} }
        }
    }
}

function Get-IG5RelativePath {
    param([string]$Root, [string]$Path)
    $base = (Get-IG5FullPath $Root) + [IO.Path]::DirectorySeparatorChar
    $full = Get-IG5FullPath $Path
    if (-not $full.StartsWith($base, [StringComparison]::OrdinalIgnoreCase)) { throw "文件超出根目录: $full" }
    return $full.Substring($base.Length).Replace('\', '/')
}

function Assert-IG5RuntimePack {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Root)
    $base = Get-IG5FullPath $Root
    if (-not (Test-IG5Path $base Container)) { throw "缺少自包含运行目录: $base" }
    if ([IO.File]::GetAttributes((ConvertTo-IG5IOPath $base)) -band [IO.FileAttributes]::ReparsePoint) { throw "运行目录不能为链接: $base" }
    $manifestPath = Join-Path $base 'manifest.json'
    $prefix = ''
    if (-not (Test-IG5Path $manifestPath Leaf)) {
        # v0.x portable packs kept runtimes beside plugin and listed them in the parent manifest.
        $legacy = Join-Path (Split-Path $base -Parent) 'manifest.json'
        if (-not (Test-IG5Path $legacy Leaf)) { throw "缺少完整 SHA-256 清单: $manifestPath" }
        $manifestPath = $legacy
        $prefix = (Split-Path $base -Leaf) + '/'
    }
    try { $manifest = Read-IG5Text $manifestPath | ConvertFrom-Json }
    catch { throw "运行包清单 JSON 无效: $manifestPath ($($_.Exception.Message))" }
    if ($manifest.schemaVersion -ne 1 -or $manifest.platform -ne 'win32-x64' -or -not $manifest.files) { throw "运行包清单 schema/platform/files 无效: $manifestPath" }
    $runtimeTotal = @($manifest.files).Count
    $runtimeProgress = $runtimeTotal -ge 4096
    if ($runtimeProgress) { Write-Host "[VERIFY] runtime: $runtimeTotal inventory entries; checking required components and hashes..." }
    foreach ($engine in @('ghidra', 'x64dbg')) { if (@($manifest.engines) -notcontains $engine) { throw "清单缺少引擎: $engine" } }
    $records = @{}
    foreach ($record in $manifest.files) {
        $relative = [string]$record.path
        if ($prefix) {
            if (-not $relative.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) { continue }
            $relative = $relative.Substring($prefix.Length)
        }
        $relative = $relative.Replace('\', '/')
        $full = Resolve-IG5PackPath $base $relative
        if ($relative -eq 'manifest.json' -or (Test-IG5ExcludedPath $relative -RuntimeRoot)) { throw "清单不能包含自身或运行缓存: $relative" }
        if ($records.ContainsKey($relative)) { throw "清单重复路径: $relative" }
        if ([string]$record.sha256 -notmatch '^[a-fA-F0-9]{64}$' -or [long]$record.bytes -lt 0) { throw "清单 SHA-256/bytes 无效: $relative" }
        if (-not (Test-IG5Path $full Leaf)) { throw "运行包缺少文件: $relative" }
        if ((New-Object IO.FileInfo (ConvertTo-IG5IOPath $full)).Length -ne [long]$record.bytes) { throw "运行包文件长度不符: $relative" }
        $records[$relative] = $record
    }
    foreach ($engine in @('ghidra', 'x64dbg')) {
        $configPath = Join-Path $base "$engine\runtime.json"
        if (-not (Test-IG5Path $configPath Leaf)) { throw "缺少引擎清单: $engine/runtime.json" }
        try { $cfg = Read-IG5Text $configPath | ConvertFrom-Json }
        catch { throw "引擎清单 JSON 无效: $engine/runtime.json" }
        $engineRoot = Join-Path $base $engine
        $requiredFields = if ($engine -eq 'ghidra') { @('pythonExe', 'ghidraHome', 'javaHome') } else { @('pythonExe', 'headlessExe', 'headless32Exe', 'x64dbgExe', 'x32dbgExe') }
        foreach ($key in $requiredFields) {
            if (-not $cfg.$key) { throw "引擎清单缺少字段: $engine/$key" }
            $component = Resolve-IG5PackPath $engineRoot ([string]$cfg.$key)
            if (-not (Test-IG5Path $component)) { throw "缺少运行组件: $engine/$($cfg.$key)" }
        }
        $python = Split-Path (Resolve-IG5PackPath $engineRoot ([string]$cfg.pythonExe)) -Parent
        $required = @((Join-Path $python 'python312.zip'), (Join-Path $python 'python312.dll'), (Join-Path $python 'python312._pth'), (Join-Path $python 'LICENSE.txt'))
        if ($engine -eq 'ghidra') {
            $ghidra = Resolve-IG5PackPath $engineRoot ([string]$cfg.ghidraHome)
            $java = Resolve-IG5PackPath $engineRoot ([string]$cfg.javaHome)
            $required += @((Join-Path $ghidra 'Ghidra\Framework\Utility\lib\Utility.jar'), (Join-Path $ghidra 'LICENSE'), (Join-Path $ghidra 'bom.json'),
                (Join-Path $ghidra 'licenses'), (Join-Path $java 'bin\java.exe'), (Join-Path $java 'bin\server\jvm.dll'), (Join-Path $java 'legal'),
                (Join-Path $python 'pylib\pyghidra\__init__.py'), (Join-Path $python 'pylib\jpype\__init__.py'), (Join-Path $python 'pylib\packaging\__init__.py'),
                (Join-Path $python 'pylib\_jpype.cp312-win_amd64.pyd'), (Join-Path $python 'pylib\org.jpype.jar'))
            foreach ($pattern in @('pyghidra-*.dist-info', 'jpype1-*.dist-info', 'packaging-*.dist-info')) {
                $pylibPath = Join-Path $python 'pylib'
                $matches = if (Test-IG5Path $pylibPath Container) { @((New-Object IO.DirectoryInfo (ConvertTo-IG5IOPath $pylibPath)).GetDirectories($pattern)) } else { @() }
                if (@($matches).Count -ne 1 -or -not (Test-IG5Path ((Get-IG5FullPath $matches[0].FullName) + '\METADATA') Leaf)) { throw "缺少或重复 Python 依赖许可证元数据: ghidra/python/pylib/$pattern" }
            }
        } else {
            if ($cfg.bridge -ne 'ig5-native' -or $cfg.mode -ne 'headless') { throw '默认 x64dbg 发行包必须为 ig5-native/headless' }
            foreach ($bits in @('32', '64')) {
                $exe = if ($bits -eq '64') { $cfg.headlessExe } else { $cfg.headless32Exe }
                $debug = Split-Path (Resolve-IG5PackPath $engineRoot ([string]$exe)) -Parent
                foreach ($name in @("plugins\ig5-bridge.dp$bits", "x${bits}_bridge.dll", "x${bits}_dbg.dll", 'TitanEngine.dll', 'jansson.dll', 'msvcp140.dll', 'vcruntime140.dll')) { $required += Join-Path $debug $name }
                if (Test-IG5Path (Join-Path $debug "plugins\x64dbg-automate.dp$bits")) { throw "存在不兼容调试插件: x64dbg-automate.dp$bits" }
            }
            foreach ($name in @('NOTICE.txt', 'x64dbg-LICENSE.txt', 'Python-LICENSE.txt', 'Jansson-LICENSE.txt', 'TitanEngine-LICENSE.txt', 'license-sources.json', 'Qt-GPL-3.0.txt', 'Qt-LGPL-3.0.txt')) { $required += Join-Path $engineRoot "licenses\$name" }
        }
        foreach ($component in $required) {
            if (-not (Test-IG5Path $component)) { throw "缺少运行组件或许可证: $(Get-IG5RelativePath $base $component)" }
            if (Test-IG5Path $component Container) {
                if (-not @(Get-IG5PackFiles $component).Count) { throw "运行组件/许可证目录为空: $(Get-IG5RelativePath $base $component)" }
            }
        }
    }
    $actual = @(Get-IG5PackFiles $base)
    $runtimeChecked = 0
    foreach ($file in $actual) {
        $relative = Get-IG5RelativePath $base $file.FullName
        if ($relative -eq 'manifest.json') { continue }
        if (-not $records.ContainsKey($relative)) { throw "运行包含未登记文件: $relative" }
        $hash = Get-IG5Hash $file.FullName
        if (-not $hash.Equals([string]$records[$relative].sha256, [StringComparison]::OrdinalIgnoreCase)) { throw "运行包 SHA-256 不符: $relative" }
        $runtimeChecked++
        if ($runtimeProgress -and $runtimeChecked % 4096 -eq 0) { Write-Host "[VERIFY] runtime SHA-256: $runtimeChecked / $($records.Count)" }
    }
    if (($actual.Count - $(if (Test-IG5Path (Join-Path $base 'manifest.json')) { 1 } else { 0 })) -ne $records.Count) { throw '运行包清单与实际文件数量不符' }
    if ($runtimeProgress) { Write-Host "[OK] runtime SHA-256: $runtimeChecked files verified" }
    return [pscustomobject]@{ Root = $base; Manifest = $manifest; ManifestPath = $manifestPath; Records = $records; Legacy = [bool]$prefix; Files = $records.Count }
}

function Copy-IG5Pack {
    param([Parameter(Mandatory)][string]$From, [Parameter(Mandatory)][string]$To, [string[]]$ExtraExclude = @())
    [IO.Directory]::CreateDirectory((ConvertTo-IG5IOPath $To)) | Out-Null
    foreach ($file in Get-IG5PackFiles $From) {
        $relative = Get-IG5RelativePath $From $file.FullName
        $skip = $false
        foreach ($excluded in $ExtraExclude) {
            if ($relative -eq $excluded -or $relative.StartsWith($excluded.TrimEnd('/') + '/', [StringComparison]::OrdinalIgnoreCase)) { $skip = $true; break }
        }
        if ($skip) { continue }
        $destination = Resolve-IG5PackPath $To $relative
        [IO.Directory]::CreateDirectory((ConvertTo-IG5IOPath (Split-Path $destination -Parent))) | Out-Null
        [IO.File]::Copy((ConvertTo-IG5IOPath $file.FullName), (ConvertTo-IG5IOPath $destination), $true)
    }
}

function Write-IG5RuntimeManifest {
    param([Parameter(Mandatory)]$Validated, [Parameter(Mandatory)][string]$Destination, [string]$PluginVersion)
    if (-not $Validated.Legacy) { [IO.File]::Copy((ConvertTo-IG5IOPath $Validated.ManifestPath), (ConvertTo-IG5IOPath (Join-Path $Destination 'manifest.json')), $true); return }
    $files = @($Validated.Records.Keys | Sort-Object | ForEach-Object { $r = $Validated.Records[$_]; @{path=$_;bytes=[long]$r.bytes;sha256=[string]$r.sha256} })
    $manifest = @{schemaVersion=1;pluginVersion=$PluginVersion;platform='win32-x64';engines=@('ghidra','x64dbg');files=$files}
    [IO.File]::WriteAllText((ConvertTo-IG5IOPath (Join-Path $Destination 'manifest.json')), ($manifest | ConvertTo-Json -Depth 8), [Text.UTF8Encoding]::new($false))
}

function Assert-IG5FileInventory {
    param([string]$Root, [object[]]$Files, [string]$Label, [switch]$IncludeExcluded, [string[]]$IgnoredPrefixes = @())
    if (-not $Files.Count) { throw "文件清单为空: $Label" }
    $progress = $Files.Count -ge 4096
    $progressLabel = [regex]::Replace([string]$Label, '[^A-Za-z0-9._/-]', '_')
    if ($progressLabel.Length -gt 80) { $progressLabel = $progressLabel.Substring(0,80) }
    if ($progress) { Write-Host "[VERIFY] ${progressLabel}: $($Files.Count) inventory entries; checking sizes/paths..." }
    $registered = 0
    $records = @{}
    foreach ($record in $Files) {
        $relative = ([string]$record.path).Replace('\', '/')
        $full = Resolve-IG5PackPath $Root $relative
        if ($records.ContainsKey($relative) -or [string]$record.sha256 -notmatch '^[a-fA-F0-9]{64}$' -or [long]$record.bytes -lt 0) { throw "无效文件清单: $Label/$relative" }
        if (-not (Test-IG5Path $full Leaf)) { throw "安装源缺少文件: $Label/$relative" }
        $actualBytes = (New-Object IO.FileInfo (ConvertTo-IG5IOPath $full)).Length
        if ($actualBytes -ne [long]$record.bytes) { throw "安装源文件长度不符: $Label/$relative`nExpected bytes: $($record.bytes); actual bytes: $actualBytes. Source files were not changed." }
        $records[$relative] = $record
        $registered++
        if ($progress -and $registered % 4096 -eq 0) { Write-Host "[VERIFY] $progressLabel sizes/paths: $registered / $($Files.Count)" }
    }
    $actual = @(Get-IG5PackFiles $Root -IncludeExcluded:$IncludeExcluded | Where-Object {
        $candidate = Get-IG5RelativePath $Root $_.FullName
        $ignored = $false
        foreach ($prefix in $IgnoredPrefixes) { if ($candidate.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) { $ignored = $true; break } }
        -not $ignored
    })
    $checked = 0
    foreach ($file in $actual) {
        $relative = Get-IG5RelativePath $Root $file.FullName
        if (-not $records.ContainsKey($relative)) { throw "安装源含未登记文件: $Label/$relative" }
        $actualHash = Get-IG5Hash $file.FullName
        if ($actualHash -ne [string]$records[$relative].sha256) {
            throw "安装源 SHA-256 不符: $Label/$relative`nExpected SHA-256: $($records[$relative].sha256)`nActual SHA-256: $actualHash`nBytes: $($file.Length). Do not edit the manifest or skip validation. For immutable asset repair use install.ps1 -RepairAssets with the pinned original ZIP via -DistributionArchive, or verified -DistributionRoot. Existing DSH installation is unchanged."
        }
        $checked++
        if ($progress -and $checked % 4096 -eq 0) { Write-Host "[VERIFY] $progressLabel SHA-256: $checked / $($Files.Count)" }
    }
    if ($actual.Count -ne $records.Count) { throw "安装源清单数量不符: $Label" }
    if ($progress) { Write-Host "[OK] $progressLabel SHA-256: $checked files verified" }
}

function Get-IG5CoreInventory {
    param([string]$Root)
    # Freeze plugin code before any potentially long asset preparation. Assets
    # are validated independently against their immutable distribution pins.
    foreach ($file in Get-IG5PackFiles $Root) {
        $relative = Get-IG5RelativePath $Root $file.FullName
        if ($relative.StartsWith('runtimes/', [StringComparison]::OrdinalIgnoreCase) -or $relative.StartsWith('third_party/sources/', [StringComparison]::OrdinalIgnoreCase)) { continue }
        @{path=$relative;bytes=$file.Length;sha256=(Get-IG5Hash $file.FullName)}
    }
}

function Assert-IG5ReleaseCore {
    param([string]$Root, [string]$PluginVersion)
    $parentManifest = Join-Path (Split-Path $Root -Parent) 'manifest.json'
    if (-not (Test-IG5Path $parentManifest Leaf)) { throw 'Asset repair of a full/partial package requires its complete outer manifest.json; use a fresh Source ZIP instead.' }
    $release = Read-IG5Text $parentManifest | ConvertFrom-Json
    if ($release.schemaVersion -ne 1 -or $release.platform -ne 'win32-x64' -or -not $release.files -or [string]$release.pluginVersion -cne $PluginVersion) { throw 'Asset repair release inventory identity/version is invalid' }
    $prefix = (Split-Path $Root -Leaf) + '/'
    $ignored = @('runtimes/', 'third_party/sources/')
    $files = @($release.files | Where-Object { ([string]$_.path).StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase) } | ForEach-Object {
        $relative = ([string]$_.path).Substring($prefix.Length).Replace('\','/')
        $null = Resolve-IG5PackPath $Root $relative
        if (-not $relative.StartsWith('runtimes/', [StringComparison]::OrdinalIgnoreCase) -and -not $relative.StartsWith('third_party/sources/', [StringComparison]::OrdinalIgnoreCase)) {
            @{path=$relative;bytes=$_.bytes;sha256=$_.sha256}
        }
    })
    Assert-IG5FileInventory $Root $files 'plugin-core' -IgnoredPrefixes $ignored
    # Keep the authenticated outer-manifest records, rather than re-snapshotting
    # possibly changed code after a download or donor copy.
    return $files
}

function Assert-IG5PluginSource {
    param([string]$Root, [switch]$CoreOnly)
    Assert-IG5NoReparsePath $Root
    if (-not (Test-IG5Path $Root Container) -or ([IO.File]::GetAttributes((ConvertTo-IG5IOPath $Root)) -band [IO.FileAttributes]::ReparsePoint)) { throw 'Plugin source must be a real directory' }
    # Keep this list aligned with the modules loaded by index.js, workers and the profile entry points.
    $required = @('package.json','index.js','client.js','engine_runtime.js','advanced_tools.js','integration_tools.js','analysis_tools.js','workflow.js',
        'semantic_diff.js','semantic_diff_async.js','semantic_diff_worker.js','source/project_store.js','source/attachment_lease.js','source/address_ref.js','source/host_platform.js','source/worker_transport.js',
        'source/audit_history.js','source/patch_export.js','source/history_index.js','source/json_output.js','source/reverse_runtime.js','source/kernel_jobs.js',
        'source/function_dossier.js','source/investigation_store.js','source/investigation_workflow.js',
        'source/analysis_artifacts.js','source/analysis_jobs.js','source/analysis_worker.js','source/crypto_analysis.js','source/crypto_recovery.js','source/protocol_analysis.js','source/protocol_inference.js',
        'worker/ig5_worker.py','worker/scan_analysis.py','worker/advanced_analysis.py','worker/execution_analysis.py','worker/memory_image.py','worker/cpu_emulator.py','worker/vendor/NOTICE.txt',
        'worker/ig5_kernel.py','worker/kernel_image.py','worker/kernel_analysis.py','worker/kernel_rtti.py','worker/kernel_decompile.py',
        'worker/vendor/unicorn/__init__.py','worker/vendor/unicorn/lib/unicorn.dll',
        'adapters/ghidra/worker.py','adapters/ghidra/pcode_view.py','adapters/ghidra/switch_analysis.py','adapters/ghidra/microcode_analysis.py','adapters/ghidra/script_api.py','adapters/ghidra/jpype-patch/JPypeContext.java','adapters/ghidra/jpype-patch/upstream/org.jpype.jar',
        'adapters/kernel/native/ig5_decompiler.dll','adapters/kernel/native/build-proof.json','adapters/kernel/native/Ghidra-LICENSE.txt','adapters/kernel/native/NOTICE','adapters/kernel/native/zlib-README.txt',
        'adapters/ghidra/jpype-patch/LICENSE','adapters/ghidra/jpype-patch/UPSTREAM-NOTICE','adapters/ghidra/jpype-patch/NOTICE.txt','adapters/ghidra/jpype-patch/unicode-bootstrap.patch',
        'scripts/patch_ghidra_jpype.ps1','scripts/patch_ghidra_project_paths.ps1','adapters/ghidra/local-project-path/build_patch.py',
        'adapters/ghidra/local-project-path/local-project-path.patch','adapters/ghidra/local-project-path/NOTICE.txt','adapters/ghidra/local-project-path/README.md',
        'adapters/x64dbg/adapter.py','adapters/x64dbg/native/ig5-bridge.dp32','adapters/x64dbg/native/ig5-bridge.dp64','adapters/x64dbg/native/sha256.json',
        'scripts/runtime_pack.ps1','scripts/bootstrap_distribution.ps1','scripts/distribution.json','install.ps1','uninstall.ps1','cordis.patch.yml','README.md','HARNESS_PLUGIN.md','LICENSE','THIRD_PARTY_NOTICES.txt')
    if (-not $CoreOnly) { $required += 'third_party/sources/manifest.json' }
    foreach ($skill in @('ig5-triage','ig5-deep-dive','ig5-patch-and-sign','ig5-diff','ig5-debug-live','ig5-crypto','ig5-protocol')) { $required += "skills/$skill/SKILL.md" }
    foreach ($relative in $required) { if (-not (Test-IG5Path (Resolve-IG5PackPath $Root $relative) Leaf)) { throw "安装源缺少插件文件: $relative" } }
    # Enumerate before network or profile writes; reject links in the source code.
    foreach ($unused in Get-IG5PackFiles $Root) { }
    if ($CoreOnly) { return }
    $parentManifest = Join-Path (Split-Path $Root -Parent) 'manifest.json'
    if (Test-IG5Path $parentManifest Leaf) {
        try { $release = Read-IG5Text $parentManifest | ConvertFrom-Json }
        catch { throw "完整发行包清单 JSON 无效: $parentManifest" }
        if ($release.schemaVersion -ne 1 -or $release.platform -ne 'win32-x64' -or -not $release.files) { throw "完整发行包清单无效: $parentManifest" }
        $prefix = (Split-Path $Root -Leaf) + '/'
        $files = @($release.files | Where-Object { ([string]$_.path).StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase) } | ForEach-Object {
            @{path=([string]$_.path).Substring($prefix.Length);bytes=$_.bytes;sha256=$_.sha256}
        })
        Assert-IG5FileInventory $Root $files 'plugin'
    }
    Assert-IG5SourceAssets $Root
}

function Assert-IG5SourceAssets {
    param([string]$Root)
    $sourcesRoot = Join-Path $Root 'third_party\sources'
    try { $sources = Read-IG5Text (Join-Path $sourcesRoot 'manifest.json') | ConvertFrom-Json }
    catch { throw '第三方源码清单 JSON 无效' }
    if ($sources.schemaVersion -ne 1 -or -not $sources.sources) { throw '第三方源码清单无效或为空' }
    $seen = @{}
    foreach ($source in $sources.sources) {
        $directory = Resolve-IG5PackPath $sourcesRoot ([string]$source.directory)
        $inventoryPath = Resolve-IG5PackPath $sourcesRoot ([string]$source.fileInventory)
        if ($seen.ContainsKey($directory)) { throw "第三方源码目录重复: $($source.directory)" }
        $seen[$directory] = $true
        if (-not (Test-IG5Path $inventoryPath Leaf)) { throw "缺少第三方源码逐文件清单: $($source.fileInventory)" }
        $inventoryText = Read-IG5Text $inventoryPath
        $inventory = $inventoryText | ConvertFrom-Json
        # Fixed source acquisition emits raw row arrays; older archives use a
        # { fileCount, files } envelope. Preserve both without member-enumerating
        # an array's missing fileCount into thousands of null values.
        $rawRows = $inventoryText.TrimStart().StartsWith('[')
        $inventoryRows = if ($rawRows) { @($inventory) } else { @($inventory.files) }
        if (@($inventoryRows).Count -ne [long]$source.fileCount -or (-not $rawRows -and [long]$inventory.fileCount -ne [long]$source.fileCount)) { throw "第三方源码数量不符: $($source.directory)" }
        Assert-IG5FileInventory $directory @($inventoryRows) ([string]$source.directory)
    }
}
