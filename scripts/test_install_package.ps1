[CmdletBinding()]
param([switch]$KeepFixture)
$ErrorActionPreference = 'Stop'
$source = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
. (Join-Path $PSScriptRoot 'runtime_pack.ps1')
. (Join-Path $PSScriptRoot 'bootstrap_distribution.ps1')
$testRoot = Join-Path ([IO.Path]::GetTempPath()) ('ig5-install-pack-' + [Guid]::NewGuid().ToString('N'))
$shellPath = (Get-Process -Id $PID).Path
$utf8 = [Text.UTF8Encoding]::new($false)
$passed = 0

function Check { param([bool]$Condition, [string]$Message) if (-not $Condition) { throw "ASSERT: $Message" } }
function Put { param([string]$Path, [string]$Text = 'fixture')
    [IO.Directory]::CreateDirectory((ConvertTo-IG5IOPath (Split-Path $Path -Parent))) | Out-Null
    [IO.File]::WriteAllText((ConvertTo-IG5IOPath $Path), $Text, $utf8)
}
function Put-Json { param([string]$Path, $Value) Put $Path ($Value | ConvertTo-Json -Depth 12) }
function Pass { param([string]$Message) $script:passed++; Write-Output "PASS $Message" }
function Expect-Failure { param([scriptblock]$Action, [string]$Expected)
    $failed = $false
    try { & $Action | Out-Null } catch { $failed = $true; Check ($_.Exception.Message.Contains($Expected)) "Expected '$Expected': $($_.Exception.Message)" }
    Check $failed "Expected failure: $Expected"
}
function New-Zip { param([string]$Path, [object[]]$Rows)
    Add-Type -AssemblyName System.IO.Compression
    $stream = [IO.File]::Create((ConvertTo-IG5IOPath $Path))
    $zip = [IO.Compression.ZipArchive]::new($stream, [IO.Compression.ZipArchiveMode]::Create)
    try {
        foreach ($row in $Rows) {
            $entry = $zip.CreateEntry([string]$row.path)
            if ($null -ne $row.attrs) { $entry.ExternalAttributes = [int]$row.attrs }
            $outputStream = $entry.Open()
            try {
                if ($row.file) { $inputStream = [IO.File]::OpenRead((ConvertTo-IG5IOPath $row.file)); try { $inputStream.CopyTo($outputStream) } finally { $inputStream.Dispose() } }
                else { $bytes = [Text.Encoding]::UTF8.GetBytes([string]$row.text); $outputStream.Write($bytes,0,$bytes.Length) }
            } finally { $outputStream.Dispose() }
        }
    } finally { $zip.Dispose(); $stream.Dispose() }
}
function Run-Script { param([string]$Script, [string[]]$Arguments = @(), [bool]$Success = $true, [string]$Expected = '')
    $savedPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue' # Windows PowerShell wraps native stderr in non-terminating errors.
        $result = @(& $shellPath -NoProfile -ExecutionPolicy Bypass -File $Script @Arguments 2>&1)
        $code = $LASTEXITCODE
    } finally { $ErrorActionPreference = $savedPreference }
    $text = ($result | Out-String)
    if ($Success -and $code -ne 0) { throw "Script failed ($code): $Script`n$text" }
    if (-not $Success -and $code -eq 0) { throw "Script unexpectedly succeeded: $Script`n$text" }
    if ($Expected -and $text -notlike "*$Expected*") { throw "Missing expected error '$Expected':`n$text" }
    return $text
}
function Manifest { param([string]$Runtime)
    $files = @(Get-IG5PackFiles $Runtime | Where-Object Name -ne 'manifest.json' | ForEach-Object {
        @{path=(Get-IG5RelativePath $Runtime $_.FullName);bytes=$_.Length;sha256=(Get-IG5Hash $_.FullName)}
    })
    Put-Json (Join-Path $Runtime 'manifest.json') @{schemaVersion=1;pluginVersion='1.0.0';platform='win32-x64';engines=@('ghidra','x64dbg');files=$files}
}
function New-Runtime { param([string]$Runtime)
    Put-Json (Join-Path $Runtime 'ghidra\runtime.json') @{pythonExe='python/python.exe';ghidraHome='ghidra';javaHome='jdk';projectRoot='projects'}
    Put-Json (Join-Path $Runtime 'x64dbg\runtime.json') @{pythonExe='python/python.exe';headlessExe='snapshot/release/x64/headless.exe';headless32Exe='snapshot/release/x32/headless.exe';x64dbgExe='snapshot/release/x64/x64dbg.exe';x32dbgExe='snapshot/release/x32/x32dbg.exe';mode='headless';bridge='ig5-native'}
    foreach ($engine in @('ghidra','x64dbg')) {
        foreach ($name in @('python.exe','python312.zip','python312.dll','python312._pth','LICENSE.txt')) { Put (Join-Path $Runtime "$engine\python\$name") }
    }
    foreach ($name in @('Ghidra\Framework\Utility\lib\Utility.jar','LICENSE','bom.json','licenses\fixture-LICENSE.txt')) { Put (Join-Path $Runtime "ghidra\ghidra\$name") }
    foreach ($name in @('bin\java.exe','bin\server\jvm.dll','legal\fixture\LICENSE')) { Put (Join-Path $Runtime "ghidra\jdk\$name") }
    foreach ($name in @('pyghidra\__init__.py','jpype\__init__.py','packaging\__init__.py','_jpype.cp312-win_amd64.pyd','org.jpype.jar','pyghidra-3.1.0.dist-info\METADATA','jpype1-1.5.2.dist-info\METADATA','packaging-26.3.dist-info\METADATA')) { Put (Join-Path $Runtime "ghidra\python\pylib\$name") }
    foreach ($bits in @('32','64')) {
        foreach ($name in @('headless.exe',"x${bits}dbg.exe", "plugins\ig5-bridge.dp$bits", "x${bits}_bridge.dll", "x${bits}_dbg.dll",'TitanEngine.dll','jansson.dll','msvcp140.dll','vcruntime140.dll')) { Put (Join-Path $Runtime "x64dbg\snapshot\release\x$bits\$name") }
    }
    foreach ($name in @('NOTICE.txt','x64dbg-LICENSE.txt','Python-LICENSE.txt','Jansson-LICENSE.txt','TitanEngine-LICENSE.txt','license-sources.json','Qt-GPL-3.0.txt','Qt-LGPL-3.0.txt')) { Put (Join-Path $Runtime "x64dbg\licenses\$name") }
    foreach ($dir in @('downloads','sessions','projects','native-build','toolchain','clientdeps','__pycache__')) { Put (Join-Path $Runtime "x64dbg\$dir\excluded.txt") }
    Manifest $Runtime
}
function New-Profile { param([string]$Dsh)
    Put-Json (Join-Path $Dsh 'profiles\default\package.json') @{name='test-profile';dependencies=@{'other-plugin'='1.0';'dsh-infinite-gen-1'='old'};dsh=@{profile=@{bundles=@('other-plugin','dsh-infinite-gen-1')}}}
}
function Check-NoMutation { param([string]$Dsh, [string]$Before, [int]$Backups)
    $profile = Join-Path $Dsh 'profiles\default\package.json'
    Check ([IO.File]::ReadAllText($profile) -eq $Before) 'failed preflight changed profile'
    Check ((Get-ChildItem -LiteralPath (Split-Path $profile) -Filter '*.bak-*').Count -eq $Backups) 'failed preflight created profile backups'
    Check (Test-Path -LiteralPath (Join-Path $Dsh 'plugins\dsh-infinite-gen-5\keep.txt')) 'failed preflight changed existing plugin'
    Check (@(Get-ChildItem -LiteralPath (Join-Path $Dsh 'plugins') -Directory -Filter '.ig5-*').Count -eq 0) 'failed preflight created staging directories'
}
try {
    $fixture = Join-Path $testRoot 'source'
    foreach ($file in @('install.ps1','uninstall.ps1','scripts\runtime_pack.ps1','scripts\bootstrap_distribution.ps1','scripts\distribution.json','scripts\package_portable.ps1')) {
        New-Item -ItemType Directory -Path (Split-Path (Join-Path $fixture $file)) -Force | Out-Null
        Copy-Item -LiteralPath (Join-Path $source $file) -Destination (Join-Path $fixture $file)
    }
    Put-Json (Join-Path $fixture 'package.json') @{name='dsh-infinite-gen-5';version='1.0.0'}
    Put (Join-Path $fixture 'index.js') 'export default {};'
    Put (Join-Path $fixture 'client.js') 'export default {};'
    foreach ($file in @('engine_runtime.js','advanced_tools.js','analysis_tools.js','integration_tools.js','workflow.js','semantic_diff.js','semantic_diff_async.js','semantic_diff_worker.js',
        'source/analysis_artifacts.js','source/analysis_jobs.js','source/analysis_worker.js','source/crypto_analysis.js','source/crypto_recovery.js','source/protocol_analysis.js','source/protocol_inference.js','worker/scan_analysis.py',
        'source/project_store.js','source/attachment_lease.js','source/audit_history.js','source/patch_export.js','source/history_index.js','source/json_output.js','source/reverse_runtime.js','source/address_ref.js','source/host_platform.js','source/worker_transport.js','worker/ig5_worker.py','worker/advanced_analysis.py','worker/execution_analysis.py','worker/memory_image.py','worker/cpu_emulator.py','worker/vendor/NOTICE.txt',
        'adapters/ghidra/worker.py','adapters/ghidra/pcode_view.py','adapters/ghidra/jpype-patch/JPypeContext.java','adapters/ghidra/jpype-patch/upstream/org.jpype.jar',
        'adapters/ghidra/jpype-patch/LICENSE','adapters/ghidra/jpype-patch/UPSTREAM-NOTICE','adapters/ghidra/jpype-patch/NOTICE.txt','adapters/ghidra/jpype-patch/unicode-bootstrap.patch',
        'scripts/patch_ghidra_jpype.ps1','scripts/patch_ghidra_project_paths.ps1','adapters/ghidra/local-project-path/build_patch.py',
        'adapters/ghidra/local-project-path/local-project-path.patch','adapters/ghidra/local-project-path/NOTICE.txt','adapters/ghidra/local-project-path/README.md',
        'adapters/x64dbg/adapter.py','adapters/x64dbg/native/ig5-bridge.dp32','adapters/x64dbg/native/ig5-bridge.dp64','adapters/x64dbg/native/sha256.json',
        'cordis.patch.yml','README.md','HARNESS_PLUGIN.md','LICENSE','THIRD_PARTY_NOTICES.txt')) { Put (Join-Path $fixture $file) }
    foreach ($skill in @('ig5-triage','ig5-deep-dive','ig5-patch-and-sign','ig5-diff','ig5-debug-live','ig5-crypto','ig5-protocol')) { Put (Join-Path $fixture "skills/$skill/SKILL.md") }
    Put (Join-Path $fixture 'third_party\sources\upstream\LICENSE') 'upstream license/source asset'
    Put (Join-Path $fixture 'third_party\sources\upstream\code.cpp') 'source audit asset'
    Put (Join-Path $fixture 'worker\vendor\unicorn\lib\unicorn.dll') 'vendor fixture binary'
    Put (Join-Path $fixture 'worker\vendor\unicorn\__init__.py') 'vendor fixture source'
    Put (Join-Path $fixture '.downloads\archive.zip') 'development download cache'
    foreach ($name in @('projects','sessions','downloads','toolchain','__pycache__','node_modules')) { Put (Join-Path $fixture "third_party\sources\upstream\$name\source.txt") 'source asset, not runtime cache' }
    $deepRelative = 'third_party/sources/upstream/' + (('long_source_segment/' * 15)) + 'hash_preserved.cpp'
    $deepPath = Join-Path $fixture $deepRelative
    Check ($deepPath.Length -gt 300) 'long-path fixture is too short'
    Put $deepPath 'long source file preserved under Windows PowerShell 5.1'
    $upstreamRoot = Join-Path $fixture 'third_party\sources\upstream'
    $sourceFiles = @(Get-IG5PackFiles $upstreamRoot | ForEach-Object { @{path=(Get-IG5RelativePath $upstreamRoot $_.FullName);bytes=$_.Length;sha256=(Get-IG5Hash $_.FullName)} })
    Put-Json (Join-Path $fixture 'third_party\sources\provenance\upstream.files.json') @{fileCount=$sourceFiles.Count;files=$sourceFiles}
    Put-Json (Join-Path $fixture 'third_party\sources\manifest.json') @{schemaVersion=1;sources=@(@{directory='upstream';fileInventory='provenance/upstream.files.json';fileCount=$sourceFiles.Count})}
    Put (Join-Path $fixture '__pycache__\excluded.txt')
    $runtime = Join-Path $fixture 'runtimes'
    New-Runtime $runtime
    $descriptor = Read-IG5Text (Join-Path $fixture 'scripts\distribution.json') | ConvertFrom-Json
    $descriptor.runtimeManifestSha256 = Get-IG5Hash (Join-Path $runtime 'manifest.json')
    $descriptor.sourceManifestSha256 = Get-IG5Hash (Join-Path $fixture 'third_party\sources\manifest.json')
    $descriptor | Add-Member -NotePropertyName sourceInventorySha256 -NotePropertyValue ([pscustomobject]@{'provenance/upstream.files.json'=(Get-IG5Hash (Join-Path $fixture 'third_party\sources\provenance\upstream.files.json'))}) -Force
    foreach ($name in @('ig5-bridge.dp32','ig5-bridge.dp64')) { $descriptor.nativeBridgeSha256.$name = Get-IG5Hash (Join-Path $fixture "adapters\x64dbg\native\$name") }
    Put-Json (Join-Path $fixture 'scripts\distribution.json') $descriptor
    $install = Join-Path $fixture 'install.ps1'
    $packager = Join-Path $fixture 'scripts\package_portable.ps1'
    Assert-IG5PluginSource $fixture
    [IO.File]::WriteAllText((Join-Path $fixture 'third_party\sources\provenance\upstream.files.json'), ($sourceFiles | ConvertTo-Json -Depth 8), [Text.UTF8Encoding]::new($false))
    Assert-IG5PluginSource $fixture
    Pass 'source inventories accept both strict envelope and raw row formats'
    $descriptor.sourceInventorySha256.'provenance/upstream.files.json' = Get-IG5Hash (Join-Path $fixture 'third_party\sources\provenance\upstream.files.json')
    Put-Json (Join-Path $fixture 'scripts\distribution.json') $descriptor
    $dsh = Join-Path $testRoot 'mock-dsh'
    New-Profile $dsh
    $null = Run-Script $install @('-DshRoot',$dsh)
    $installed = Join-Path $dsh 'plugins\dsh-infinite-gen-5'
    $null = Assert-IG5RuntimePack (Join-Path $installed 'runtimes')
    Check (-not (Test-Path -LiteralPath (Join-Path $dsh 'ig5\runtimes'))) 'default installer used external runtime root'
    Check (-not (Test-Path -LiteralPath (Join-Path $installed '__pycache__'))) 'installer leaked source bytecode cache'
    Check (-not (Test-Path -LiteralPath (Join-Path $installed '.downloads'))) 'installer leaked development downloads'
    foreach ($name in @('lib\unicorn.dll','__init__.py')) {
        Check ((Get-FileHash -LiteralPath (Join-Path $fixture "worker\vendor\unicorn\$name")).Hash -eq (Get-FileHash -LiteralPath (Join-Path $installed "worker\vendor\unicorn\$name")).Hash) "installer changed vendor file $name"
    }
    Check (-not (Test-Path -LiteralPath (Join-Path $installed 'runtimes\x64dbg\downloads'))) 'installer leaked runtime download cache'
    $profilePath = Join-Path $dsh 'profiles\default\package.json'
    $profile = Get-Content -LiteralPath $profilePath -Raw | ConvertFrom-Json
    Check ($profile.dependencies.'dsh-infinite-gen-5' -eq 'file:../../plugins/dsh-infinite-gen-5') 'plugin dependency missing'
    Check ($profile.dependencies.'other-plugin' -eq '1.0') 'other dependency changed'
    Check ($profile.dependencies.PSObject.Properties.Name -notcontains 'dsh-infinite-gen-1') 'legacy dependency not removed'
    Check ((Get-Item -LiteralPath (Join-Path $dsh 'profiles\default\node_modules\dsh-infinite-gen-5')).LinkType -eq 'Junction') 'profile junction missing'
    Pass 'default install carries both runtimes and licenses, preserves other dependencies, excludes caches'

    Put (Join-Path $installed 'stale.txt')
    $null = Run-Script $install @('-DshRoot',$dsh)
    Check (-not (Test-Path -LiteralPath (Join-Path $installed 'stale.txt'))) 'repeat install retained stale plugin file'
    Check (@(Get-ChildItem -LiteralPath (Join-Path $dsh 'ig5\artifacts') -Directory -Filter 'install-backup-*').Count -eq 1) 'prior plugin backup missing'
    Pass 'repeat installation replaces obsolete files and retains a recoverable prior plugin'

    Put (Join-Path $installed 'keep.txt')
    $before = [IO.File]::ReadAllText($profilePath)
    $backups = @(Get-ChildItem -LiteralPath (Split-Path $profilePath) -Filter '*.bak-*').Count
    foreach ($critical in @('index.js','adapters/ghidra/worker.py','source/attachment_lease.js','source/audit_history.js','source/patch_export.js','source/history_index.js')) {
        $criticalPath = Join-Path $fixture $critical
        $criticalText = Read-IG5Text $criticalPath
        [IO.File]::Delete((ConvertTo-IG5IOPath $criticalPath))
        $null = Run-Script $install @('-DshRoot',$dsh) $false $critical
        Check-NoMutation $dsh $before $backups
        Put $criticalPath $criticalText
    }
    Pass 'missing host, adapter, lease or history/export modules fail preflight before changing the existing installation'
    Check ((Get-IG5Hash $deepPath) -eq (Get-IG5Hash (Join-Path $installed $deepRelative))) 'long source path was changed or dropped by installer'
    Pass 'source paths beyond 300 characters enumerate, hash and install without truncation'
    $bridge = Join-Path $runtime 'x64dbg\snapshot\release\x32\plugins\ig5-bridge.dp32'
    $bridgeText = [IO.File]::ReadAllText($bridge)
    Remove-Item -LiteralPath $bridge
    $null = Run-Script $install @('-DshRoot',$dsh) $false 'ig5-bridge.dp32'
    Check-NoMutation $dsh $before $backups
    Put $bridge $bridgeText
    Pass 'missing x86 bridge fails before touching an existing plugin or profile'

    Put $bridge 'changed'
    $null = Run-Script $install @('-DshRoot',$dsh) $false 'SHA-256'
    Check-NoMutation $dsh $before $backups
    Put $bridge $bridgeText
    Pass 'same-size content corruption fails SHA-256 preflight without partial installation'

    $manifestPath = Join-Path $runtime 'manifest.json'
    $manifestText = [IO.File]::ReadAllText($manifestPath)
    $bad = $manifestText | ConvertFrom-Json
    $bad.files += [pscustomobject]@{path='../escape.dll';bytes=1;sha256=('0'*64)}
    Put-Json $manifestPath $bad
    $null = Run-Script $install @('-DshRoot',$dsh) $false 'escape.dll'
    Check-NoMutation $dsh $before $backups
    Put $manifestPath $manifestText
    Pass 'manifest traversal is rejected before mutation'

    Put (Join-Path $runtime 'x64dbg\unlisted.dll')
    $null = Run-Script $install @('-DshRoot',$dsh) $false 'unlisted.dll'
    Check-NoMutation $dsh $before $backups
    Remove-Item -LiteralPath (Join-Path $runtime 'x64dbg\unlisted.dll')
    Pass 'unlisted runtime payload is rejected'

    $output = Join-Path $testRoot 'portable-output'
    $result = Run-Script $packager @('-OutputRoot',$output)
    $portable = ($result -split "`r?`n" | Where-Object { $_ -like 'PORTABLE_ROOT=*' } | Select-Object -First 1).Substring('PORTABLE_ROOT='.Length).Trim()
    Check (Test-Path -LiteralPath (Join-Path $portable 'plugin\runtimes\ghidra\runtime.json')) 'portable runtime is not inside plugin'
    Check (-not (Test-Path -LiteralPath (Join-Path $portable 'runtimes'))) 'portable still has external sibling runtimes'
    Check (Test-Path -LiteralPath (Join-Path $portable 'plugin\third_party\sources\upstream\code.cpp')) 'upstream source assets were dropped'
    Check (-not (Test-Path -LiteralPath (Join-Path $portable 'plugin\.downloads'))) 'portable leaked development downloads'
    foreach ($name in @('lib\unicorn.dll','__init__.py')) {
        Check ((Get-FileHash -LiteralPath (Join-Path $fixture "worker\vendor\unicorn\$name")).Hash -eq (Get-FileHash -LiteralPath (Join-Path $portable "plugin\worker\vendor\unicorn\$name")).Hash) "portable changed vendor file $name"
    }
    foreach ($name in @('projects','sessions','downloads','toolchain','__pycache__','node_modules')) { Check (Test-Path -LiteralPath (Join-Path $portable "plugin\third_party\sources\upstream\$name\source.txt")) "upstream same-name source directory dropped: $name" }
    $instructions = Get-Content -LiteralPath (Join-Path $portable 'INSTALL.txt') -Raw
    Check ($instructions.Contains('& .\plugin\install.ps1') -and -not $instructions.Contains('-RuntimeSource')) 'portable installation requires extra parameters'
    $null = Assert-IG5RuntimePack (Join-Path $portable 'plugin\runtimes')
    $release = Get-Content -LiteralPath (Join-Path $portable 'manifest.json') -Raw | ConvertFrom-Json
    foreach ($file in $release.files) {
        $full = Resolve-IG5PackPath $portable $file.path
        Check ((Get-IG5Hash $full) -eq $file.sha256) "portable manifest mismatch: $($file.path)"
        Check (-not (Test-IG5ExcludedPath $file.path)) "portable leaked cache: $($file.path)"
    }
    Pass 'default portable pack preserves plugin/runtimes, licenses, source assets and complete hashes'

    $portableDsh = Join-Path $testRoot 'portable-dsh'
    New-Profile $portableDsh
    $null = Run-Script (Join-Path $portable 'plugin\install.ps1') @('-DshRoot',$portableDsh)
    $null = Assert-IG5RuntimePack (Join-Path $portableDsh 'plugins\dsh-infinite-gen-5\runtimes')
    Pass 'the packaged installer works without RuntimeSource or setup scripts'

    $sourceZip = Join-Path $testRoot 'source-only'
    Copy-IG5Pack $fixture $sourceZip @('runtimes','third_party/sources')
    $sourceHost = Join-Path $sourceZip 'index.js'
    Put $sourceHost 'export default {localSourceRevision: "retain-this-code"};'
    $sourceHash = Get-IG5Hash $sourceHost
    Assert-IG5PluginSource $sourceZip -CoreOnly
    $sourceInstaller = Join-Path $sourceZip 'install.ps1'
    $sourceDsh = Join-Path $testRoot 'source-dsh'
    New-Profile $sourceDsh
    $sourceProfile = Join-Path $sourceDsh 'profiles\default\package.json'
    $sourceBefore = Read-IG5Text $sourceProfile
    $null = Run-Script $sourceInstaller @('-DshRoot',$sourceDsh,'-Offline') $false 'Source ZIP lacks runtime/upstream assets'
    Check ((Read-IG5Text $sourceProfile) -eq $sourceBefore -and -not (Test-IG5Path (Join-Path $sourceDsh 'plugins'))) 'offline source preflight changed DSH'
    Pass 'source ZIP offline without assets gives actionable release/local-asset instructions and no profile mutation'

    $null = Run-Script $sourceInstaller @('-DshRoot',$sourceDsh,'-DistributionRoot',$portable,'-Offline')
    $sourceInstalled = Join-Path $sourceDsh 'plugins\dsh-infinite-gen-5'
    Check ((Get-IG5Hash (Join-Path $sourceInstalled 'index.js')) -eq $sourceHash) 'source bootstrap replaced local source with old release code'
    Check ((Get-IG5Hash $sourceHost) -eq $sourceHash) 'source bootstrap changed the original checkout'
    Check (-not (Test-IG5Path (Join-Path $sourceZip 'runtimes')) -and -not (Test-IG5Path (Join-Path $sourceZip 'third_party\sources'))) 'source bootstrap wrote assets into the source checkout'
    $null = Assert-IG5RuntimePack (Join-Path $sourceInstalled 'runtimes')
    Assert-IG5PluginSource $sourceInstalled
    Pass 'source ZIP supplements verified local release assets, installs complete engines/upstream source and preserves local code'

    Put (Join-Path $sourceInstalled 'keep.txt')
    $sourceBefore = Read-IG5Text $sourceProfile
    $sourceBackups = @(Get-ChildItem -LiteralPath (Split-Path $sourceProfile) -Filter '*.bak-*').Count
    $descriptorPath = Join-Path $sourceZip 'scripts\distribution.json'
    $descriptorOriginal = Read-IG5Text $descriptorPath
    $badDescriptor = $descriptorOriginal | ConvertFrom-Json
    $badDescriptor.runtimeManifestSha256 = '0'*64
    Put-Json $descriptorPath $badDescriptor
    $null = Run-Script $sourceInstaller @('-DshRoot',$sourceDsh,'-DistributionRoot',$portable,'-Offline') $false 'Pinned distribution manifest SHA-256 mismatch'
    Check-NoMutation $sourceDsh $sourceBefore $sourceBackups
    Put $descriptorPath $descriptorOriginal
    $sourceCore = Join-Path $sourceZip 'source\json_output.js'
    $sourceCoreText = Read-IG5Text $sourceCore
    [IO.File]::Delete((ConvertTo-IG5IOPath $sourceCore))
    $null = Run-Script $sourceInstaller @('-DshRoot',$sourceDsh) $false 'source/json_output.js'
    Check-NoMutation $sourceDsh $sourceBefore $sourceBackups
    Put $sourceCore $sourceCoreText
    Put (Join-Path $sourceZip 'runtimes\partial.txt')
    $null = Run-Script $sourceInstaller @('-DshRoot',$sourceDsh,'-Offline') $false 'third_party/sources/manifest.json'
    Check-NoMutation $sourceDsh $sourceBefore $sourceBackups
    Remove-IG5Tree (Join-Path $sourceZip 'runtimes')
    Pass 'mismatched asset pins, incomplete own code and partial full packs fail before mutating existing DSH'

    # Simulate another process updating profile JSON during asset preparation, using a fixture-only wrapper.
    $bootstrapPath = Join-Path $sourceZip 'scripts\bootstrap_distribution.ps1'
    $bootstrapText = Read-IG5Text $bootstrapPath
    $concurrentPkg = $sourceBefore | ConvertFrom-Json
    $concurrentPkg.dependencies | Add-Member -NotePropertyName userConcurrentPlugin -NotePropertyValue '2.0'
    $concurrentText = $concurrentPkg | ConvertTo-Json -Depth 20
    $fixtureHook = @'
$script:fixturePrepare = (Get-Item Function:New-IG5SourceDistribution).ScriptBlock
function New-IG5SourceDistribution {
    param([string]$SourceRoot,[string]$PluginVersion,[string]$DistributionRoot,[switch]$Offline,[string]$DistributionArchive,[object[]]$CoreFiles)
    $prepared = & $script:fixturePrepare @PSBoundParameters
    [IO.File]::WriteAllText('__PROFILE_PATH__',[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('__PROFILE_TEXT__')),[Text.UTF8Encoding]::new($false))
    return $prepared
}
'@
    $fixtureHook = $fixtureHook.Replace('__PROFILE_PATH__',$sourceProfile.Replace("'","''")).Replace('__PROFILE_TEXT__',[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($concurrentText)))
    Put $bootstrapPath ($bootstrapText + [Environment]::NewLine + $fixtureHook)
    try {
        $null = Run-Script $sourceInstaller @('-DshRoot',$sourceDsh,'-DistributionRoot',$portable,'-Offline') $false 'Profile changed during preparation'
        Check ((Read-IG5Text $sourceProfile) -eq $concurrentText) 'installer overwrote a concurrent profile edit'
        Check-NoMutation $sourceDsh $concurrentText $sourceBackups
    } finally { Put $bootstrapPath $bootstrapText; Put $sourceProfile $sourceBefore }
    Pass 'profile edits made during long preparation are preserved and abort before switching the existing plugin'

    # A source edit after the donor was checked must not become a new trusted snapshot.
    $coreRaceHook = @'
$script:fixtureAssets = (Get-Item Function:Assert-IG5DistributionAssets).ScriptBlock
function Assert-IG5DistributionAssets {
    param([string]$DistributionRoot,$Descriptor,[string]$PluginVersion)
    $donor = & $script:fixtureAssets @PSBoundParameters
    [IO.File]::WriteAllText('__CORE_PATH__',[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('__CORE_TEXT__')),[Text.UTF8Encoding]::new($false))
    return $donor
}
'@
    $sourceHostText = Read-IG5Text $sourceHost
    $coreRaceHook = $coreRaceHook.Replace('__CORE_PATH__',$sourceHost.Replace("'","''")).Replace('__CORE_TEXT__',[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($sourceHostText.Replace('export','exporX'))))
    Put $bootstrapPath ($bootstrapText + [Environment]::NewLine + $coreRaceHook)
    try {
        $null = Run-Script $sourceInstaller @('-DshRoot',$sourceDsh,'-DistributionRoot',$portable,'-Offline') $false 'prepared-core/index.js'
        Check-NoMutation $sourceDsh $sourceBefore $sourceBackups
    } finally { Put $bootstrapPath $bootstrapText; Put $sourceHost $sourceHostText }
    Pass 'source edits during asset preparation fail against the original core snapshot before touching DSH'

    $stagePinHook = @'
$script:fixtureWrite = (Get-Item Function:Write-IG5RuntimeManifest).ScriptBlock
function Write-IG5RuntimeManifest {
    param($Validated,[string]$Destination,[string]$PluginVersion)
    & $script:fixtureWrite @PSBoundParameters
    [IO.File]::WriteAllText((Join-Path $Destination 'x64dbg\licenses\NOTICE.txt'),'stage-time replacement',[Text.UTF8Encoding]::new($false))
    $files = @(Get-IG5PackFiles $Destination | Where-Object Name -ne 'manifest.json' | ForEach-Object {
        @{path=(Get-IG5RelativePath $Destination $_.FullName);bytes=$_.Length;sha256=(Get-IG5Hash $_.FullName)}
    })
    $manifest = @{schemaVersion=1;pluginVersion=$PluginVersion;platform='win32-x64';engines=@('ghidra','x64dbg');files=$files}
    [IO.File]::WriteAllText((Join-Path $Destination 'manifest.json'),($manifest | ConvertTo-Json -Depth 8),[Text.UTF8Encoding]::new($false))
}
'@
    Put $bootstrapPath ($bootstrapText + [Environment]::NewLine + $stagePinHook)
    try {
        $null = Run-Script $sourceInstaller @('-DshRoot',$sourceDsh,'-DistributionRoot',$portable,'-Offline') $false 'Pinned distribution manifest SHA-256 mismatch'
        Check-NoMutation $sourceDsh $sourceBefore $sourceBackups
    } finally { Put $bootstrapPath $bootstrapText }
    Pass 'final installer stage rejects replacement assets with a self-consistent new manifest against immutable pins'

    $externalDsh = Join-Path $testRoot 'external-profile'
    New-Profile $externalDsh
    $linkedDsh = Join-Path $testRoot 'linked-dsh'
    New-Item -ItemType Directory -Path $linkedDsh | Out-Null
    New-Item -ItemType Junction -Path (Join-Path $linkedDsh 'profiles') -Target (Join-Path $externalDsh 'profiles') | Out-Null
    $linkedBefore = Read-IG5Text (Join-Path $externalDsh 'profiles\default\package.json')
    $null = Run-Script $install @('-DshRoot',$linkedDsh) $false 'Path ancestor cannot be a link'
    Check ((Read-IG5Text (Join-Path $externalDsh 'profiles\default\package.json')) -eq $linkedBefore) 'installer wrote through profile root junction'
    [IO.Directory]::Delete((Join-Path $linkedDsh 'profiles'))
    Pass 'profile-root junction is rejected before writing outside the selected DSH root'

    $fixtureZip = Join-Path $testRoot 'release-fixture.zip'
    $zipRows = @(Get-IG5PackFiles $portable | ForEach-Object { @{path=(Get-IG5RelativePath $portable $_.FullName);file=$_.FullName} })
    New-Zip $fixtureZip $zipRows
    $zipHash = Get-IG5Hash $fixtureZip
    $zipExtract = Join-Path $testRoot 'safe-extracted'
    Expand-IG5VerifiedZip $fixtureZip $zipExtract
    $null = Assert-IG5DistributionAssets $zipExtract $descriptor '1.0.0'
    Check ((Get-IG5Hash (Join-Path $zipExtract "plugin\$deepRelative")) -eq (Get-IG5Hash $deepPath)) 'ZIP extraction lost long Windows paths'
    Pass 'safe ZIP extraction preserves long paths and passes full distribution/pinned asset inventories'

    # A fixed older release supplies immutable assets, while the new core is retained.
    $descriptor | Add-Member -NotePropertyName assetSha256 -NotePropertyValue $zipHash -Force
    $descriptor | Add-Member -NotePropertyName assetBytes -NotePropertyValue (New-Object IO.FileInfo $fixtureZip).Length -Force
    Put-Json $descriptorPath $descriptor
    Put-Json (Join-Path $fixture 'scripts\distribution.json') $descriptor
    $null = Run-Script $sourceInstaller @('-DshRoot',$sourceDsh,'-DistributionArchive',$fixtureZip,'-Offline')
    Check ((Get-IG5Hash (Join-Path $sourceInstalled 'index.js')) -eq $sourceHash) 'offline archive recovery replaced Source ZIP core'
    Pass 'source ZIP installs from a fixed SHA-256 original ZIP fully offline, preserving current code'

    $repairResult = Run-Script $packager @('-OutputRoot',(Join-Path $testRoot 'repair-package'))
    $repairPortable = ($repairResult -split "`r?`n" | Where-Object { $_ -like 'PORTABLE_ROOT=*' } | Select-Object -First 1).Substring('PORTABLE_ROOT='.Length).Trim()
    $repairInstaller = Join-Path $repairPortable 'plugin\install.ps1'
    $repairDsh = Join-Path $testRoot 'repair-dsh'
    New-Profile $repairDsh
    $null = Run-Script $repairInstaller @('-DshRoot',$repairDsh)
    $repairInstalled = Join-Path $repairDsh 'plugins\dsh-infinite-gen-5'
    Put (Join-Path $repairInstalled 'keep.txt')
    $repairProfilePath = Join-Path $repairDsh 'profiles\default\package.json'
    $repairBefore = Read-IG5Text $repairProfilePath
    $repairBackups = @(Get-ChildItem -LiteralPath (Split-Path $repairProfilePath) -Filter '*.bak-*').Count
    $damagedSource = Join-Path $repairPortable 'plugin\third_party\sources\upstream\code.cpp'
    $goodSourceText = Read-IG5Text $damagedSource
    Put $damagedSource ($goodSourceText.Replace('source','sourcX'))
    $badSourceHash = Get-IG5Hash $damagedSource
    $failureText = Run-Script $repairInstaller @('-DshRoot',$repairDsh) $false 'Expected SHA-256:'
    Check ($failureText.Contains('Actual SHA-256:') -and $failureText.Contains($badSourceHash)) 'failure lacks exact expected/actual checksum diagnostics'
    Check-NoMutation $repairDsh $repairBefore $repairBackups
    $null = Run-Script $repairInstaller @('-DshRoot',$repairDsh,'-RepairAssets','-DistributionArchive',$fixtureZip,'-Offline')
    Check ((Get-IG5Hash $damagedSource) -eq $badSourceHash) 'repair modified the original damaged extraction'
    Check ((Read-IG5Text (Join-Path $repairInstalled 'third_party\sources\upstream\code.cpp')) -eq $goodSourceText) 'repair did not restore verified source asset bytes'
    Check ((Get-IG5Hash (Join-Path $repairInstalled 'index.js')) -eq (Get-IG5Hash (Join-Path $repairPortable 'plugin\index.js'))) 'repair changed current plugin core'
    Check (-not (Test-IG5Path (Join-Path $repairInstalled 'keep.txt'))) 'repair left a partial previous install'
    $null = Assert-IG5RuntimePack (Join-Path $repairInstalled 'runtimes')
    Pass 'same-size source corruption is diagnosed and repaired from the pinned ZIP without editing input or skipping inventories'

    Put (Join-Path $repairInstalled 'keep.txt')
    $repairBefore = Read-IG5Text $repairProfilePath
    $repairBackups = @(Get-ChildItem -LiteralPath (Split-Path $repairProfilePath) -Filter '*.bak-*').Count
    $repairCore = Join-Path $repairPortable 'plugin\index.js'
    $repairCoreText = Read-IG5Text $repairCore
    Put $repairCore ($repairCoreText.Replace('export','exporX'))
    $null = Run-Script $repairInstaller @('-DshRoot',$repairDsh,'-RepairAssets','-DistributionArchive',$fixtureZip,'-Offline') $false 'plugin-core/index.js'
    Check-NoMutation $repairDsh $repairBefore $repairBackups
    Put $repairCore $repairCoreText
    Pass 'asset repair refuses changed core code before touching profiles or existing installation'

    # A legitimately sealed fixture adds a hook which changes prepared code only after
    # the helper returns. The installer must retain the original outer core records.
    $repairBootstrapPath = Join-Path $repairPortable 'plugin\scripts\bootstrap_distribution.ps1'
    $repairBootstrapText = Read-IG5Text $repairBootstrapPath
    $preparedRaceHook = @'
$script:fixturePrepare = (Get-Item Function:New-IG5SourceDistribution).ScriptBlock
function New-IG5SourceDistribution {
    param([string]$SourceRoot,[string]$PluginVersion,[string]$DistributionRoot,[switch]$Offline,[string]$DistributionArchive,[object[]]$CoreFiles)
    $prepared = & $script:fixturePrepare @PSBoundParameters
    $index = Join-Path $prepared.Root 'index.js'
    [IO.File]::WriteAllText($index,(Read-IG5Text $index).Replace('export','exporX'),[Text.UTF8Encoding]::new($false))
    return $prepared
}
'@
    $repairOuterPath = Join-Path $repairPortable 'manifest.json'
    $repairOuterText = Read-IG5Text $repairOuterPath
    Put $repairBootstrapPath ($repairBootstrapText + [Environment]::NewLine + $preparedRaceHook)
    $raceOuter = $repairOuterText | ConvertFrom-Json
    foreach ($row in $raceOuter.files) {
        if ($row.path -eq 'plugin/scripts/bootstrap_distribution.ps1') { $row.sha256=Get-IG5Hash $repairBootstrapPath; $row.bytes=(New-Object IO.FileInfo $repairBootstrapPath).Length }
    }
    Put-Json $repairOuterPath $raceOuter
    try {
        $null = Run-Script $repairInstaller @('-DshRoot',$repairDsh,'-RepairAssets','-DistributionArchive',$fixtureZip,'-Offline') $false 'core-after-preparation/index.js'
        Check-NoMutation $repairDsh $repairBefore $repairBackups
    } finally { Put $repairBootstrapPath $repairBootstrapText; Put $repairOuterPath $repairOuterText }
    Pass 'full asset repair retains the authenticated outer core hashes through preparation and rejects a later code change'

    $damagedZip = Join-Path $testRoot 'damaged-original.zip'
    [IO.File]::Copy($fixtureZip,$damagedZip)
    $damagedZipBytes = [IO.File]::ReadAllBytes($damagedZip)
    $damagedZipBytes[100] = $damagedZipBytes[100] -bxor 1
    [IO.File]::WriteAllBytes($damagedZip,$damagedZipBytes)
    $null = Run-Script $repairInstaller @('-DshRoot',$repairDsh,'-RepairAssets','-DistributionArchive',$damagedZip,'-Offline') $false 'DistributionArchive SHA-256 differs'
    Check-NoMutation $repairDsh $repairBefore $repairBackups
    $null = Run-Script $repairInstaller @('-DshRoot',$repairDsh,'-RepairAssets','-DistributionArchive',$fixtureZip,'-DistributionRoot',$portable,'-Offline') $false 'Choose either'
    Check-NoMutation $repairDsh $repairBefore $repairBackups
    Pass 'fixed ZIP digest and mutually exclusive donor arguments reject unsafe recovery without mutation'

    $insideArchive = Join-Path $sourceZip 'original-full.zip'
    [IO.File]::Copy($fixtureZip,$insideArchive)
    try {
        $null = Run-Script $sourceInstaller @('-DshRoot',$sourceDsh,'-DistributionArchive',$insideArchive,'-Offline') $false 'Place DistributionArchive outside'
        $null = Run-Script $sourceInstaller @('-DshRoot',$sourceDsh,'-DistributionRoot',$sourceZip,'-Offline') $false 'separate non-overlapping'
    } finally { [IO.File]::Delete($insideArchive) }
    Pass 'archive and donor overlap are rejected so downloaded assets cannot become copied plugin code'

    # Preserve the current snapshot after the successful archive-backed reinstall.
    $sourceBefore = Read-IG5Text $sourceProfile
    $sourceBackups = @(Get-ChildItem -LiteralPath (Split-Path $sourceProfile) -Filter '*.bak-*').Count
    Put (Join-Path $sourceInstalled 'keep.txt')

    $tamperedDonor = Join-Path $testRoot 'rewritten-upstream-release'
    Copy-IG5Pack $portable $tamperedDonor
    $tamperedCode = Join-Path $tamperedDonor 'plugin\third_party\sources\upstream\code.cpp'
    Put $tamperedCode 'rewritten upstream content'
    $tamperedInventoryPath = Join-Path $tamperedDonor 'plugin\third_party\sources\provenance\upstream.files.json'
    $tamperedRows = Read-IG5Text $tamperedInventoryPath | ConvertFrom-Json
    foreach ($row in $tamperedRows) { if ($row.path -eq 'code.cpp') { $row.sha256=Get-IG5Hash $tamperedCode; $row.bytes=(New-Object IO.FileInfo $tamperedCode).Length } }
    Put-Json $tamperedInventoryPath $tamperedRows
    $tamperedOuterPath = Join-Path $tamperedDonor 'manifest.json'
    $tamperedOuter = Read-IG5Text $tamperedOuterPath | ConvertFrom-Json
    foreach ($row in $tamperedOuter.files) {
        if ($row.path -in @('plugin/third_party/sources/upstream/code.cpp','plugin/third_party/sources/provenance/upstream.files.json')) {
            $filePath = Resolve-IG5PackPath $tamperedDonor $row.path
            $row.sha256=Get-IG5Hash $filePath; $row.bytes=(New-Object IO.FileInfo (ConvertTo-IG5IOPath $filePath)).Length
        }
    }
    Put-Json $tamperedOuterPath $tamperedOuter
    Expect-Failure { Assert-IG5DistributionAssets $tamperedDonor $descriptor '1.0.0' } 'Pinned source inventory SHA-256 mismatch'
    Pass 'rewriting upstream source plus its inventory and outer release manifest still fails the fixed inventory hash pin'

    # Copy-time replacement can be internally self-consistent; fixed pins must still win.
    $copyDefinition = (Get-Item Function:Copy-IG5Pack).ScriptBlock
    $script:fixtureCopy = $copyDefinition
    function Copy-IG5Pack {
        param([string]$From,[string]$To,[string[]]$ExtraExclude=@())
        & $script:fixtureCopy @PSBoundParameters
        if ($To -like '*\prepared-plugin\runtimes') {
            Put (Join-Path $To 'x64dbg\licenses\NOTICE.txt') 'copy-time replacement'
            Manifest $To
        }
    }
    try {
        Expect-Failure { New-IG5SourceDistribution $sourceZip '1.0.0' $portable -Offline } 'Pinned distribution manifest SHA-256 mismatch'
        Check-NoMutation $sourceDsh $sourceBefore $sourceBackups
    } finally { Set-Item Function:Copy-IG5Pack $copyDefinition }
    Pass 'prepared assets are rechecked against fixed pins even when replacement bytes have a self-consistent new inventory'

    $badZipCases = @(
        @{name='traversal';rows=@(@{path='../outside.txt';text='bad'});expected='Unsafe ZIP path'},
        @{name='drive';rows=@(@{path='C:/outside.txt';text='bad'});expected='Unsafe ZIP path'},
        @{name='backslash';rows=@(@{path='plugin\..\outside.txt';text='bad'});expected='Unsafe ZIP path'},
        @{name='duplicate';rows=@(@{path='plugin/a';text='a'},@{path='PLUGIN/A';text='b'});expected='Duplicate ZIP path'},
        @{name='parent-collision';rows=@(@{path='plugin/a';text='a'},@{path='plugin/a/child';text='b'});expected='ZIP file/directory collision'},
        @{name='child-collision';rows=@(@{path='plugin/a/child';text='a'},@{path='plugin/a';text='b'});expected='ZIP file/directory collision'},
        @{name='reserved';rows=@(@{path='plugin/NUL.txt';text='bad'});expected='Unsafe ZIP path'},
        @{name='symlink';rows=@(@{path='plugin/link';text='target';attrs=-1610612736});expected='ZIP link/special entry rejected'}
    )
    foreach ($case in $badZipCases) {
        $badZip = Join-Path $testRoot ($case.name + '.zip')
        $badExtract = Join-Path $testRoot ($case.name + '-extract')
        New-Zip $badZip $case.rows
        Expect-Failure { Expand-IG5VerifiedZip $badZip $badExtract } $case.expected
        Check (-not (Test-IG5Path $badExtract)) "unsafe ZIP wrote files before full validation: $($case.name)"
    }
    Pass 'ZIP traversal, drive/ambiguous paths, case duplicates, file/directory collisions, reserved names and links are rejected before extraction'

    $forgedZip = Join-Path $testRoot 'forged-length.zip'
    New-Zip $forgedZip @(@{path='forged.txt';text=('A'*65536)})
    $zipBytes = [IO.File]::ReadAllBytes($forgedZip)
    $central = -1
    for ($i=0; $i -lt $zipBytes.Length-28; $i++) { if ([BitConverter]::ToUInt32($zipBytes,$i) -eq 0x02014b50) { $central=$i; break } }
    Check ($central -ge 0) 'ZIP fixture central directory not found'
    [BitConverter]::GetBytes([uint32]1).CopyTo($zipBytes,$central+24)
    [IO.File]::WriteAllBytes($forgedZip,$zipBytes)
    $forgedExtract = Join-Path $testRoot 'forged-extract'
    Expect-Failure { Expand-IG5VerifiedZip $forgedZip $forgedExtract } 'ZIP expanded byte/time budget exceeded'
    Check ((New-Object IO.FileInfo (Join-Path $forgedExtract 'forged.txt')).Length -le 1) 'forged ZIP length allowed excess bytes onto disk'
    Pass 'forged ZIP central-directory length is enforced before writing expanded bytes'

    # Exercise the network bootstrap control flow with deterministic local data; no network calls.
    $downloadDefinition = (Get-Item Function:Invoke-IG5DistributionDownload).Definition
    $script:mockRequests = @()
    $script:mockRelease = @{tag_name=$descriptor.releaseTag;draft=$false;assets=@(
        @{name=$descriptor.assetName;size=(New-Object IO.FileInfo $fixtureZip).Length;digest=('sha256:'+$zipHash);browser_download_url="https://github.com/$($descriptor.repository)/releases/download/$($descriptor.releaseTag)/$($descriptor.assetName)"},
        @{name=($descriptor.assetName+'.sha256');size=($zipHash+'  '+$descriptor.assetName).Length;browser_download_url="https://github.com/$($descriptor.repository)/releases/download/$($descriptor.releaseTag)/$($descriptor.assetName).sha256"})}
    function Invoke-IG5DistributionDownload {
        param([string]$Url,[string]$OutputPath,[long]$MaxBytes,[long]$ExpectedBytes=-1,[switch]$Progress)
        $script:mockRequests += $Url
        if ($Url.StartsWith('https://api.github.com/')) { return ($script:mockRelease | ConvertTo-Json -Depth 12) }
        if ($Url.EndsWith('.sha256')) { return ($zipHash+'  '+$descriptor.assetName) }
        [IO.File]::Copy($fixtureZip,$OutputPath,$true)
    }
    try {
        $prepared = New-IG5SourceDistribution $sourceZip '1.0.0'
        try { Check ((Get-IG5Hash (Join-Path $prepared.Root 'index.js')) -eq $sourceHash) 'online control flow replaced source code' }
        finally { Remove-IG5BootstrapWorkspace $prepared.Workspace }
        Check ($script:mockRequests.Count -eq 3) 'bootstrap did not request metadata, checksum and ZIP exactly once'
        $script:mockRelease.assets[0].digest = 'sha256:' + ('0'*64)
        $script:mockRequests = @()
        Expect-Failure { New-IG5SourceDistribution $sourceZip '1.0.0' } 'GitHub asset digest differs'
        Check ($script:mockRequests.Count -eq 2) 'digest mismatch still downloaded ZIP'
        Check-NoMutation $sourceDsh $sourceBefore $sourceBackups
        $script:mockRelease.assets[0].digest = 'sha256:' + $zipHash
        $script:mockRelease.assets[0].size = 2GB + 1
        Expect-Failure { New-IG5SourceDistribution $sourceZip '1.0.0' } 'Release asset size exceeds'
        $script:mockRequests = @()
        [IO.File]::Delete((ConvertTo-IG5IOPath $sourceCore))
        Expect-Failure { New-IG5SourceDistribution $sourceZip '1.0.0' } 'source/json_output.js'
        Check ($script:mockRequests.Count -eq 0) 'incomplete source triggered network requests'
        Put $sourceCore $sourceCoreText
        function Invoke-IG5DistributionDownload { throw 'fixture-network-unavailable' }
        Expect-Failure { New-IG5SourceDistribution $sourceZip '1.0.0' } 'Use the full ZIP at https://github.com/'
        Check-NoMutation $sourceDsh $sourceBefore $sourceBackups
    } finally { Set-Item Function:Invoke-IG5DistributionDownload ([scriptblock]::Create($downloadDefinition)) }
    Pass 'network bootstrap control flow checks metadata/checksum/digest/ZIP budgets, preserves source and fails with offline instructions; local fixtures only'

    # Corrupt plugin files and injected payloads are checked against the outer complete-release manifest.
    $portableHost = Join-Path $portable 'plugin\index.js'
    $hostText = Read-IG5Text $portableHost
    Put $portableHost ($hostText.Replace('export', 'exporX'))
    $null = Run-Script (Join-Path $portable 'plugin\install.ps1') @('-DshRoot',$portableDsh) $false 'SHA-256'
    Put $portableHost $hostText
    Put (Join-Path $portable 'plugin\extra_payload.dll')
    $null = Run-Script (Join-Path $portable 'plugin\install.ps1') @('-DshRoot',$portableDsh) $false 'extra_payload.dll'
    Remove-Item -LiteralPath (Join-Path $portable 'plugin\extra_payload.dll')
    Pass 'complete release plugin SHA verification rejects changed code and injected payloads'

    # Compatible explicit input: old layouts had sibling runtimes and a parent SHA manifest.
    $legacyRoot = Join-Path $testRoot 'legacy'
    $legacyRuntime = Join-Path $legacyRoot 'runtimes'
    Copy-IG5Pack $runtime $legacyRuntime
    $legacyManifest = Get-Content -LiteralPath (Join-Path $legacyRuntime 'manifest.json') -Raw | ConvertFrom-Json
    foreach ($file in $legacyManifest.files) { $file.path = 'runtimes/' + $file.path }
    Put-Json (Join-Path $legacyRoot 'manifest.json') $legacyManifest
    Remove-Item -LiteralPath (Join-Path $legacyRuntime 'manifest.json')
    $legacyDsh = Join-Path $testRoot 'legacy-dsh'
    New-Profile $legacyDsh
    $null = Run-Script $install @('-DshRoot',$legacyDsh,'-RuntimeSource',$legacyRuntime)
    $null = Assert-IG5RuntimePack (Join-Path $legacyDsh 'plugins\dsh-infinite-gen-5\runtimes')
    Pass 'explicit legacy RuntimeSource migrates sibling-runtime parent hash manifest into the plugin'

    $failedOutput = Join-Path $testRoot 'must-not-exist'
    Remove-Item -LiteralPath $bridge
    $null = Run-Script $packager @('-OutputRoot',$failedOutput) $false 'ig5-bridge.dp32'
    Check (-not (Test-Path -LiteralPath $failedOutput)) 'invalid pack created a partial output directory'
    Put $bridge $bridgeText
    Pass 'packaging an incomplete source creates no partial release'

    Put (Join-Path $dsh 'ig5\projects\user-project.txt') 'preserve project'
    Put (Join-Path $dsh 'ig5\state\user-state.txt') 'preserve state'
    Put (Join-Path $dsh 'plugins\other-plugin\user.txt') 'preserve other plugin'
    $badProfile = Join-Path $dsh 'profiles\broken\package.json'
    Put $badProfile '{ invalid'
    $badText = Read-IG5Text $badProfile
    $profileBeforeUninstall = Read-IG5Text $profilePath
    $null = Run-Script (Join-Path $fixture 'uninstall.ps1') @('-DshRoot',$dsh) $false 'JSON'
    Check ((Read-IG5Text $badProfile) -eq $badText) 'uninstall overwrote invalid JSON'
    Check ((Read-IG5Text $profilePath) -eq $profileBeforeUninstall) 'uninstall changed a good profile before rejecting the bad one'
    Check (Test-IG5Path (Join-Path $installed 'keep.txt') Leaf) 'invalid JSON uninstall removed plugin'
    Pass 'invalid profile JSON aborts uninstall before changing any profile or plugin'
    Put-Json $badProfile @{name='repaired';dependencies=@{}}
    $null = Run-Script (Join-Path $fixture 'uninstall.ps1') @('-DshRoot',$dsh)
    Check (-not (Test-IG5Path $installed)) 'uninstall retained active plugin'
    foreach ($saved in @('ig5\projects\user-project.txt','ig5\state\user-state.txt','plugins\other-plugin\user.txt')) { Check (Test-IG5Path (Join-Path $dsh $saved) Leaf) "uninstall deleted user data: $saved" }
    $profileAfter = Read-IG5Text $profilePath | ConvertFrom-Json
    Check ($profileAfter.dependencies.'other-plugin' -eq '1.0') 'uninstall changed other plugin dependency'
    Check ($profileAfter.dependencies.PSObject.Properties.Name -notcontains 'dsh-infinite-gen-5') 'uninstall retained IG5 dependency'
    Pass 'explicit DshRoot uninstall preserves projects, state, other plugins and profile backups'
    Write-Output "=== INSTALL/PACKAGE REGRESSIONS PASSED ($passed scenarios; fake runtime files; no engine or real profile launched) ==="
} finally {
    if ($KeepFixture) { Write-Output "FIXTURE_ROOT=$testRoot" }
    elseif (Test-Path -LiteralPath $testRoot) {
        $safe = [IO.Path]::GetFullPath($testRoot)
        $boundary = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\') + '\'
        if (-not $safe.StartsWith($boundary, [StringComparison]::OrdinalIgnoreCase) -or (Split-Path $safe -Leaf) -notlike 'ig5-install-pack-*') { throw 'Unsafe fixture cleanup path' }
        # Remove junctions themselves before recursive fixture cleanup; never traverse their targets.
        Remove-IG5Tree $safe
    }
}
