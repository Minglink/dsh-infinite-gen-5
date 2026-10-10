[CmdletBinding()]
param([switch]$KeepFixture)
$ErrorActionPreference = 'Stop'
$source = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
. (Join-Path $PSScriptRoot 'runtime_pack.ps1')
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
    foreach ($file in @('install.ps1','uninstall.ps1','scripts\runtime_pack.ps1','scripts\package_portable.ps1')) {
        New-Item -ItemType Directory -Path (Split-Path (Join-Path $fixture $file)) -Force | Out-Null
        Copy-Item -LiteralPath (Join-Path $source $file) -Destination (Join-Path $fixture $file)
    }
    Put-Json (Join-Path $fixture 'package.json') @{name='dsh-infinite-gen-5';version='1.0.0'}
    Put (Join-Path $fixture 'index.js') 'export default {};'
    Put (Join-Path $fixture 'client.js') 'export default {};'
    foreach ($file in @('engine_runtime.js','advanced_tools.js','analysis_tools.js','integration_tools.js','workflow.js','semantic_diff.js','semantic_diff_async.js','semantic_diff_worker.js',
        'source/analysis_artifacts.js','source/analysis_jobs.js','source/analysis_worker.js','source/crypto_analysis.js','source/crypto_recovery.js','source/protocol_analysis.js','source/protocol_inference.js','worker/scan_analysis.py',
        'source/project_store.js','source/attachment_lease.js','source/audit_history.js','source/patch_export.js','source/history_index.js','source/address_ref.js','source/host_platform.js','source/worker_transport.js','worker/ig5_worker.py','worker/advanced_analysis.py','worker/execution_analysis.py','worker/memory_image.py','worker/cpu_emulator.py','worker/vendor/NOTICE.txt',
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
    $install = Join-Path $fixture 'install.ps1'
    $packager = Join-Path $fixture 'scripts\package_portable.ps1'
    Assert-IG5PluginSource $fixture
    [IO.File]::WriteAllText((Join-Path $fixture 'third_party\sources\provenance\upstream.files.json'), ($sourceFiles | ConvertTo-Json -Depth 8), [Text.UTF8Encoding]::new($false))
    Assert-IG5PluginSource $fixture
    Pass 'source inventories accept both strict envelope and raw row formats'
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
