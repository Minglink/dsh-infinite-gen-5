param(
  [string]$SourceRoot,
  [string]$BuildRoot,
  [string]$OutputRoot,
  [string]$CMake = 'cmake',
  [string]$Generator = 'Visual Studio 18 2026',
  [int]$Parallel = 4
)
$ErrorActionPreference = 'Stop'
if (-not $SourceRoot) { $SourceRoot = Join-Path $PSScriptRoot '..\..\third_party\sources\ghidra-12.1.4' }
if (-not $BuildRoot) { $BuildRoot = Join-Path $env:USERPROFILE ('.dsh\ig5\artifacts\kernel-reconstruction-20261010\native-decompiler-build-' + [Guid]::NewGuid().ToString('N')) }
if (-not $OutputRoot) { $OutputRoot = Join-Path $PSScriptRoot 'native' }
$SourceRoot = [IO.Path]::GetFullPath($SourceRoot)
$BuildRoot = [IO.Path]::GetFullPath($BuildRoot)
$OutputRoot = [IO.Path]::GetFullPath($OutputRoot)
$properties = Get-Content -LiteralPath (Join-Path $SourceRoot 'Ghidra\application.properties') -Raw
if ($properties -notmatch '(?m)^application.version=12\.1\.4\s*$') { throw 'Expected pinned Ghidra source baseline' }
if ($Parallel -lt 1 -or $Parallel -gt 16) { throw 'Parallel must be between 1 and 16' }
New-Item -ItemType Directory -Path $BuildRoot -Force | Out-Null
$configure = @('-S', (Join-Path $PSScriptRoot 'native-core'), '-B', $BuildRoot, "-DGHIDRA_SOURCE_ROOT=$SourceRoot", '-DCMAKE_BUILD_TYPE=Release')
if ($Generator) { $configure += @('-G', $Generator); if ($Generator -like 'Visual Studio*') { $configure += @('-A', 'x64') } }
& $CMake @configure
if ($LASTEXITCODE -ne 0) { throw 'Native decompiler CMake configure failed' }
& $CMake --build $BuildRoot --config Release --parallel $Parallel
if ($LASTEXITCODE -ne 0) { throw 'Native decompiler compilation failed' }
& $CMake --install $BuildRoot --config Release --prefix $OutputRoot
if ($LASTEXITCODE -ne 0) { throw 'Native decompiler artifact installation failed' }
$sourceFiles = @(Get-Content -LiteralPath (Join-Path $BuildRoot 'upstream-sources.txt') | Where-Object { $_ } | ForEach-Object {
  @{path=$_.Substring($SourceRoot.Length + 1).Replace('\','/'); sha256=(Get-FileHash -LiteralPath $_ -Algorithm SHA256).Hash.ToLowerInvariant()}
})
$dll = Join-Path $OutputRoot 'ig5_decompiler.dll'
$proof = @{schemaVersion=1; engine='IG5 Kernel'; upstream='Ghidra native decompiler'; sourceCommit='8b6bbb857accdfa20dc5b2f5dea471178c2e9fbc'; builtUtc=[DateTime]::UtcNow.ToString('o'); artifact=@{path='ig5_decompiler.dll'; bytes=(Get-Item -LiteralPath $dll).Length; sha256=(Get-FileHash -LiteralPath $dll -Algorithm SHA256).Hash.ToLowerInvariant()}; upstreamSources=$sourceFiles; javaFrameworkLinked=$false; bfdLinked=$false; commercialEngineUsed=$false; nativeExecutionVerified=$false; mobileHostValidated=$false; optimizerDeadline='external isolated worker'}
$proof | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $OutputRoot 'build-proof.json') -Encoding UTF8
Write-Output (Join-Path $OutputRoot 'build-proof.json')
