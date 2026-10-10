param(
  [string]$SourceRoot,
  [string]$BuildRoot = (Join-Path $env:USERPROFILE '.dsh\ig5\artifacts\ghidra-build\native-win-x64'),
  [string]$CMake = 'cmake',
  [string]$Generator = 'Visual Studio 18 2026',
  [string]$ToolchainFile,
  [int]$Parallel = 4
)
$ErrorActionPreference = 'Stop'
if (-not $PSBoundParameters.ContainsKey('SourceRoot')) { $SourceRoot = Join-Path $PSScriptRoot '..\third_party\sources\ghidra-12.1.4' }
$SourceRoot = [IO.Path]::GetFullPath($SourceRoot)
$BuildRoot = [IO.Path]::GetFullPath($BuildRoot)
$properties = Get-Content -LiteralPath (Join-Path $SourceRoot 'Ghidra\application.properties') -Raw
if ($properties -notmatch '(?m)^application.version=12\.1\.4\s*$') { throw 'Expected pinned Ghidra 12.1.4 source baseline' }
New-Item -ItemType Directory -Path $BuildRoot -Force | Out-Null
$configure = @('-S', (Join-Path $PSScriptRoot '..\adapters\ghidra\native-core'), '-B', $BuildRoot, "-DGHIDRA_SOURCE_ROOT=$SourceRoot", '-DCMAKE_BUILD_TYPE=Release')
if ($ToolchainFile) { $configure += "-DCMAKE_TOOLCHAIN_FILE=$([IO.Path]::GetFullPath($ToolchainFile))" }
if ($Generator) { $configure += @('-G', $Generator); if ($Generator -like 'Visual Studio*') { $configure += @('-A', 'x64') } }
& $CMake @configure
if ($LASTEXITCODE -ne 0) { throw 'Ghidra native CMake configure failed' }
& $CMake --build $BuildRoot --config Release --parallel $Parallel
if ($LASTEXITCODE -ne 0) { throw 'Ghidra native compilation failed' }
& $CMake --install $BuildRoot --config Release --prefix (Join-Path $BuildRoot 'install')
if ($LASTEXITCODE -ne 0) { throw 'Ghidra native installation failed' }
$files = @(Get-ChildItem -LiteralPath (Join-Path $BuildRoot 'install') -Recurse -File | ForEach-Object {
  @{path=$_.FullName.Substring($BuildRoot.Length + 1).Replace('\','/'); bytes=$_.Length; sha256=(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()}
})
$proof = @{schemaVersion=1; engine='Ghidra'; version='12.1.4'; commit='8b6bbb857accdfa20dc5b2f5dea471178c2e9fbc'; builtUtc=[DateTime]::UtcNow.ToString('o'); generator=$Generator; toolchainFile=$ToolchainFile; sourceRoot=$SourceRoot; artifacts=$files; fullJavaFrameworkBuilt=$false; mobileHostValidated=$false}
$proof | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $BuildRoot 'build-proof.json') -Encoding utf8
Write-Output (Join-Path $BuildRoot 'build-proof.json')
