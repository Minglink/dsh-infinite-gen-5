param(
  [string]$RuntimeRoot = (Join-Path $PSScriptRoot '..\..\runtimes\x64dbg'),
  [string]$Vcvars = 'C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvarsall.bat',
  [string]$HeaderRoot = (Join-Path $PSScriptRoot '..\..\third_party\sources\x64dbg-runtime\src\dbg'),
  [string]$CoreBuildRoot = (Join-Path $PSScriptRoot '..\..\.downloads\x64dbg-build')
)
$ErrorActionPreference = 'Stop'
$RuntimeRoot = [IO.Path]::GetFullPath($RuntimeRoot)
$sdk = Join-Path $RuntimeRoot 'snapshot\pluginsdk'
$buildDir = Join-Path $RuntimeRoot 'native-build'
New-Item -ItemType Directory -Path $buildDir -Force | Out-Null
$buildProof = @()
foreach ($arch in @('x64','x86')) {
  $taskEnvironment = & cmd.exe /d /s /c "`"$Vcvars`" $arch >nul && set"
  if ($LASTEXITCODE -ne 0) { throw "MSVC environment failed for $arch" }
  foreach ($line in $taskEnvironment) {
    if ($line -match '^([^=]+)=(.*)$') { [Environment]::SetEnvironmentVariable($matches[1], $matches[2], 'Process') }
  }
  $bits = if ($arch -eq 'x64') { '64' } else { '32' }
  $sdkArch = if ($arch -eq 'x64') { 'x64' } else { 'x32' }
  $janssonArch = if ($arch -eq 'x64') { 'x64' } else { 'x86' }
  $output = Join-Path $buildDir "ig5-bridge.dp$bits"
  $builtCore = Join-Path $CoreBuildRoot "$arch\Release"
  $bridgeImport = Join-Path $builtCore "${sdkArch}bridge.lib"
  $dbgImport = Join-Path $builtCore "${sdkArch}dbg.lib"
  if (-not (Test-Path -LiteralPath $bridgeImport)) { $bridgeImport = Join-Path $sdk "${sdkArch}bridge.lib" }
  if (-not (Test-Path -LiteralPath $dbgImport)) { $dbgImport = Join-Path $sdk "${sdkArch}dbg.lib" }
  & cl.exe /nologo /LD /O2 /MT /EHsc /std:c++17 /I $sdk /I $HeaderRoot /Fo"$buildDir\ig5_bridge$bits.obj" (Join-Path $PSScriptRoot 'ig5_bridge.cpp') $bridgeImport $dbgImport "$sdk\jansson\jansson_$janssonArch.lib" /link advapi32.lib /OUT:$output /IMPLIB:"$buildDir\ig5_bridge$bits.lib"
  if ($LASTEXITCODE -ne 0) { throw "Native bridge compilation failed for $arch" }
  $pluginDir = Join-Path $RuntimeRoot "snapshot\release\$sdkArch\plugins"
  New-Item -ItemType Directory -Path $pluginDir -Force | Out-Null
  Copy-Item -LiteralPath $output -Destination $pluginDir -Force
  $portableDir = Join-Path $PSScriptRoot 'native'
  New-Item -ItemType Directory -Path $portableDir -Force | Out-Null
  Copy-Item -LiteralPath $output -Destination $portableDir -Force
  $buildProof += [ordered]@{architecture=$arch;compiler=(Get-Command cl.exe).Source;compilerVersion=(Get-Item -LiteralPath (Get-Command cl.exe).Source).VersionInfo.FileVersion;sourceSHA256=(Get-FileHash -LiteralPath (Join-Path $PSScriptRoot 'ig5_bridge.cpp') -Algorithm SHA256).Hash.ToLowerInvariant();imports=@(@{path=[IO.Path]::GetFileName($bridgeImport);sha256=(Get-FileHash -LiteralPath $bridgeImport -Algorithm SHA256).Hash.ToLowerInvariant()},@{path=[IO.Path]::GetFileName($dbgImport);sha256=(Get-FileHash -LiteralPath $dbgImport -Algorithm SHA256).Hash.ToLowerInvariant()});product="ig5-bridge.dp$bits";productSHA256=(Get-FileHash -LiteralPath $output -Algorithm SHA256).Hash.ToLowerInvariant()}
}
$nativeHashes = @{}
foreach ($bits in @('32','64')) { $nativeHashes["ig5-bridge.dp$bits"] = (Get-FileHash -LiteralPath (Join-Path $PSScriptRoot "native\ig5-bridge.dp$bits") -Algorithm SHA256).Hash.ToLowerInvariant() }
$nativeHashes | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $PSScriptRoot 'native\sha256.json') -Encoding utf8
$proof = [ordered]@{schemaVersion=1;protocol=2;upstreamCommit='9c8ca1cae0b6d56cc44f31fddcb10e3b02ffbb87';built=$buildProof;createdUtc=[DateTime]::UtcNow.ToString('o')}
$proof | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $PSScriptRoot 'native\build-proof.json') -Encoding utf8
$proof | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $RuntimeRoot 'native-build-proof.json') -Encoding utf8
