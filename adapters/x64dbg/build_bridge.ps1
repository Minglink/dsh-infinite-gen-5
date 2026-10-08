param(
  [string]$RuntimeRoot = (Join-Path $PSScriptRoot '..\..\runtimes\x64dbg'),
  [string]$Vcvars = 'C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvarsall.bat',
  [string]$HeaderRoot = (Join-Path $PSScriptRoot '..\..\third_party\sources\x64dbg-runtime\src\dbg')
)
$ErrorActionPreference = 'Stop'
$RuntimeRoot = [IO.Path]::GetFullPath($RuntimeRoot)
$sdk = Join-Path $RuntimeRoot 'snapshot\pluginsdk'
$buildDir = Join-Path $RuntimeRoot 'native-build'
New-Item -ItemType Directory -Path $buildDir -Force | Out-Null
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
  & cl.exe /nologo /LD /O2 /MT /EHsc /std:c++17 /I $sdk /I $HeaderRoot /Fo"$buildDir\ig5_bridge$bits.obj" (Join-Path $PSScriptRoot 'ig5_bridge.cpp') "$sdk\${sdkArch}bridge.lib" "$sdk\${sdkArch}dbg.lib" "$sdk\jansson\jansson_$janssonArch.lib" /link advapi32.lib /OUT:$output /IMPLIB:"$buildDir\ig5_bridge$bits.lib"
  if ($LASTEXITCODE -ne 0) { throw "Native bridge compilation failed for $arch" }
  $pluginDir = Join-Path $RuntimeRoot "snapshot\release\$sdkArch\plugins"
  New-Item -ItemType Directory -Path $pluginDir -Force | Out-Null
  Copy-Item -LiteralPath $output -Destination $pluginDir -Force
  $portableDir = Join-Path $PSScriptRoot 'native'
  New-Item -ItemType Directory -Path $portableDir -Force | Out-Null
  Copy-Item -LiteralPath $output -Destination $portableDir -Force
}
$nativeHashes = @{}
foreach ($bits in @('32','64')) { $nativeHashes["ig5-bridge.dp$bits"] = (Get-FileHash -LiteralPath (Join-Path $PSScriptRoot "native\ig5-bridge.dp$bits") -Algorithm SHA256).Hash.ToLowerInvariant() }
$nativeHashes | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $PSScriptRoot 'native\sha256.json') -Encoding utf8
