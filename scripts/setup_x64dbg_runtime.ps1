param([string]$RuntimeRoot = (Join-Path $PSScriptRoot '..\runtimes\x64dbg'))
$ErrorActionPreference = 'Stop'
$RuntimeRoot = [IO.Path]::GetFullPath($RuntimeRoot)
New-Item -ItemType Directory -Path $RuntimeRoot -Force | Out-Null
$downloadDir = Join-Path $RuntimeRoot 'downloads'
New-Item -ItemType Directory -Path $downloadDir -Force | Out-Null
$sources = @(
  @{name='snapshot.zip'; url='https://github.com/x64dbg/x64dbg/releases/download/2026.05.27/snapshot_2026-05-27_12-11.zip'; dest='snapshot'; sha256='d41966dfc5b435a372798245300ca0ab7bb8e48bdbf48512c6fb20fcca427697'},
  @{name='python.zip'; url='https://www.python.org/ftp/python/3.12.10/python-3.12.10-embed-amd64.zip'; dest='python'; sha256='4acbed6dd1c744b0376e3b1cf57ce906f9dc9e95e68824584c8099a63025a3c3'}
)
foreach ($source in $sources) {
  $archive = Join-Path $downloadDir $source.name
  if (!(Test-Path -LiteralPath $archive)) { Invoke-WebRequest -Uri $source.url -OutFile $archive }
  if ((Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant() -ne $source.sha256) { throw "Download hash mismatch: $($source.name)" }
  $destination = [IO.Path]::GetFullPath((Join-Path $RuntimeRoot $source.dest))
  if (!$destination.StartsWith($RuntimeRoot + '\', [StringComparison]::OrdinalIgnoreCase)) { throw 'Extraction path escaped runtime root' }
  Expand-Archive -LiteralPath $archive -DestinationPath $destination -Force
}
$adapterRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\adapters\x64dbg'))
$hashes = Get-Content -LiteralPath (Join-Path $adapterRoot 'native\sha256.json') -Raw | ConvertFrom-Json
foreach ($bits in @('32','64')) {
  $pluginDir = Join-Path $RuntimeRoot "snapshot\release\x$bits\plugins"
  New-Item -ItemType Directory -Path $pluginDir -Force | Out-Null
  # Earlier automate experiments must remain disabled on every repeated setup.
  $disabled = Join-Path $downloadDir "disabled-automate$bits"
  New-Item -ItemType Directory -Path $disabled -Force | Out-Null
  foreach ($name in @("x64dbg-automate.dp$bits", 'libzmq-mt-4_3_5.dll')) {
    $old = Join-Path $pluginDir $name
    if (Test-Path -LiteralPath $old) { Move-Item -LiteralPath $old -Destination (Join-Path $disabled $name) -Force }
  }
  $name = "ig5-bridge.dp$bits"
  $binary = Join-Path $adapterRoot "native\$name"
  if ((Get-FileHash -LiteralPath $binary -Algorithm SHA256).Hash.ToLowerInvariant() -ne $hashes.$name) { throw "Native bridge hash mismatch: $name" }
  Copy-Item -LiteralPath $binary -Destination $pluginDir -Force
}
# The native bridge uses only Python's standard library. No pip/client/ZeroMQ is needed.
Set-Content -LiteralPath (Join-Path $RuntimeRoot 'python\python312._pth') -Value @('python312.zip','.') -Encoding ascii
$config = @{
  pythonExe='python/python.exe'; headlessExe='snapshot/release/x64/headless.exe'; headless32Exe='snapshot/release/x32/headless.exe';
  x64dbgExe='snapshot/release/x64/x64dbg.exe'; x32dbgExe='snapshot/release/x32/x32dbg.exe'; mode='headless'; bridge='ig5-native';
  x64dbgTag='2026.05.27'; x64dbgCommit='9c8ca1cae0b6d56cc44f31fddcb10e3b02ffbb87'; extraEnv=@{}
}
$config | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $RuntimeRoot 'runtime.json') -Encoding utf8
$sources | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $RuntimeRoot 'downloads-manifest.json') -Encoding utf8
$licenseDir = Join-Path $RuntimeRoot 'licenses'
New-Item -ItemType Directory -Path $licenseDir -Force | Out-Null
Copy-Item -LiteralPath (Join-Path $RuntimeRoot 'python\LICENSE.txt') -Destination (Join-Path $licenseDir 'Python-LICENSE.txt') -Force
Get-ChildItem -LiteralPath (Join-Path $adapterRoot 'licenses') -File | Copy-Item -Destination $licenseDir -Force
Write-Output (Join-Path $RuntimeRoot 'runtime.json')
