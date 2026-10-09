param(
  [string]$BuildRoot = (Join-Path $PSScriptRoot '..\.downloads\x64dbg-build'),
  [string]$RuntimeRoot = (Join-Path $PSScriptRoot '..\runtimes\x64dbg'),
  [string]$CMake = 'C:\Program Files\CMake\bin\cmake.exe',
  [string]$Python = (Join-Path $PSScriptRoot '..\runtimes\ghidra\python\python.exe'),
  [ValidateSet('x64','x86','both')][string]$Architecture = 'both',
  [switch]$InstallBuiltRuntime
)
$ErrorActionPreference = 'Stop'
$pluginRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$BuildRoot = [IO.Path]::GetFullPath($BuildRoot)
$RuntimeRoot = [IO.Path]::GetFullPath($RuntimeRoot)
. (Join-Path $PSScriptRoot 'runtime_pack.ps1')
$source = Join-Path $pluginRoot 'third_party\sources\x64dbg-runtime'
$overlay = Join-Path $pluginRoot 'third_party\x64dbg-build'
$lock = Get-Content -LiteralPath (Join-Path $overlay 'build-lock.json') -Raw | ConvertFrom-Json
$inventory = Get-Content -LiteralPath (Join-Path $pluginRoot 'third_party\sources\provenance\x64dbg-runtime.files.json') -Raw | ConvertFrom-Json
Assert-IG5FileInventory -Root $source -Files $inventory.files -Label 'fixed x64dbg source'
if (-not (Test-Path -LiteralPath $CMake)) { throw 'CMake is required to rebuild x64dbg' }
if (-not (Test-Path -LiteralPath $Python)) { throw 'bundled Python is required to apply the maintained patch' }
New-Item -ItemType Directory -Path $BuildRoot -Force | Out-Null
$checkout = Join-Path $BuildRoot 'checkout'
if (-not (Test-Path -LiteralPath $checkout)) {
  Copy-IG5Pack -From $source -To $checkout
}
& $Python -I -B (Join-Path $overlay 'prepare_headless.py') $checkout $overlay
if ($LASTEXITCODE -ne 0) { throw 'Headless patch failed' }
$expectedPatched = $lock.patchedCMakeSHA256
if ((Get-IG5Hash (Join-Path $checkout 'CMakeLists.txt')) -ne $expectedPatched) { throw 'Build checkout differs from maintained overlay' }
$patchedInventory = foreach ($row in $inventory.files) {
  $change = $lock.modifiedFiles | Where-Object path -eq $row.path
  if ($change) { [pscustomobject]@{path=$row.path;bytes=$change.patchedBytes;sha256=$change.patchedSHA256} } else { $row }
}
Assert-IG5FileInventory -Root $checkout -Files $patchedInventory -Label 'verified IG5 patched x64dbg checkout'
$architectures = if ($Architecture -eq 'both') { @('x64','x86') } else { @($Architecture) }
$built = @()
foreach ($arch in $architectures) {
  $platform = if ($arch -eq 'x64') { 'x64' } else { 'Win32' }
  $sdkArch = if ($arch -eq 'x64') { 'x64' } else { 'x32' }
  $build = Join-Path $BuildRoot $arch
  $log = Join-Path $BuildRoot "build-$arch.log"
  & $CMake -S $checkout -B $build -G 'Visual Studio 18 2026' -A $platform -DCMKR_SKIP_GENERATION=ON -DX64DBG_BUILD_IN_TREE=OFF -DCMAKE_UNITY_BUILD=OFF 2>&1 | Tee-Object -FilePath $log
  if ($LASTEXITCODE -ne 0) { throw "x64dbg configure failed: $log" }
  & $CMake --build $build --config Release --target headless --parallel 4 2>&1 | Tee-Object -FilePath $log -Append
  if ($LASTEXITCODE -ne 0) { throw "x64dbg native build failed: $log" }
  $release = Join-Path $build 'Release'
  $products = @('headless.exe',"${sdkArch}dbg.dll","${sdkArch}bridge.dll",'loaddll.exe')
  $titan = Join-Path $build 'src\third_party\TitanEngine\Release\TitanEngine.dll'
  if (-not (Test-Path -LiteralPath $titan)) { throw 'Source-built TitanEngine is missing' }
  $files = foreach ($name in $products) {
    $file = Join-Path $release $name
    if (-not (Test-Path -LiteralPath $file)) { throw "Source-built product missing: $name" }
    [ordered]@{ name=$name; bytes=(Get-Item -LiteralPath $file).Length; sha256=(Get-IG5Hash $file) }
  }
  $files += [ordered]@{name='TitanEngine.dll';bytes=(Get-Item -LiteralPath $titan).Length;sha256=(Get-IG5Hash $titan)}
  if ($InstallBuiltRuntime) {
    $destination = Join-Path $RuntimeRoot "snapshot\release\$sdkArch"
    foreach ($name in $products) { Copy-Item -LiteralPath (Join-Path $release $name) -Destination $destination -Force }
    Copy-Item -LiteralPath $titan -Destination $destination -Force
  }
  $compilerInfo = Get-Content -LiteralPath (Get-ChildItem -LiteralPath (Join-Path $build 'CMakeFiles') -Recurse -Filter CMakeCXXCompiler.cmake | Select-Object -First 1).FullName
  $compilerPath = ([regex]::Match(($compilerInfo -join "`n"), 'set\(CMAKE_CXX_COMPILER "([^"]+)"\)')).Groups[1].Value
  $compilerVersion = ([regex]::Match(($compilerInfo -join "`n"), 'set\(CMAKE_CXX_COMPILER_VERSION "([^"]+)"\)')).Groups[1].Value
  $built += [ordered]@{ architecture=$arch; configuration='Release'; compiler=$compilerPath; compilerVersion=$compilerVersion; products=$files }
}
$proof = [ordered]@{
  schemaVersion=1; engine='x64dbg'; upstreamCommit=$lock.commit;
  upstreamRepository=$lock.repository; gitlinks=$lock.gitlinks;
  patches=@($lock.patches | ForEach-Object { [ordered]@{path=$_;sha256=(Get-IG5Hash (Join-Path $overlay $_))} });
  sourceInventorySHA256=(Get-IG5Hash (Join-Path $pluginRoot 'third_party\sources\provenance\x64dbg-runtime.files.json'));
  cmake=(& $CMake --version | Select-Object -First 1);
  headlessOnly=$true; builtFromSource=@('bridge','dbg','headless','loaddll','zydis_wrapper','btparser','TitanEngine','scylla_wrapper','distorm');
  prebuiltLinkedDependencies=$lock.prebuiltLinkedDependencies; architectures=$built;
  installedIntoSourceRuntime=[bool]$InstallBuiltRuntime; createdUtc=[DateTime]::UtcNow.ToString('o')
}
$proof | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath (Join-Path $BuildRoot 'build-proof.json') -Encoding utf8
if ($InstallBuiltRuntime) {
  Copy-Item -LiteralPath (Join-Path $BuildRoot 'build-proof.json') -Destination (Join-Path $RuntimeRoot 'source-build-proof.json') -Force
}
$proof | ConvertTo-Json -Depth 12
