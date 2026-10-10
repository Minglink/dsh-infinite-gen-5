param(
  [string]$RuntimeRoot
)
$ErrorActionPreference = 'Stop'
if (-not $PSBoundParameters.ContainsKey('RuntimeRoot')) { $RuntimeRoot = Join-Path $PSScriptRoot '..\runtimes\ghidra' }
$RuntimeRoot = [IO.Path]::GetFullPath($RuntimeRoot)
$cache = Join-Path $RuntimeRoot 'downloads'
New-Item -ItemType Directory -Path $cache -Force | Out-Null
$packages = @(
  @{name='ghidra_12.1.4_PUBLIC_20260921.zip';url='https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_12.1.4_build/ghidra_12.1.4_PUBLIC_20260921.zip';sha256='ddac49f903da9d5bac833e5cc79395098b9c33cfd3279be5f31bd00387d2d4db';folder='ghidra_12.1.4_PUBLIC';proof='GitHub release asset digest'},
  @{name='OpenJDK21U-jdk_x64_windows_hotspot_21.0.12.1_1.zip';url='https://github.com/adoptium/temurin21-binaries/releases/download/jdk-21.0.12.1%2B1/OpenJDK21U-jdk_x64_windows_hotspot_21.0.12.1_1.zip';sha256='f9d6e191ab098c0d416e7d588a24420a8621cd2f4720dab2459b8b7b2d2d8b4e';folder='jdk-21.0.12.1+1';proof='Adoptium API package checksum'},
  @{name='python-3.12.10-embed-amd64.zip';url='https://www.python.org/ftp/python/3.12.10/python-3.12.10-embed-amd64.zip';sha256='4acbed6dd1c744b0376e3b1cf57ce906f9dc9e95e68824584c8099a63025a3c3';folder='python';proof='python.org Sigstore message SHA2_256 digest'}
)
foreach ($package in $packages) {
  $archive = Join-Path $cache $package.name
  if (!(Test-Path -LiteralPath $archive) -or (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant() -ne $package.sha256) {
    Write-Output ('Downloading ' + $package.name)
    & curl.exe --fail --location --retry 5 --retry-all-errors --output $archive $package.url
    if ($LASTEXITCODE -ne 0) { throw ('Download failed: ' + $package.name) }
  }
  if ((Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant() -ne $package.sha256) { throw ('SHA256 mismatch: ' + $package.name) }
  $destination = if ($package.folder -eq 'python') { Join-Path $RuntimeRoot 'python' } else { $RuntimeRoot }
  $marker = Join-Path (Join-Path $RuntimeRoot $package.folder) '.ig5-source-sha256'
  if (!(Test-Path -LiteralPath $marker) -or (Get-Content -LiteralPath $marker -Raw).Trim() -ne $package.sha256) {
    Write-Output ('Extracting ' + $package.name)
    Expand-Archive -LiteralPath $archive -DestinationPath $destination -Force
    Set-Content -LiteralPath $marker -Encoding ascii -Value $package.sha256
  }
}
$ghidraHome = Join-Path $RuntimeRoot $packages[0].folder
$javaHome = Join-Path $RuntimeRoot $packages[1].folder
$pythonHome = Join-Path $RuntimeRoot 'python'
$wheels = Join-Path $cache 'wheels'
$pylib = Join-Path $pythonHome 'pylib'
New-Item -ItemType Directory -Path $wheels,$pylib -Force | Out-Null
$included = Get-ChildItem -LiteralPath (Join-Path $ghidraHome 'Ghidra\Features\PyGhidra\pypkg\dist') -Filter 'pyghidra-*.whl' | Select-Object -First 1
if (!$included) { throw 'Official release has no bundled PyGhidra wheel' }
Copy-Item -LiteralPath $included.FullName -Destination (Join-Path $wheels $included.Name) -Force
$dependencies = @(
  @{name='jpype1-1.5.2-cp312-cp312-win_amd64.whl';url='https://files.pythonhosted.org/packages/74/dd/7408d4beae755de6fcd07c76b2f0bacabc0461b43fba83811c1f7c22440e/jpype1-1.5.2-cp312-cp312-win_amd64.whl';sha256='c7b1c2d76d211cab60be16505d32a6b3c9fffc51ce79c68e81a3d48e5effff2d';proof='https://pypi.org/pypi/JPype1/1.5.2/json'},
  @{name='packaging-26.3-py3-none-any.whl';url='https://files.pythonhosted.org/packages/63/34/ba1c580383c9eada3711951fef0795c80b829a078d72188184bcab9dd527/packaging-26.3-py3-none-any.whl';sha256='d7193f7c8e4e93f444fde0262bf90af30e16fa0ad0ad44cb553c87339b23cd1c';proof='https://pypi.org/pypi/packaging/26.3/json'}
)
foreach ($dependency in $dependencies) {
  $wheelPath = Join-Path $wheels $dependency.name
  if (!(Test-Path -LiteralPath $wheelPath) -or (Get-FileHash -LiteralPath $wheelPath -Algorithm SHA256).Hash.ToLowerInvariant() -ne $dependency.sha256) {
    & curl.exe --fail --location --retry 5 --retry-all-errors --output $wheelPath $dependency.url
    if ($LASTEXITCODE -ne 0) { throw ('Download failed: ' + $dependency.name) }
  }
  if ((Get-FileHash -LiteralPath $wheelPath -Algorithm SHA256).Hash.ToLowerInvariant() -ne $dependency.sha256) { throw ('SHA256 mismatch: ' + $dependency.name) }
}
$wheelManifest = @()
Add-Type -AssemblyName System.IO.Compression.FileSystem
foreach ($wheelName in @($included.Name) + @($dependencies | ForEach-Object name)) {
  $wheelPath = Join-Path $wheels $wheelName
  $wheelHash = (Get-FileHash -LiteralPath $wheelPath -Algorithm SHA256).Hash.ToLowerInvariant()
  $wheelMarker = Join-Path $pylib ('.ig5-wheel-' + $wheelName + '.sha256')
  if (!(Test-Path -LiteralPath $wheelMarker) -or (Get-Content -LiteralPath $wheelMarker -Raw).Trim() -ne $wheelHash) {
    $archive = [IO.Compression.ZipFile]::OpenRead($wheelPath)
    try {
      foreach ($entry in $archive.Entries) {
        $entryPath = [IO.Path]::GetFullPath((Join-Path $pylib $entry.FullName))
        if (!$entryPath.StartsWith(([IO.Path]::GetFullPath($pylib) + [IO.Path]::DirectorySeparatorChar), [StringComparison]::OrdinalIgnoreCase)) { throw 'Invalid wheel archive path' }
        if (!$entry.Name) { New-Item -ItemType Directory -Path $entryPath -Force | Out-Null; continue }
        New-Item -ItemType Directory -Path ([IO.Path]::GetDirectoryName($entryPath)) -Force | Out-Null
        [IO.Compression.ZipFileExtensions]::ExtractToFile($entry, $entryPath, $true)
      }
    } finally { $archive.Dispose() }
    Set-Content -LiteralPath $wheelMarker -Encoding ascii -Value $wheelHash
  }
  $wheelManifest += @{name=$wheelName;sha256=(Get-FileHash -LiteralPath $wheelPath -Algorithm SHA256).Hash.ToLowerInvariant();source=if ($wheelName -like 'pyghidra-*') {'bundled official Ghidra release'} else {($dependencies | Where-Object name -eq $wheelName).url} }
}
Set-Content -LiteralPath (Join-Path $pythonHome 'python312._pth') -Encoding ascii -Value @('python312.zip','.','pylib','import site')
$manifest = @{
  schemaVersion=1;engine='Ghidra';version='12.1.4';pythonExe='python/python.exe';ghidraHome=$packages[0].folder;javaHome=$packages[1].folder;
  packages=$packages;wheels=$wheelManifest;wheelProofs=$dependencies;createdUtc=[DateTime]::UtcNow.ToString('o');
  licenses=@('ghidra_12.1.4_PUBLIC/LICENSE','ghidra_12.1.4_PUBLIC/bom.json','ghidra_12.1.4_PUBLIC/licenses','jdk-21.0.12.1+1/legal','python/LICENSE.txt','python/pylib/*.dist-info');
  projectRoot='projects'
}
$manifest | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $RuntimeRoot 'runtime.json') -Encoding utf8
& (Join-Path $PSScriptRoot 'patch_ghidra_jpype.ps1') -RuntimeRoot $RuntimeRoot
if (-not $?) { throw 'JPype Unicode bootstrap patch failed' }
& (Join-Path $PSScriptRoot 'patch_ghidra_project_paths.ps1') -RuntimeRoot $RuntimeRoot
if (-not $?) { throw 'Ghidra local project path patch failed' }
& (Join-Path $pythonHome 'python.exe') -I -B -c 'import sys,pyghidra,jpype; print(sys.version); print("pyghidra",pyghidra.__version__,"jpype",jpype.__version__)'
if ($LASTEXITCODE -ne 0) { throw 'Independent Python dependency check failed' }
& (Join-Path $javaHome 'bin\java.exe') -version
if ($LASTEXITCODE -ne 0) { throw 'Independent JDK check failed' }
Write-Output ('Ready: ' + (Join-Path $RuntimeRoot 'runtime.json'))
